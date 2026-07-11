//! ACL enforcement (`memvault_api::acl::check_bucket_access`) — covers
//! owner bypass, Peer / Agent / Role audience matching, and the
//! expired-grant + no-grant deny paths.

use ed25519_dalek::SigningKey;
use rand::RngCore;

use memvault_api::MemvaultClient;
use memvault_api::acl;
use memvault_auth::{Action, AgentRole, Grant, GrantAudience, sign_agent_attestation};
use memvault_core::{AgentName, BucketId, PeerId, Visibility};

use crate::harness::TestNode;

/// Build a node, mint an agent attestation against the node key, and
/// publish it. Returns the agent's ed25519 verifying key bytes — the
/// authoritative caller identity used by `check_bucket_access`.
async fn setup_agent(node: &TestNode, agent_name: &str, role: AgentRole) -> ([u8; 32], AgentName) {
    let node_sk = node
        .client
        .node_signing_key()
        .expect("node signing key present")
        .clone();

    let mut agent_seed = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut agent_seed);
    let agent_sk = SigningKey::from_bytes(&agent_seed);
    let agent_pk = agent_sk.verifying_key().to_bytes();

    let attestation = sign_agent_attestation(
        &node_sk,
        AgentName(agent_name.to_string()),
        agent_pk,
        role,
        u64::MAX,
    )
    .expect("sign agent attestation");

    memvault_api::sigchain::publish_agent_attestation(&node.client, &attestation)
        .expect("publish attestation");

    (agent_pk, AgentName(agent_name.to_string()))
}

/// Create a plain bucket owned by no specific agent — the default case
/// for grant-gated access.
async fn make_bucket(node: &TestNode, name: &str) -> BucketId {
    node.client
        .bucket_create(
            name,
            None,
            Visibility::Internal,
            memvault_core::classification::Classification::Internal,
            memvault_doc::BucketRole::Standard,
        )
        .await
        .expect("bucket create")
}

#[tokio::test]
async fn deny_without_grant() {
    let node = TestNode::new();
    let (agent_pk, _) = setup_agent(&node, "no-grant-agent", AgentRole::AgentHost).await;
    let bucket = make_bucket(&node, "no-grant-bucket").await;

    let err = acl::check_bucket_access(&node.client, &agent_pk, &bucket, Action::Write)
        .expect_err("must deny when no grant covers the agent");
    assert!(
        matches!(err, memvault_api::ApiError::Forbidden(_)),
        "expected Forbidden, got {err:?}"
    );
}

#[tokio::test]
async fn allow_peer_audience() {
    let node = TestNode::new();
    let (agent_pk, _) = setup_agent(&node, "peer-agent", AgentRole::AgentHost).await;
    let bucket = make_bucket(&node, "peer-bucket").await;

    node.client
        .issue_bucket_grant(
            &bucket,
            GrantAudience::Peer(PeerId(agent_pk.to_vec())),
            vec![Action::Read],
            u64::MAX,
        )
        .await
        .expect("issue peer grant");

    acl::check_bucket_access(&node.client, &agent_pk, &bucket, Action::Read)
        .expect("peer grant for Read should pass");

    // The same grant only listed Read — Write must still be denied.
    let err = acl::check_bucket_access(&node.client, &agent_pk, &bucket, Action::Write)
        .expect_err("Write must require a Write grant");
    assert!(matches!(err, memvault_api::ApiError::Forbidden(_)));
}

#[tokio::test]
async fn allow_agent_audience() {
    let node = TestNode::new();
    let (agent_pk, _) = setup_agent(&node, "named-agent", AgentRole::AgentHost).await;
    let bucket = make_bucket(&node, "named-bucket").await;

    node.client
        .issue_bucket_grant(
            &bucket,
            GrantAudience::AgentKey(agent_pk),
            vec![Action::Write],
            u64::MAX,
        )
        .await
        .expect("issue agent grant");

    acl::check_bucket_access(&node.client, &agent_pk, &bucket, Action::Write)
        .expect("agent-id-audience grant should pass");
}

#[tokio::test]
async fn allow_role_audience() {
    let node = TestNode::new();
    let (agent_pk, _) = setup_agent(&node, "role-agent", AgentRole::AgentHost).await;
    let bucket = make_bucket(&node, "role-bucket").await;

    node.client
        .issue_bucket_grant(
            &bucket,
            GrantAudience::Role(AgentRole::AgentHost),
            vec![Action::Read, Action::Write],
            u64::MAX,
        )
        .await
        .expect("issue role grant");

    acl::check_bucket_access(&node.client, &agent_pk, &bucket, Action::Read)
        .expect("Role grant for Read");
    acl::check_bucket_access(&node.client, &agent_pk, &bucket, Action::Write)
        .expect("Role grant for Write");
}

#[tokio::test]
async fn role_mismatch_denied() {
    let node = TestNode::new();
    // Agent enrolled as Service, but the grant targets AgentHost.
    let (agent_pk, _) = setup_agent(&node, "svc-agent", AgentRole::Service).await;
    let bucket = make_bucket(&node, "role-mismatch-bucket").await;

    node.client
        .issue_bucket_grant(
            &bucket,
            GrantAudience::Role(AgentRole::AgentHost),
            vec![Action::Write],
            u64::MAX,
        )
        .await
        .expect("issue role grant");

    let err = acl::check_bucket_access(&node.client, &agent_pk, &bucket, Action::Write)
        .expect_err("Service caller must not satisfy a Role(AgentHost) grant");
    assert!(matches!(err, memvault_api::ApiError::Forbidden(_)));
}

#[tokio::test]
async fn owner_agent_bypasses_grants() {
    let node = TestNode::new();
    let (agent_pk, agent_id) = setup_agent(&node, "owner-agent", AgentRole::AgentHost).await;

    // Mint a bucket owned by this agent via the deterministic
    // pubkey-keyed helper — same path the daemon uses for agent buckets.
    let bucket = node
        .client
        .ensure_agent_bucket_for_pubkey(&agent_pk, &agent_id.0)
        .await
        .expect("ensure agent bucket");

    // No explicit grant on chain — pure owner bypass.
    let grants = node.client.list_bucket_grants(&bucket).expect("list");
    assert!(
        grants.is_empty(),
        "no grants should exist for fresh agent bucket"
    );

    acl::check_bucket_access(&node.client, &agent_pk, &bucket, Action::Read).expect("owner Read");
    acl::check_bucket_access(&node.client, &agent_pk, &bucket, Action::Write).expect("owner Write");
}

/// Regression: when the HTTP `POST /buckets` handler creates a bucket
/// on behalf of a caller, it threads the caller's `agent_id` through
/// `bucket_create_as` so the new bucket records them as `owner_agent`.
/// Without that, the BucketDecl inherited the daemon's identity and
/// the caller couldn't even read the bucket they just created.
#[tokio::test]
async fn bucket_create_as_sets_owner_and_grants_access() {
    let node = TestNode::new();
    let (agent_pk, agent_id) = setup_agent(&node, "create-as-agent", AgentRole::AgentHost).await;

    let bucket = node
        .client
        .bucket_create_as(
            agent_id.clone(),
            Some(agent_pk),
            "create-as-bucket",
            None,
            Visibility::Internal,
            memvault_core::classification::Classification::Internal,
            memvault_doc::BucketRole::Standard,
        )
        .await
        .expect("bucket_create_as");

    let info = node
        .client
        .bucket_get(&bucket)
        .await
        .expect("bucket_get")
        .expect("bucket exists");
    assert_eq!(
        info.owner_agent.as_ref(),
        Some(&agent_id),
        "owner_agent must be the caller, not the daemon"
    );

    let grants = node.client.list_bucket_grants(&bucket).expect("list");
    assert!(
        grants.is_empty(),
        "creating a bucket must not require/issue a separate grant"
    );

    acl::check_bucket_access(&node.client, &agent_pk, &bucket, Action::Read).expect("creator Read");
    acl::check_bucket_access(&node.client, &agent_pk, &bucket, Action::Write)
        .expect("creator Write");
}

/// `revoke_bucket_grant` must take effect immediately — the same
/// `check_bucket_access` call that succeeded under the live grant
/// returns Forbidden once the revocation lands.
#[tokio::test]
async fn revoked_grant_denied() {
    let node = TestNode::new();
    let (agent_pk, _) = setup_agent(&node, "revoke-agent", AgentRole::AgentHost).await;
    let bucket = make_bucket(&node, "revoke-bucket").await;

    let grant_cid = node
        .client
        .issue_bucket_grant(
            &bucket,
            GrantAudience::AgentKey(agent_pk),
            vec![Action::Read, Action::Write],
            u64::MAX,
        )
        .await
        .expect("issue grant");

    // Before revocation: access works.
    acl::check_bucket_access(&node.client, &agent_pk, &bucket, Action::Read)
        .expect("Read under live grant");

    let rev_cid = node
        .client
        .revoke_bucket_grant(&grant_cid, "key rotation")
        .await
        .expect("revoke grant");
    assert_ne!(
        rev_cid, grant_cid,
        "revocation must be its own block, not overwrite the grant"
    );

    // The original grant block stays on the chain (audit), but ACL
    // checks now treat it as if it didn't exist.
    let grants = node.client.list_bucket_grants(&bucket).expect("list");
    assert_eq!(grants.len(), 1, "grant block preserved for audit");
    assert!(
        node.client.store().is_revoked(&grant_cid).unwrap(),
        "revocation table must mark the target grant"
    );

    let err = acl::check_bucket_access(&node.client, &agent_pk, &bucket, Action::Read)
        .expect_err("Read must fail after revocation");
    assert!(matches!(err, memvault_api::ApiError::Forbidden(_)));
    let err = acl::check_bucket_access(&node.client, &agent_pk, &bucket, Action::Write)
        .expect_err("Write must fail after revocation");
    assert!(matches!(err, memvault_api::ApiError::Forbidden(_)));
}

/// Revoking grant A must not affect a separate grant B on the same
/// bucket. Catches an over-broad `is_revoked` check that keyed on
/// bucket id or audience instead of the specific grant CID.
#[tokio::test]
async fn revocation_is_grant_specific() {
    let node = TestNode::new();
    let (agent_pk, _) = setup_agent(&node, "two-grant-agent", AgentRole::AgentHost).await;
    let bucket = make_bucket(&node, "two-grant-bucket").await;

    // Two grants, same audience, same actions — only the first is revoked.
    let grant_a = node
        .client
        .issue_bucket_grant(
            &bucket,
            GrantAudience::AgentKey(agent_pk),
            vec![Action::Read],
            u64::MAX,
        )
        .await
        .expect("grant A");
    let grant_b = node
        .client
        .issue_bucket_grant(
            &bucket,
            GrantAudience::AgentKey(agent_pk),
            vec![Action::Read],
            u64::MAX,
        )
        .await
        .expect("grant B");
    assert_ne!(grant_a, grant_b, "issued grants must have distinct CIDs");

    node.client
        .revoke_bucket_grant(&grant_a, "superseded")
        .await
        .expect("revoke A");

    // Read still works — grant B is untouched.
    acl::check_bucket_access(&node.client, &agent_pk, &bucket, Action::Read)
        .expect("Read still allowed via surviving grant B");
}

/// Revoking a CID that isn't a grant block must fail loudly rather than
/// silently poisoning the revocation table — guards against typos in
/// admin tooling.
#[tokio::test]
async fn revoke_rejects_non_grant_cid() {
    let node = TestNode::new();
    let bucket = make_bucket(&node, "bogus-cid-bucket").await;

    let mut bogus = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bogus);

    let err = node
        .client
        .revoke_bucket_grant(&bogus, "typo")
        .await
        .expect_err("unknown cid must fail");
    assert!(matches!(err, memvault_api::ApiError::Other(_)));

    // And revoking the bucket-decl CID — a real block, but not a grant
    // — must also fail.
    let decl_cid = node
        .client
        .store()
        .get_bucket(&bucket.0)
        .expect("bucket decl cid lookup")
        .expect("bucket decl exists");
    let err = node
        .client
        .revoke_bucket_grant(&decl_cid, "wrong target")
        .await
        .expect_err("non-grant block must fail");
    assert!(matches!(err, memvault_api::ApiError::Other(_)));
}

#[tokio::test]
async fn expired_grant_denied() {
    let node = TestNode::new();
    let (agent_pk, _) = setup_agent(&node, "expired-agent", AgentRole::AgentHost).await;
    let bucket = make_bucket(&node, "expired-bucket").await;

    // Issue a grant directly with a not_after_ns in the past — bypass
    // the public helper which always derives the bound from
    // (now + ttl). The store carries the signed envelope either way.
    let admin_key = node
        .client
        .admin_signing_key()
        .expect("admin key present")
        .clone();
    let mut nonce = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut nonce);
    let mut grant = Grant {
        issuer: PeerId(node.client.peer_id().to_vec()),
        issuing_cluster: node.cluster_id.clone(),
        admin_pubkey: admin_key.verifying_key().to_bytes(),
        audience: GrantAudience::Peer(PeerId(agent_pk.to_vec())),
        scopes: vec![],
        actions: vec![Action::Read, Action::Write],
        not_before_ns: 1,
        not_after_ns: 2, // already in the past
        parent: None,
        nonce,
        bucket_scopes: vec![bucket.clone()],
        signature: [0u8; 64],
    };
    let signing_bytes = grant.signing_bytes().expect("signing bytes");
    use ed25519_dalek::Signer;
    grant.signature = admin_key.sign(&signing_bytes).to_bytes();

    let grant_bytes = serde_ipld_dagcbor::to_vec(&grant).expect("encode grant");
    let cid = memvault_core::cid_from_bytes(&grant_bytes);
    let meta = memvault_store::EnvelopeMeta {
        author: node.client.peer_id().to_vec(),
        tags: vec![
            ("grant".to_string(), hex::encode(bucket.0)),
            ("kind".to_string(), "grant".to_string()),
        ],
        wall_ns: 1,
        causal: vec![],
        provenance: vec![],
        cluster_id: Some(node.cluster_id.0.to_vec()),
        bucket_id: Some(bucket.0.to_vec()),
        ..Default::default()
    };
    node.client
        .store()
        .insert_envelope(&cid.to_bytes(), &grant_bytes, &meta)
        .expect("insert expired grant");

    // Confirm the grant landed.
    let grants = node.client.list_bucket_grants(&bucket).expect("list");
    assert_eq!(grants.len(), 1);

    let err = acl::check_bucket_access(&node.client, &agent_pk, &bucket, Action::Read)
        .expect_err("expired grant must be ignored");
    assert!(matches!(err, memvault_api::ApiError::Forbidden(_)));
}

/// Store a raw grant block with a caller-chosen `admin_pubkey` and
/// signer, bypassing `issue_bucket_grant`. Lets tests forge grants the
/// way a malicious peer would (injecting a block via sync). `signer` is
/// the key that actually signs; `admin_pubkey` is what the grant claims.
fn insert_raw_grant(
    node: &TestNode,
    bucket: &BucketId,
    audience: GrantAudience,
    actions: Vec<Action>,
    admin_pubkey: [u8; 32],
    signer: Option<&SigningKey>,
) -> Vec<u8> {
    insert_raw_grant_at(node, bucket, audience, actions, admin_pubkey, signer, 1)
}

#[allow(clippy::too_many_arguments)]
fn insert_raw_grant_at(
    node: &TestNode,
    bucket: &BucketId,
    audience: GrantAudience,
    actions: Vec<Action>,
    admin_pubkey: [u8; 32],
    signer: Option<&SigningKey>,
    not_before_ns: u64,
) -> Vec<u8> {
    let mut nonce = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut nonce);
    let mut grant = Grant {
        issuer: PeerId(node.client.peer_id().to_vec()),
        issuing_cluster: node.cluster_id.clone(),
        admin_pubkey,
        audience,
        scopes: vec![],
        actions,
        not_before_ns,
        not_after_ns: u64::MAX,
        parent: None,
        nonce,
        bucket_scopes: vec![bucket.clone()],
        signature: [0u8; 64],
    };
    if let Some(sk) = signer {
        use ed25519_dalek::Signer;
        let sb = grant.signing_bytes().expect("signing bytes");
        grant.signature = sk.sign(&sb).to_bytes();
    }
    let grant_bytes = serde_ipld_dagcbor::to_vec(&grant).expect("encode grant");
    let cid = memvault_core::cid_from_bytes(&grant_bytes);
    let meta = memvault_store::EnvelopeMeta {
        author: node.client.peer_id().to_vec(),
        tags: vec![
            ("grant".to_string(), hex::encode(bucket.0)),
            ("kind".to_string(), "grant".to_string()),
        ],
        wall_ns: 1,
        cluster_id: Some(node.cluster_id.0.to_vec()),
        bucket_id: Some(bucket.0.to_vec()),
        ..Default::default()
    };
    node.client
        .store()
        .insert_envelope(&cid.to_bytes(), &grant_bytes, &meta)
        .expect("insert raw grant");
    cid.to_bytes()
}

/// A grant predating the `admin_pubkey` field (all-zero) is always
/// denied — there is no tolerance/migration mode; a peer could otherwise
/// forge access by simply omitting the signer.
#[tokio::test]
async fn legacy_unsigned_grant_always_denied() {
    let node = TestNode::new();
    let (agent_pk, _) = setup_agent(&node, "legacy-agent", AgentRole::AgentHost).await;
    let bucket = make_bucket(&node, "legacy-bucket").await;

    insert_raw_grant(
        &node,
        &bucket,
        GrantAudience::Peer(PeerId(agent_pk.to_vec())),
        vec![Action::Read],
        [0u8; 32], // legacy: no admin_pubkey
        None,      // legacy: no signature
    );

    let err = acl::check_bucket_access(&node.client, &agent_pk, &bucket, Action::Read)
        .expect_err("legacy unsigned grant must always be denied");
    assert!(matches!(err, memvault_api::ApiError::Forbidden(_)));
}

/// A grant whose signature verifies against its embedded `admin_pubkey`,
/// but whose key was never a cluster admin, must be denied. This is the
/// core forgery defence: a malicious peer signs a grant with their own
/// key and claims it as the signer.
#[tokio::test]
async fn forged_grant_from_non_admin_denied() {
    let node = TestNode::new();
    let (agent_pk, _) = setup_agent(&node, "forge-agent", AgentRole::AgentHost).await;
    let bucket = make_bucket(&node, "forge-bucket").await;

    // Attacker key — internally consistent (admin_pubkey matches signer)
    // but not a cluster admin.
    let mut seed = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut seed);
    let attacker = SigningKey::from_bytes(&seed);

    insert_raw_grant(
        &node,
        &bucket,
        GrantAudience::Peer(PeerId(agent_pk.to_vec())),
        vec![Action::Read, Action::Write],
        attacker.verifying_key().to_bytes(),
        Some(&attacker),
    );

    let err = acl::check_bucket_access(&node.client, &agent_pk, &bucket, Action::Write)
        .expect_err("grant signed by a non-admin key must be denied");
    assert!(matches!(err, memvault_api::ApiError::Forbidden(_)));
}

/// A grant claiming a real admin's `admin_pubkey` but signed by someone
/// else (signature won't verify) must be denied.
#[tokio::test]
async fn grant_with_admin_pubkey_but_bad_signature_denied() {
    let node = TestNode::new();
    let (agent_pk, _) = setup_agent(&node, "badsig-agent", AgentRole::AgentHost).await;
    let bucket = make_bucket(&node, "badsig-bucket").await;

    let admin_pubkey = node
        .client
        .admin_signing_key()
        .expect("admin key")
        .verifying_key()
        .to_bytes();
    // Claim the real admin's pubkey, but sign with a different key.
    let mut seed = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut seed);
    let imposter = SigningKey::from_bytes(&seed);

    insert_raw_grant(
        &node,
        &bucket,
        GrantAudience::Peer(PeerId(agent_pk.to_vec())),
        vec![Action::Read],
        admin_pubkey,
        Some(&imposter),
    );

    let err = acl::check_bucket_access(&node.client, &agent_pk, &bucket, Action::Read)
        .expect_err("grant with mismatched signature must be denied");
    assert!(matches!(err, memvault_api::ApiError::Forbidden(_)));
}

#[tokio::test]
async fn no_attestation_denied() {
    let node = TestNode::new();
    let bucket = make_bucket(&node, "no-att-bucket").await;

    // Random pubkey with no on-chain attestation — must be denied even
    // when a Role grant covers AgentHost broadly.
    let mut bogus = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bogus);

    node.client
        .issue_bucket_grant(
            &bucket,
            GrantAudience::Role(AgentRole::AgentHost),
            vec![Action::Read],
            u64::MAX,
        )
        .await
        .expect("issue role grant");

    let err = acl::check_bucket_access(&node.client, &bogus, &bucket, Action::Read)
        .expect_err("caller with no attestation is unidentified → Forbidden");
    assert!(matches!(err, memvault_api::ApiError::Forbidden(_)));
}

// ── Multi-admin lifecycle ────────────────────────────────────────────

/// After admitting a second admin key, grants signed by that key verify.
#[tokio::test]
async fn admitted_admin_grant_accepted() {
    let node = TestNode::new();
    let (agent_pk, _) = setup_agent(&node, "admit-agent", AgentRole::AgentHost).await;
    let bucket = make_bucket(&node, "admit-bucket").await;

    // New operator generates their key + POP offline (POP never expires).
    let mut seed = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut seed);
    let admin2 = SigningKey::from_bytes(&seed);
    let pop = memvault_auth::sign_admin_pop(&admin2, &node.cluster_id, u64::MAX);

    // Anchor admits admin2 (valid from now; backdating is clamped away).
    node.client
        .admit_admin_key(admin2.verifying_key().to_bytes(), pop, u64::MAX, None)
        .await
        .expect("admit admin2");

    // A grant signed by admin2, issued now (within admin2's window), is
    // accepted.
    let not_before = memvault_core::wall_ns();
    insert_raw_grant_at(
        &node,
        &bucket,
        GrantAudience::Peer(PeerId(agent_pk.to_vec())),
        vec![Action::Read],
        admin2.verifying_key().to_bytes(),
        Some(&admin2),
        not_before,
    );
    acl::check_bucket_access(&node.client, &agent_pk, &bucket, Action::Read)
        .expect("grant signed by admitted admin must be accepted");
}

/// A retired admin's grants issued before retirement keep working; grants
/// it would issue after retirement are rejected.
#[tokio::test]
async fn retired_admin_past_grant_survives_new_rejected() {
    let node = TestNode::new();
    let (agent_pk, _) = setup_agent(&node, "retire-agent", AgentRole::AgentHost).await;
    let bucket = make_bucket(&node, "retire-bucket").await;

    let mut seed = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut seed);
    let admin2 = SigningKey::from_bytes(&seed);
    let admin2_pk = admin2.verifying_key().to_bytes();
    let pop = memvault_auth::sign_admin_pop(&admin2, &node.cluster_id, u64::MAX);
    node.client
        .admit_admin_key(admin2_pk, pop, u64::MAX, None)
        .await
        .expect("admit admin2");

    // Grant issued now, while admin2 is valid (not_before within its window).
    let pre_retire_nb = memvault_core::wall_ns();
    insert_raw_grant_at(
        &node,
        &bucket,
        GrantAudience::Peer(PeerId(agent_pk.to_vec())),
        vec![Action::Read],
        admin2_pk,
        Some(&admin2),
        pre_retire_nb,
    );
    acl::check_bucket_access(&node.client, &agent_pk, &bucket, Action::Read)
        .expect("pre-retirement grant valid");

    // Retire admin2 (signed by the still-held anchor).
    let retire_at = node
        .client
        .retire_admin_key(admin2_pk, "offboarding")
        .await
        .expect("retire admin2");
    assert!(!retire_at.is_empty());

    // Past grant still valid (its not_before precedes the retirement).
    acl::check_bucket_access(&node.client, &agent_pk, &bucket, Action::Read)
        .expect("past grant survives retirement");

    // A grant admin2 issues *after* retirement (not_before in the far
    // future, past the retirement instant) must be rejected.
    let bucket2 = make_bucket(&node, "retire-bucket-2").await;
    insert_raw_grant_at(
        &node,
        &bucket2,
        GrantAudience::Peer(PeerId(agent_pk.to_vec())),
        vec![Action::Read],
        admin2_pk,
        Some(&admin2),
        u64::MAX - 1,
    );
    let err = acl::check_bucket_access(&node.client, &agent_pk, &bucket2, Action::Read)
        .expect_err("post-retirement grant must be rejected");
    assert!(matches!(err, memvault_api::ApiError::Forbidden(_)));
}

/// The cluster must never be able to retire its last valid admin.
#[tokio::test]
async fn cannot_retire_last_admin() {
    let node = TestNode::new();
    let anchor_pk = node
        .client
        .admin_signing_key()
        .expect("anchor key")
        .verifying_key()
        .to_bytes();

    let err = node
        .client
        .retire_admin_key(anchor_pk, "oops")
        .await
        .expect_err("retiring the only admin must fail");
    assert!(matches!(err, memvault_api::ApiError::Other(_)));
}

/// A grant whose signed `bucket_scopes` is bucket A must NOT authorize
/// bucket B even if its storage tag points at B (tag is unsigned; the
/// signed scope is authoritative). Guards the tag-vs-scope confusion.
#[tokio::test]
async fn grant_scoped_to_other_bucket_denied() {
    let node = TestNode::new();
    let (agent_pk, _) = setup_agent(&node, "scope-agent", AgentRole::AgentHost).await;
    let bucket_a = make_bucket(&node, "scope-bucket-a").await;
    let bucket_b = make_bucket(&node, "scope-bucket-b").await;

    let admin_key = node.client.admin_signing_key().expect("admin key");
    let admin_pk = admin_key.verifying_key().to_bytes();

    // Build a grant SIGNED for bucket_a, but store it under bucket_b's tag.
    let mut nonce = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut nonce);
    let mut grant = Grant {
        issuer: PeerId(node.client.peer_id().to_vec()),
        issuing_cluster: node.cluster_id.clone(),
        admin_pubkey: admin_pk,
        audience: GrantAudience::Peer(PeerId(agent_pk.to_vec())),
        scopes: vec![],
        actions: vec![Action::Read],
        not_before_ns: 1,
        not_after_ns: u64::MAX,
        parent: None,
        nonce,
        bucket_scopes: vec![bucket_a.clone()], // signed scope = A
        signature: [0u8; 64],
    };
    use ed25519_dalek::Signer;
    let sb = grant.signing_bytes().expect("signing bytes");
    grant.signature = admin_key.sign(&sb).to_bytes();
    let grant_bytes = serde_ipld_dagcbor::to_vec(&grant).expect("encode");
    let cid = memvault_core::cid_from_bytes(&grant_bytes);
    let meta = memvault_store::EnvelopeMeta {
        author: node.client.peer_id().to_vec(),
        tags: vec![
            ("grant".to_string(), hex::encode(bucket_b.0)), // mis-tagged under B
            ("kind".to_string(), "grant".to_string()),
        ],
        wall_ns: 1,
        cluster_id: Some(node.cluster_id.0.to_vec()),
        bucket_id: Some(bucket_b.0.to_vec()),
        ..Default::default()
    };
    node.client
        .store()
        .insert_envelope(&cid.to_bytes(), &grant_bytes, &meta)
        .expect("insert");

    // The grant is admin-signed and valid, but its signed scope is A —
    // it must NOT confer access on B.
    let err = acl::check_bucket_access(&node.client, &agent_pk, &bucket_b, Action::Read)
        .expect_err("grant scoped to A must not authorize B");
    assert!(matches!(err, memvault_api::ApiError::Forbidden(_)));
}

/// A future-dated grant (not_before in the future) must not yet confer
/// access.
#[tokio::test]
async fn future_dated_grant_denied() {
    let node = TestNode::new();
    let (agent_pk, _) = setup_agent(&node, "future-agent", AgentRole::AgentHost).await;
    let bucket = make_bucket(&node, "future-bucket").await;
    let admin_key = node.client.admin_signing_key().expect("admin key");

    insert_raw_grant_at(
        &node,
        &bucket,
        GrantAudience::Peer(PeerId(agent_pk.to_vec())),
        vec![Action::Read],
        admin_key.verifying_key().to_bytes(),
        Some(&admin_key),
        u64::MAX - 1, // not_before far in the future
    );
    let err = acl::check_bucket_access(&node.client, &agent_pk, &bucket, Action::Read)
        .expect_err("future-dated grant must not be valid yet");
    assert!(matches!(err, memvault_api::ApiError::Forbidden(_)));
}

/// A synced grant-revocation block (admin-signed) must be applied to the
/// local revocation index by scan_grant_revocations — the path a peer
/// uses at bootstrap. Models cross-node revocation propagation: the
/// revocation block arrives via sync but record_revocation wasn't called
/// locally, yet the grant must stop conferring access once scanned.
#[tokio::test]
async fn synced_grant_revocation_applies_on_scan() {
    let node = TestNode::new();
    let (agent_pk, _) = setup_agent(&node, "syncrev-agent", AgentRole::AgentHost).await;
    let bucket = make_bucket(&node, "syncrev-bucket").await;

    let grant_cid = node
        .client
        .issue_bucket_grant(
            &bucket,
            GrantAudience::AgentKey(agent_pk),
            vec![Action::Read],
            u64::MAX,
        )
        .await
        .expect("issue grant");
    acl::check_bucket_access(&node.client, &agent_pk, &bucket, Action::Read)
        .expect("grant works before revocation");

    // Build an admin-signed GrantRevocation and insert it as a sigchain
    // block WITHOUT calling record_revocation (simulating arrival via sync).
    let admin_key = node.client.admin_signing_key().expect("admin key");
    let raw_grant = node.client.store().get_block(&grant_cid).unwrap().unwrap();
    let target_cid = memvault_core::cid_from_bytes(&raw_grant);
    let rev = memvault_auth::sign_grant_revocation(&admin_key, target_cid, "synced")
        .expect("sign revocation");
    let rev_bytes = serde_ipld_dagcbor::to_vec(&rev).expect("encode");
    let rev_cid = memvault_core::cid_from_bytes(&rev_bytes);
    let meta = memvault_store::EnvelopeMeta {
        author: node.client.peer_id().to_vec(),
        tags: vec![("sigchain".to_string(), "grant_revocation".to_string())],
        wall_ns: 1,
        cluster_id: Some(node.cluster_id.0.to_vec()),
        ..Default::default()
    };
    node.client
        .store()
        .insert_envelope(&rev_cid.to_bytes(), &rev_bytes, &meta)
        .expect("insert revocation block");

    // Not yet applied to the index → still authorized.
    acl::check_bucket_access(&node.client, &agent_pk, &bucket, Action::Read)
        .expect("still works before scan applies the revocation");

    // The bootstrap-equivalent scan applies it.
    let admin_keys = node.client.admin_verifying_keys();
    let applied =
        memvault_api::sigchain::scan_grant_revocations(&node.client, &admin_keys).expect("scan");
    assert_eq!(applied, 1);

    let err = acl::check_bucket_access(&node.client, &agent_pk, &bucket, Action::Read)
        .expect_err("revoked after scan");
    assert!(matches!(err, memvault_api::ApiError::Forbidden(_)));
}

/// An agent revocation is honoured only when signed by the node that
/// attested the agent — a different (even trusted) node cannot revoke
/// another node's agents.
#[tokio::test]
async fn agent_revocation_must_come_from_attesting_node() {
    use memvault_auth::jwt::NodeTrust;
    use std::collections::HashMap;

    let node = TestNode::new();
    let (agent_pk, _) = setup_agent(&node, "rev-bind-agent", AgentRole::AgentHost).await;

    // The agent was attested by this node's node key (the attester).
    let attester_pk = node
        .client
        .node_signing_key()
        .expect("node key")
        .verifying_key()
        .to_bytes();

    // A foreign node (not the attester) tries to revoke the agent.
    let mut seed = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut seed);
    let foreign = SigningKey::from_bytes(&seed);
    let foreign_pk = foreign.verifying_key().to_bytes();
    let rev = memvault_auth::sign_agent_revocation(&foreign, agent_pk, "malicious")
        .expect("sign foreign revocation");
    memvault_api::sigchain::publish_agent_revocation(&node.client, &rev).expect("publish");

    // Trust map with BOTH nodes trusted.
    let mut node_trust: HashMap<[u8; 32], NodeTrust> = HashMap::new();
    node_trust.insert(foreign_pk, NodeTrust::PreGenesis);
    node_trust.insert(attester_pk, NodeTrust::PreGenesis);
    let admin_keys = node.client.admin_verifying_keys();

    let (revoked, _) =
        memvault_api::sigchain::scan_revocations(&node.client, &admin_keys, &node_trust)
            .expect("scan");
    assert!(
        !revoked.contains(&agent_pk),
        "foreign (non-attesting) node must not be able to revoke the agent"
    );

    // The attesting node CAN revoke it.
    let node_sk = node.client.node_signing_key().expect("node key").clone();
    let rev2 = memvault_auth::sign_agent_revocation(&node_sk, agent_pk, "legitimate")
        .expect("sign attester revocation");
    memvault_api::sigchain::publish_agent_revocation(&node.client, &rev2).expect("publish2");
    let (revoked2, _) =
        memvault_api::sigchain::scan_revocations(&node.client, &admin_keys, &node_trust)
            .expect("scan2");
    assert!(
        revoked2.contains(&agent_pk),
        "the attesting node's revocation must be honoured"
    );
}

/// admit_admin_key rejects a POP whose bound expiry has already passed —
/// a captured POP cannot be replayed indefinitely.
#[tokio::test]
async fn admit_rejects_expired_pop() {
    let node = TestNode::new();
    let mut seed = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut seed);
    let admin2 = SigningKey::from_bytes(&seed);
    // POP bound to an expiry in the distant past.
    let pop = memvault_auth::sign_admin_pop(&admin2, &node.cluster_id, 1);
    let err = node
        .client
        .admit_admin_key(admin2.verifying_key().to_bytes(), pop, 1, None)
        .await
        .expect_err("expired POP must be rejected");
    assert!(matches!(err, memvault_api::ApiError::Other(_)));
}

// ── Owner / attesting-node grant authority (paths 2 & 3) ─────────────

/// Attest an agent and return its signing key too, so tests can sign
/// owner grants with it.
async fn setup_agent_keyed(
    node: &TestNode,
    name: &str,
    role: AgentRole,
) -> (SigningKey, [u8; 32], AgentName) {
    let node_sk = node.client.node_signing_key().expect("node key").clone();
    let mut seed = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut seed);
    let agent_sk = SigningKey::from_bytes(&seed);
    let agent_pk = agent_sk.verifying_key().to_bytes();
    let att = sign_agent_attestation(
        &node_sk,
        AgentName(name.to_string()),
        agent_pk,
        role,
        u64::MAX,
    )
    .expect("sign attestation");
    memvault_api::sigchain::publish_agent_attestation(&node.client, &att).expect("publish");
    (agent_sk, agent_pk, AgentName(name.to_string()))
}

async fn make_owned_bucket(
    node: &TestNode,
    name: &str,
    owner: AgentName,
    owner_pk: [u8; 32],
) -> BucketId {
    node.client
        .bucket_create_as(
            owner,
            Some(owner_pk),
            name,
            None,
            Visibility::Internal,
            memvault_core::classification::Classification::Internal,
            memvault_doc::BucketRole::Standard,
        )
        .await
        .expect("create owned bucket")
}

/// Path 2: the bucket owner's own agent key can grant access to its bucket.
#[tokio::test]
async fn owner_signed_grant_accepted() {
    let node = TestNode::new();
    let (owner_sk, owner_pk, owner_id) =
        setup_agent_keyed(&node, "owner-issuer", AgentRole::AgentHost).await;
    let (grantee_pk, _) = setup_agent(&node, "grantee", AgentRole::AgentHost).await;
    let bucket = make_owned_bucket(&node, "owner-issued-bucket", owner_id, owner_pk).await;

    // Owner signs a grant for the grantee with its own agent key.
    insert_raw_grant_at(
        &node,
        &bucket,
        GrantAudience::Peer(PeerId(grantee_pk.to_vec())),
        vec![Action::Read],
        owner_pk,
        Some(&owner_sk),
        memvault_core::wall_ns(),
    );
    acl::check_bucket_access(&node.client, &grantee_pk, &bucket, Action::Read)
        .expect("owner-signed grant must authorize the grantee");
}

/// Path 3: the node that attested the owner can grant on its behalf
/// (host-on-behalf), signing with the node key — no admin needed.
#[tokio::test]
async fn attesting_node_signed_grant_accepted() {
    let node = TestNode::new();
    let (_owner_sk, owner_pk, owner_id) =
        setup_agent_keyed(&node, "hosted-owner", AgentRole::AgentHost).await;
    let (grantee_pk, _) = setup_agent(&node, "host-grantee", AgentRole::AgentHost).await;
    let bucket = make_owned_bucket(&node, "host-issued-bucket", owner_id, owner_pk).await;

    let node_sk = node.client.node_signing_key().expect("node key").clone();
    let node_pk = node_sk.verifying_key().to_bytes();

    // Path 3 requires the attesting node to be a trusted cluster node.
    // Production installs this via bootstrap; the bare harness doesn't, so
    // install a minimal trust state trusting our node.
    {
        use memvault_auth::jwt::NodeTrust;
        use std::collections::{HashMap, HashSet};
        use std::sync::{Arc, RwLock};
        let mut nt = HashMap::new();
        nt.insert(node_pk, NodeTrust::PreGenesis);
        node.client
            .set_trust_state(memvault_api::sigchain::LiveTrustState {
                node_trust: Arc::new(RwLock::new(nt)),
                revoked_agents: Arc::new(RwLock::new(HashSet::new())),
                revoked_nodes: Arc::new(RwLock::new(HashSet::new())),
                trusted_agents: Arc::new(RwLock::new(HashSet::new())),
                trusted_attestations: Arc::new(RwLock::new(HashMap::new())),
            });
    }

    insert_raw_grant_at(
        &node,
        &bucket,
        GrantAudience::Peer(PeerId(grantee_pk.to_vec())),
        vec![Action::Read],
        node_pk,
        Some(&node_sk),
        memvault_core::wall_ns(),
    );
    acl::check_bucket_access(&node.client, &grantee_pk, &bucket, Action::Read)
        .expect("attesting-node grant must authorize the grantee");
}

/// A node-signed grant on a bucket with no owner (not owned by an agent
/// this node attested) is denied — host authority is scoped to owned
/// buckets, the node isn't an admin.
#[tokio::test]
async fn node_signed_grant_on_unowned_bucket_denied() {
    let node = TestNode::new();
    let (grantee_pk, _) = setup_agent(&node, "unowned-grantee", AgentRole::AgentHost).await;
    let bucket = make_bucket(&node, "unowned-bucket").await; // owner_agent_pubkey = None

    let node_sk = node.client.node_signing_key().expect("node key").clone();
    let node_pk = node_sk.verifying_key().to_bytes();
    insert_raw_grant_at(
        &node,
        &bucket,
        GrantAudience::Peer(PeerId(grantee_pk.to_vec())),
        vec![Action::Read],
        node_pk,
        Some(&node_sk),
        memvault_core::wall_ns(),
    );
    let err = acl::check_bucket_access(&node.client, &grantee_pk, &bucket, Action::Read)
        .expect_err("node-signed grant on an unowned bucket must be denied");
    assert!(matches!(err, memvault_api::ApiError::Forbidden(_)));
}

/// A node-owned bucket (e.g. the per-node legacy bucket) can be delegated
/// by the owning node's key — no admin or agent owner needed. A different
/// node's signature is rejected.
#[tokio::test]
async fn node_owned_bucket_grant_authority() {
    let node = TestNode::new();
    let (grantee_pk, _) = setup_agent(&node, "node-owned-grantee", AgentRole::AgentHost).await;

    let node_sk = node.client.node_signing_key().expect("node key").clone();
    let node_pk = node_sk.verifying_key().to_bytes();

    // A node-owned bucket (role Legacy, owner_node_pubkey = this node).
    let bucket = BucketId([0x5a; 32]);
    node.client
        .create_bucket_with_id(
            bucket.clone(),
            "legacy",
            None,
            Visibility::Internal,
            memvault_core::classification::Classification::Internal,
            memvault_doc::BucketRole::Legacy,
            Some(node_pk),
        )
        .expect("create node-owned bucket");

    // Trust this node (production installs trust via bootstrap).
    {
        use memvault_auth::jwt::NodeTrust;
        use std::collections::{HashMap, HashSet};
        use std::sync::{Arc, RwLock};
        let mut nt = HashMap::new();
        nt.insert(node_pk, NodeTrust::PreGenesis);
        node.client
            .set_trust_state(memvault_api::sigchain::LiveTrustState {
                node_trust: Arc::new(RwLock::new(nt)),
                revoked_agents: Arc::new(RwLock::new(HashSet::new())),
                revoked_nodes: Arc::new(RwLock::new(HashSet::new())),
                trusted_agents: Arc::new(RwLock::new(HashSet::new())),
                trusted_attestations: Arc::new(RwLock::new(HashMap::new())),
            });
    }

    // Owning node signs a grant with its node key → accepted.
    insert_raw_grant_at(
        &node,
        &bucket,
        GrantAudience::Peer(PeerId(grantee_pk.to_vec())),
        vec![Action::Read],
        node_pk,
        Some(&node_sk),
        memvault_core::wall_ns(),
    );
    acl::check_bucket_access(&node.client, &grantee_pk, &bucket, Action::Read)
        .expect("node-owner grant must authorize the grantee");

    // A different (non-owning) node's grant is denied.
    let mut seed = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut seed);
    let other_node = SigningKey::from_bytes(&seed);
    let bucket2 = make_bucket(&node, "other-node-bucket").await; // no node owner
    insert_raw_grant_at(
        &node,
        &bucket2,
        GrantAudience::Peer(PeerId(grantee_pk.to_vec())),
        vec![Action::Read],
        other_node.verifying_key().to_bytes(),
        Some(&other_node),
        memvault_core::wall_ns(),
    );
    let err = acl::check_bucket_access(&node.client, &grantee_pk, &bucket2, Action::Read)
        .expect_err("non-owning node grant must be denied");
    assert!(matches!(err, memvault_api::ApiError::Forbidden(_)));
}

// ── Path 2: submit externally-signed grant ──────────────────────────

fn build_signed_grant(
    node: &TestNode,
    bucket: &BucketId,
    audience: GrantAudience,
    actions: Vec<Action>,
    signer_pk: [u8; 32],
    signer: &SigningKey,
    not_before_ns: u64,
) -> Grant {
    let mut nonce = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut nonce);
    let mut grant = Grant {
        issuer: PeerId(node.client.peer_id().to_vec()),
        issuing_cluster: node.cluster_id.clone(),
        admin_pubkey: signer_pk,
        audience,
        scopes: vec![],
        actions,
        not_before_ns,
        not_after_ns: u64::MAX,
        parent: None,
        nonce,
        bucket_scopes: vec![bucket.clone()],
        signature: [0u8; 64],
    };
    use ed25519_dalek::Signer;
    let sb = grant.signing_bytes().expect("signing bytes");
    grant.signature = signer.sign(&sb).to_bytes();
    grant
}

/// A grant the owner signed client-side can be submitted (path 2) and then
/// authorizes the grantee — the daemon stores it without signing.
#[tokio::test]
async fn submit_signed_grant_owner_accepted() {
    let node = TestNode::new();
    let (owner_sk, owner_pk, owner_id) =
        setup_agent_keyed(&node, "submit-owner", AgentRole::AgentHost).await;
    let (grantee_pk, _) = setup_agent(&node, "submit-grantee", AgentRole::AgentHost).await;
    let bucket = make_owned_bucket(&node, "submit-bucket", owner_id, owner_pk).await;

    let grant = build_signed_grant(
        &node,
        &bucket,
        GrantAudience::Peer(PeerId(grantee_pk.to_vec())),
        vec![Action::Read],
        owner_pk,
        &owner_sk,
        memvault_core::wall_ns(),
    );
    node.client
        .submit_signed_grant(&grant)
        .expect("owner-signed grant accepted on submit");

    acl::check_bucket_access(&node.client, &grantee_pk, &bucket, Action::Read)
        .expect("submitted owner grant authorizes the grantee");
}

/// Submitting a grant signed by a key with no authority over the bucket
/// is rejected.
#[tokio::test]
async fn submit_signed_grant_unauthorized_rejected() {
    let node = TestNode::new();
    let (_owner_sk, owner_pk, owner_id) =
        setup_agent_keyed(&node, "submit-owner2", AgentRole::AgentHost).await;
    let (grantee_pk, _) = setup_agent(&node, "submit-grantee2", AgentRole::AgentHost).await;
    let bucket = make_owned_bucket(&node, "submit-bucket2", owner_id, owner_pk).await;

    // A random key (not admin, owner, or attesting node).
    let mut seed = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut seed);
    let stranger = SigningKey::from_bytes(&seed);
    let grant = build_signed_grant(
        &node,
        &bucket,
        GrantAudience::Peer(PeerId(grantee_pk.to_vec())),
        vec![Action::Read],
        stranger.verifying_key().to_bytes(),
        &stranger,
        memvault_core::wall_ns(),
    );
    let err = node
        .client
        .submit_signed_grant(&grant)
        .expect_err("unauthorized issuer must be rejected on submit");
    assert!(matches!(err, memvault_api::ApiError::Forbidden(_)));
}

/// If two distinct nodes attest the same owner agent, host-on-behalf
/// authority is ambiguous and denied for everyone — a rival trusted node
/// can't seize delegation authority by minting a second attestation.
#[tokio::test]
async fn conflicting_attestations_deny_host_authority() {
    let node = TestNode::new();
    let (_owner_sk, owner_pk, owner_id) =
        setup_agent_keyed(&node, "ambig-owner", AgentRole::AgentHost).await;
    let (grantee_pk, _) = setup_agent(&node, "ambig-grantee", AgentRole::AgentHost).await;
    let bucket = make_owned_bucket(&node, "ambig-bucket", owner_id.clone(), owner_pk).await;

    let node_sk = node.client.node_signing_key().expect("node key").clone();
    let node_pk = node_sk.verifying_key().to_bytes();

    // A rival key publishes a second attestation for the same owner pubkey.
    let mut seed = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut seed);
    let rival = SigningKey::from_bytes(&seed);
    let rival_att =
        sign_agent_attestation(&rival, owner_id, owner_pk, AgentRole::AgentHost, u64::MAX)
            .expect("rival attestation");
    memvault_api::sigchain::publish_agent_attestation(&node.client, &rival_att)
        .expect("publish rival attestation");

    // Trust the legit node.
    {
        use memvault_auth::jwt::NodeTrust;
        use std::collections::{HashMap, HashSet};
        use std::sync::{Arc, RwLock};
        let mut nt = HashMap::new();
        nt.insert(node_pk, NodeTrust::PreGenesis);
        node.client
            .set_trust_state(memvault_api::sigchain::LiveTrustState {
                node_trust: Arc::new(RwLock::new(nt)),
                revoked_agents: Arc::new(RwLock::new(HashSet::new())),
                revoked_nodes: Arc::new(RwLock::new(HashSet::new())),
                trusted_agents: Arc::new(RwLock::new(HashSet::new())),
                trusted_attestations: Arc::new(RwLock::new(HashMap::new())),
            });
    }

    // The legit node's host-on-behalf grant is now denied (ambiguous attester).
    insert_raw_grant_at(
        &node,
        &bucket,
        GrantAudience::Peer(PeerId(grantee_pk.to_vec())),
        vec![Action::Read],
        node_pk,
        Some(&node_sk),
        memvault_core::wall_ns(),
    );
    let err = acl::check_bucket_access(&node.client, &grantee_pk, &bucket, Action::Read)
        .expect_err("host authority must be denied under conflicting attestations");
    assert!(matches!(err, memvault_api::ApiError::Forbidden(_)));
}

// ── Phase 1: AgentKey(pubkey) audience ──────────────────────────────────
// The canonical, collision-free agent grant. Access matches the caller's
// verified ed25519 pubkey directly, so two nodes' same-named agents never
// share access the way a legacy Agent(string) grant would.

#[tokio::test]
async fn agentkey_grant_allows_matching_pubkey() {
    let node = TestNode::new();
    let (agent_pk, _) = setup_agent(&node, "ak-agent", AgentRole::AgentHost).await;
    let bucket = make_bucket(&node, "ak-bucket").await;

    node.client
        .issue_bucket_grant(
            &bucket,
            GrantAudience::AgentKey(agent_pk),
            vec![Action::Read],
            u64::MAX,
        )
        .await
        .expect("issue agentkey grant");

    acl::check_bucket_access(&node.client, &agent_pk, &bucket, Action::Read)
        .expect("AgentKey grant for the matching pubkey should pass");
    // Read-only grant: Write still denied.
    let err = acl::check_bucket_access(&node.client, &agent_pk, &bucket, Action::Write)
        .expect_err("Write must require a Write grant");
    assert!(matches!(err, memvault_api::ApiError::Forbidden(_)));
}

#[tokio::test]
async fn agentkey_grant_denies_other_pubkey() {
    let node = TestNode::new();
    // Two agents sharing the SAME agent_id label "alice" but different
    // pubkeys — the exact cross-node collision an Agent(string) grant can't
    // distinguish. An AgentKey grant must bind to one pubkey only.
    let (alice_a_pk, _) = setup_agent(&node, "alice", AgentRole::AgentHost).await;
    let (alice_b_pk, _) = setup_agent(&node, "alice", AgentRole::AgentHost).await;
    assert_ne!(alice_a_pk, alice_b_pk, "the two alices must differ by key");
    let bucket = make_bucket(&node, "ak-deny-bucket").await;

    node.client
        .issue_bucket_grant(
            &bucket,
            GrantAudience::AgentKey(alice_a_pk),
            vec![Action::Read],
            u64::MAX,
        )
        .await
        .expect("issue agentkey grant for alice_a");

    acl::check_bucket_access(&node.client, &alice_a_pk, &bucket, Action::Read)
        .expect("alice_a (granted pubkey) should pass");
    let err = acl::check_bucket_access(&node.client, &alice_b_pk, &bucket, Action::Read)
        .expect_err("alice_b (same label, different pubkey) must be denied");
    assert!(matches!(err, memvault_api::ApiError::Forbidden(_)));
}

#[tokio::test]
async fn owner_bypass_uses_owner_pubkey_not_label() {
    let node = TestNode::new();
    let (owner_pk, owner_id) = setup_agent(&node, "alice", AgentRole::AgentHost).await;
    // A second "alice" on a different key must NOT inherit ownership.
    let (other_pk, _) = setup_agent(&node, "alice", AgentRole::AgentHost).await;
    assert_ne!(owner_pk, other_pk);

    let bucket = node
        .client
        .ensure_agent_bucket_for_pubkey(&owner_pk, &owner_id.0)
        .await
        .expect("ensure agent bucket");

    // Real owner bypasses without a grant.
    acl::check_bucket_access(&node.client, &owner_pk, &bucket, Action::Write)
        .expect("real owner pubkey bypasses");
    // Same-label impostor is denied (no grant, owner pubkey mismatch).
    let err = acl::check_bucket_access(&node.client, &other_pk, &bucket, Action::Read)
        .expect_err("same-label different-pubkey must not inherit ownership");
    assert!(matches!(err, memvault_api::ApiError::Forbidden(_)));
}

#[tokio::test]
async fn legacy_owner_pubkey_absent_falls_back_to_label() {
    let node = TestNode::new();
    let (agent_pk, agent_id) = setup_agent(&node, "legacy-owner", AgentRole::AgentHost).await;

    // Legacy bucket: owner_agent recorded, owner_agent_pubkey absent (None).
    let bucket = node
        .client
        .bucket_create_as(
            agent_id,
            None, // no owner pubkey → legacy shape
            "legacy-owned",
            None,
            Visibility::Internal,
            memvault_core::classification::Classification::Internal,
            memvault_doc::BucketRole::Standard,
        )
        .await
        .expect("create legacy owned bucket");

    // With no owner pubkey on record, owner-bypass falls back to the agent_id
    // string so the owner still gets in (back-compat).
    acl::check_bucket_access(&node.client, &agent_pk, &bucket, Action::Write)
        .expect("legacy label fallback owner bypass");
}

/// Bucket merge + ACL: a grant on the **canonical** authorizes access to a
/// **source's** content (the merge normalizes source → canonical in
/// `check_bucket_access`), and a source with no grant of its own is denied
/// until the merge lands. Proves canonical-governs ACL semantics.
#[tokio::test]
async fn grant_on_canonical_authorizes_merged_source() {
    let node = TestNode::new();
    let (agent_pk, _) = setup_agent(&node, "merge-acl-agent", AgentRole::AgentHost).await;
    let canonical = make_bucket(&node, "canonical-bucket").await;
    let source = make_bucket(&node, "source-bucket").await;

    // Grant the agent Read on the canonical only.
    node.client
        .issue_bucket_grant(
            &canonical,
            GrantAudience::AgentKey(agent_pk),
            vec![Action::Read],
            u64::MAX,
        )
        .await
        .expect("issue canonical grant");

    // Before the merge: the agent has no grant on the source → denied.
    let err = acl::check_bucket_access(&node.client, &agent_pk, &source, Action::Read)
        .expect_err("source has no grant of its own");
    assert!(matches!(err, memvault_api::ApiError::Forbidden(_)));

    // Merge the source into the canonical.
    node.client
        .bucket_merge_sync(&[source.clone()], &canonical)
        .expect("merge source into canonical");

    // After the merge: an access check against the source normalizes to the
    // canonical, where the agent's Read grant now authorizes it.
    acl::check_bucket_access(&node.client, &agent_pk, &source, Action::Read)
        .expect("canonical grant authorizes source content after merge");

    // The grant scope is still honored: Write was never granted.
    let err = acl::check_bucket_access(&node.client, &agent_pk, &source, Action::Write)
        .expect_err("Write still requires a Write grant on the canonical");
    assert!(matches!(err, memvault_api::ApiError::Forbidden(_)));
}

/// Orphaned attestation rejection: an agent attested by a node that was
/// NEVER attested into the cluster must confer NO access — not even
/// role=Admin. This is the ephemeral-identity-churn footgun (a throwaway
/// instance gossiping its `_ui` Admin agent into the cluster). The
/// attestation's own signature is valid; what's missing is a trusted
/// attesting node.
#[tokio::test]
async fn orphan_admin_agent_is_denied() {
    let node = TestNode::new();

    // A foreign node identity that holds no NodeAttestation in this cluster.
    let foreign_node = SigningKey::from_bytes(&[0x42u8; 32]);

    // Mint an Admin agent attestation signed by that orphan node.
    let mut seed = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut seed);
    let agent_pk = SigningKey::from_bytes(&seed).verifying_key().to_bytes();
    let att = memvault_auth::sign_agent_attestation(
        &foreign_node,
        AgentName("evil_ui".to_string()),
        agent_pk,
        AgentRole::Admin,
        u64::MAX,
    )
    .expect("sign orphan attestation");
    memvault_api::sigchain::publish_agent_attestation(&node.client, &att)
        .expect("publish orphan attestation");

    let bucket = make_bucket(&node, "victim-bucket").await;

    // Self-consistent + role=Admin, yet denied: the attesting node is orphaned.
    let err = acl::check_bucket_access(&node.client, &agent_pk, &bucket, Action::Read)
        .expect_err("orphaned Admin attestation must not confer access");
    assert!(
        matches!(err, memvault_api::ApiError::Forbidden(_)),
        "expected Forbidden for orphaned attestation, got {err:?}"
    );
}

/// Self-trust counterpart: the node's OWN agent (attested by its own node
/// key) is honored even with no admin NodeAttestation for itself yet —
/// the daemon's own `_ui` admin must work through the bootstrap window.
#[tokio::test]
async fn self_attested_admin_agent_is_allowed() {
    let node = TestNode::new();
    let (agent_pk, _) = setup_agent(&node, "ui-admin", AgentRole::Admin).await;
    let bucket = make_bucket(&node, "self-bucket").await;
    // Attested by the local node key (self-trust) → Admin bypass applies.
    acl::check_bucket_access(&node.client, &agent_pk, &bucket, Action::Write)
        .expect("self-attested Admin agent must pass");
}

/// The startup orphan sweep removes orphaned attestations but keeps
/// legitimate (self-attested) ones.
#[tokio::test]
async fn prune_orphaned_agent_attestations_sweeps_orphans_only() {
    let node = TestNode::new();

    // A legit self-attested agent (attesting node = this node).
    let (legit_pk, _) = setup_agent(&node, "legit-ui", AgentRole::Admin).await;

    // An orphan attested by a node never attested into the cluster.
    let foreign_node = SigningKey::from_bytes(&[0x77u8; 32]);
    let mut seed = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut seed);
    let orphan_pk = SigningKey::from_bytes(&seed).verifying_key().to_bytes();
    let att = memvault_auth::sign_agent_attestation(
        &foreign_node,
        AgentName("orphan-ui".to_string()),
        orphan_pk,
        AgentRole::Admin,
        u64::MAX,
    )
    .expect("sign orphan");
    memvault_api::sigchain::publish_agent_attestation(&node.client, &att).expect("publish orphan");

    // Sweep.
    let pruned = node
        .client
        .prune_orphaned_agent_attestations()
        .expect("prune");
    assert_eq!(pruned, 1, "exactly the orphan is pruned");

    // The orphan attestation is gone; the legit one survives.
    assert!(
        memvault_api::sigchain::find_agent_attestation(&node.client, &orphan_pk)
            .unwrap()
            .is_none(),
        "orphan attestation removed"
    );
    assert!(
        memvault_api::sigchain::find_agent_attestation(&node.client, &legit_pk)
            .unwrap()
            .is_some(),
        "legit self-attested agent kept"
    );
}

/// Post-genesis local agent end-to-end: a founder node, after the real
/// `bootstrap_cluster_trust`, must SELF-ATTEST its own node key as
/// `Attested` (not leave it `PreGenesis`). Otherwise a fresh agent enrolled
/// locally — attested by that node — fails `jwt::verify` with 401
/// ("PreGenesis trust returned but admin keys are configured"), which is
/// what broke the MCP's `/buckets/agent` call. This pins the invariant.
#[tokio::test]
async fn post_genesis_founder_self_attests_and_local_agent_is_trusted() {
    use ed25519_dalek::SigningKey;
    use memvault_auth::jwt::NodeTrust;
    use memvault_core::ClusterId;
    use std::sync::Arc;
    use tokio::sync::RwLock;

    let dir = tempfile::tempdir().unwrap();
    let store =
        Arc::new(memvault_store::MemvaultStore::open(dir.path().join("blocks.redb")).unwrap());
    let cluster_id = ClusterId([3u8; 32]);
    store.set_local_cluster_id(&cluster_id.0).unwrap();
    let mut peer_id = vec![0u8; 32];
    rand::thread_rng().fill_bytes(&mut peer_id);
    store.set_local_peer_id(&peer_id).unwrap();

    let client = Arc::new(memvault_api::LocalClient::new(
        Arc::clone(&store),
        Arc::new(RwLock::new(memvault_query::QuotaManager::default())),
        Arc::new(memvault_api::EventBus::new(64)),
        peer_id,
        cluster_id.0.to_vec(),
    ));
    let admin_sk = SigningKey::from_bytes(&[5u8; 32]);
    client.set_admin_signing_key(admin_sk.clone());
    let genesis =
        memvault_auth::sign_admin_genesis(&admin_sk, cluster_id.clone(), memvault_core::wall_ns())
            .unwrap();
    client.set_pinned_admin_genesis(genesis);
    let node_sk = SigningKey::from_bytes(&[9u8; 32]);
    let node_pk = node_sk.verifying_key().to_bytes();
    client.set_node_signing_key(node_sk);

    // Real bootstrap: holding the admin key, the founder must self-attest.
    let boot = memvault_api::bootstrap::bootstrap_cluster_trust(&client).expect("bootstrap");

    // The local node must be Attested, not PreGenesis.
    {
        let nt = boot.trust_state.node_trust.read().unwrap();
        match nt.get(&node_pk) {
            Some(NodeTrust::Attested(_)) => {}
            other => panic!("post-genesis founder node must be Attested, got {other:?}"),
        }
    }

    // A fresh local agent is attested by this (Attested) node, so its
    // attestation chains to a trusted node — `jwt::verify` would accept it.
    let agent = memvault_api::agent_identity::enroll_local_agent_in_keystore(
        &client,
        "mcp",
        AgentRole::Admin,
        u64::MAX,
    )
    .expect("enroll local agent");
    let att =
        memvault_api::sigchain::find_agent_attestation(&client, &agent.verifying_key.to_bytes())
            .unwrap()
            .expect("agent attestation present");
    assert_eq!(
        att.node_pubkey, node_pk,
        "local agent is attested by the local node key"
    );
    assert_eq!(att.not_after_ns, u64::MAX, "enrolled never-expiry");

    // "Test again": mint a JWT and run the daemon's exact verification. A
    // never-expiry attestation authenticates — the contrast with a lapsed
    // one, which jwt::verify rejects as "agent attestation: attestation
    // expired" (the real cause of the MCP's /buckets/agent 401).
    let token = agent.issue_jwt("read write admin", 300).expect("mint jwt");
    let admin_keys = vec![admin_sk.verifying_key()];
    let node_trust = boot.trust_state.node_trust.read().unwrap().clone();
    let claims = memvault_auth::jwt::verify(
        &token,
        &admin_keys,
        |pk| {
            memvault_api::sigchain::find_agent_attestation(&client, pk)
                .ok()
                .flatten()
        },
        |npk| node_trust.get(npk).cloned(),
    )
    .expect("never-expiry local agent must authenticate");
    assert_eq!(claims.iss, "mcp");
}

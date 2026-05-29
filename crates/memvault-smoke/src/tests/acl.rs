//! ACL enforcement (`memvault_api::acl::check_bucket_access`) — covers
//! owner bypass, Peer / Agent / Role audience matching, and the
//! expired-grant + no-grant deny paths.

use ed25519_dalek::SigningKey;
use rand::RngCore;

use memvault_api::MemvaultClient;
use memvault_api::acl;
use memvault_auth::{Action, Grant, GrantAudience, Role, sign_agent_attestation};
use memvault_core::{AgentId, BucketId, PeerId, Visibility};

use crate::harness::TestNode;

/// Build a node, mint an agent attestation against the node key, and
/// publish it. Returns the agent's ed25519 verifying key bytes — the
/// authoritative caller identity used by `check_bucket_access`.
async fn setup_agent(
    node: &TestNode,
    agent_name: &str,
    role: Role,
) -> ([u8; 32], AgentId) {
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
        AgentId(agent_name.to_string()),
        agent_pk,
        role,
        u64::MAX,
    )
    .expect("sign agent attestation");

    memvault_api::sigchain::publish_agent_attestation(&node.client, &attestation)
        .expect("publish attestation");

    (agent_pk, AgentId(agent_name.to_string()))
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
    let (agent_pk, _) = setup_agent(&node, "no-grant-agent", Role::AgentHost).await;
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
    let (agent_pk, _) = setup_agent(&node, "peer-agent", Role::AgentHost).await;
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
    let (agent_pk, agent_id) = setup_agent(&node, "named-agent", Role::AgentHost).await;
    let bucket = make_bucket(&node, "named-bucket").await;

    node.client
        .issue_bucket_grant(
            &bucket,
            GrantAudience::Agent(agent_id),
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
    let (agent_pk, _) = setup_agent(&node, "role-agent", Role::AgentHost).await;
    let bucket = make_bucket(&node, "role-bucket").await;

    node.client
        .issue_bucket_grant(
            &bucket,
            GrantAudience::Role(Role::AgentHost),
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
    let (agent_pk, _) = setup_agent(&node, "svc-agent", Role::Service).await;
    let bucket = make_bucket(&node, "role-mismatch-bucket").await;

    node.client
        .issue_bucket_grant(
            &bucket,
            GrantAudience::Role(Role::AgentHost),
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
    let (agent_pk, agent_id) = setup_agent(&node, "owner-agent", Role::AgentHost).await;

    // Mint a bucket owned by this agent via the deterministic
    // pubkey-keyed helper — same path the daemon uses for agent buckets.
    let bucket = node
        .client
        .ensure_agent_bucket_for_pubkey(&agent_pk, &agent_id.0)
        .await
        .expect("ensure agent bucket");

    // No explicit grant on chain — pure owner bypass.
    let grants = node.client.list_bucket_grants(&bucket).expect("list");
    assert!(grants.is_empty(), "no grants should exist for fresh agent bucket");

    acl::check_bucket_access(&node.client, &agent_pk, &bucket, Action::Read)
        .expect("owner Read");
    acl::check_bucket_access(&node.client, &agent_pk, &bucket, Action::Write)
        .expect("owner Write");
}

/// Regression: when the HTTP `POST /buckets` handler creates a bucket
/// on behalf of a caller, it threads the caller's `agent_id` through
/// `bucket_create_as` so the new bucket records them as `owner_agent`.
/// Without that, the BucketDecl inherited the daemon's identity and
/// the caller couldn't even read the bucket they just created.
#[tokio::test]
async fn bucket_create_as_sets_owner_and_grants_access() {
    let node = TestNode::new();
    let (agent_pk, agent_id) =
        setup_agent(&node, "create-as-agent", Role::AgentHost).await;

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

    acl::check_bucket_access(&node.client, &agent_pk, &bucket, Action::Read)
        .expect("creator Read");
    acl::check_bucket_access(&node.client, &agent_pk, &bucket, Action::Write)
        .expect("creator Write");
}

/// `revoke_bucket_grant` must take effect immediately — the same
/// `check_bucket_access` call that succeeded under the live grant
/// returns Forbidden once the revocation lands.
#[tokio::test]
async fn revoked_grant_denied() {
    let node = TestNode::new();
    let (agent_pk, agent_id) = setup_agent(&node, "revoke-agent", Role::AgentHost).await;
    let bucket = make_bucket(&node, "revoke-bucket").await;

    let grant_cid = node
        .client
        .issue_bucket_grant(
            &bucket,
            GrantAudience::Agent(agent_id.clone()),
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
    let (agent_pk, agent_id) = setup_agent(&node, "two-grant-agent", Role::AgentHost).await;
    let bucket = make_bucket(&node, "two-grant-bucket").await;

    // Two grants, same audience, same actions — only the first is revoked.
    let grant_a = node
        .client
        .issue_bucket_grant(
            &bucket,
            GrantAudience::Agent(agent_id.clone()),
            vec![Action::Read],
            u64::MAX,
        )
        .await
        .expect("grant A");
    let grant_b = node
        .client
        .issue_bucket_grant(
            &bucket,
            GrantAudience::Agent(agent_id),
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
    let (agent_pk, _) = setup_agent(&node, "expired-agent", Role::AgentHost).await;
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
    let (agent_pk, _) = setup_agent(&node, "legacy-agent", Role::AgentHost).await;
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
    let (agent_pk, _) = setup_agent(&node, "forge-agent", Role::AgentHost).await;
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
    let (agent_pk, _) = setup_agent(&node, "badsig-agent", Role::AgentHost).await;
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
            GrantAudience::Role(Role::AgentHost),
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
    let (agent_pk, _) = setup_agent(&node, "admit-agent", Role::AgentHost).await;
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
    let (agent_pk, _) = setup_agent(&node, "retire-agent", Role::AgentHost).await;
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
    let (agent_pk, _) = setup_agent(&node, "scope-agent", Role::AgentHost).await;
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
    let (agent_pk, _) = setup_agent(&node, "future-agent", Role::AgentHost).await;
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
    let (agent_pk, agent_id) = setup_agent(&node, "syncrev-agent", Role::AgentHost).await;
    let bucket = make_bucket(&node, "syncrev-bucket").await;

    let grant_cid = node
        .client
        .issue_bucket_grant(
            &bucket,
            GrantAudience::Agent(agent_id),
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
    use std::collections::HashMap;
    use memvault_auth::jwt::NodeTrust;

    let node = TestNode::new();
    let (agent_pk, _) = setup_agent(&node, "rev-bind-agent", Role::AgentHost).await;

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
    memvault_api::sigchain::publish_agent_revocation(&node.client, &rev)
        .expect("publish");

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
    memvault_api::sigchain::publish_agent_revocation(&node.client, &rev2)
        .expect("publish2");
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
    role: Role,
) -> (SigningKey, [u8; 32], AgentId) {
    let node_sk = node.client.node_signing_key().expect("node key").clone();
    let mut seed = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut seed);
    let agent_sk = SigningKey::from_bytes(&seed);
    let agent_pk = agent_sk.verifying_key().to_bytes();
    let att = sign_agent_attestation(
        &node_sk,
        AgentId(name.to_string()),
        agent_pk,
        role,
        u64::MAX,
    )
    .expect("sign attestation");
    memvault_api::sigchain::publish_agent_attestation(&node.client, &att).expect("publish");
    (agent_sk, agent_pk, AgentId(name.to_string()))
}

async fn make_owned_bucket(
    node: &TestNode,
    name: &str,
    owner: AgentId,
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
        setup_agent_keyed(&node, "owner-issuer", Role::AgentHost).await;
    let (grantee_pk, _) = setup_agent(&node, "grantee", Role::AgentHost).await;
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
        setup_agent_keyed(&node, "hosted-owner", Role::AgentHost).await;
    let (grantee_pk, _) = setup_agent(&node, "host-grantee", Role::AgentHost).await;
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
    let (grantee_pk, _) = setup_agent(&node, "unowned-grantee", Role::AgentHost).await;
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
    let (grantee_pk, _) = setup_agent(&node, "node-owned-grantee", Role::AgentHost).await;

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
        setup_agent_keyed(&node, "submit-owner", Role::AgentHost).await;
    let (grantee_pk, _) = setup_agent(&node, "submit-grantee", Role::AgentHost).await;
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
        setup_agent_keyed(&node, "submit-owner2", Role::AgentHost).await;
    let (grantee_pk, _) = setup_agent(&node, "submit-grantee2", Role::AgentHost).await;
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
        setup_agent_keyed(&node, "ambig-owner", Role::AgentHost).await;
    let (grantee_pk, _) = setup_agent(&node, "ambig-grantee", Role::AgentHost).await;
    let bucket = make_owned_bucket(&node, "ambig-bucket", owner_id.clone(), owner_pk).await;

    let node_sk = node.client.node_signing_key().expect("node key").clone();
    let node_pk = node_sk.verifying_key().to_bytes();

    // A rival key publishes a second attestation for the same owner pubkey.
    let mut seed = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut seed);
    let rival = SigningKey::from_bytes(&seed);
    let rival_att = sign_agent_attestation(
        &rival,
        owner_id,
        owner_pk,
        Role::AgentHost,
        u64::MAX,
    )
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

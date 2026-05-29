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

/// A grant predating the `admin_pubkey` field (all-zero) must be denied
/// under strict verification (the default) — otherwise a peer could
/// forge access by simply omitting the signer.
#[tokio::test]
async fn legacy_unsigned_grant_denied_when_strict() {
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

    assert!(node.client.strict_grant_verify(), "strict is the default");
    let err = acl::check_bucket_access(&node.client, &agent_pk, &bucket, Action::Read)
        .expect_err("legacy unsigned grant must be denied under strict");
    assert!(matches!(err, memvault_api::ApiError::Forbidden(_)));

    // Migration window: with strict off, the legacy grant is honoured.
    node.client.set_strict_grant_verify(false);
    acl::check_bucket_access(&node.client, &agent_pk, &bucket, Action::Read)
        .expect("legacy grant honoured when strict verification is disabled");
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

    // New operator generates their key + POP offline.
    let mut seed = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut seed);
    let admin2 = SigningKey::from_bytes(&seed);
    let pop = memvault_auth::sign_admin_pop(&admin2, &node.cluster_id);

    // Anchor admits admin2, valid from epoch so a not_before=1 grant lands
    // inside its window.
    node.client
        .admit_admin_key(admin2.verifying_key().to_bytes(), pop, Some(0))
        .await
        .expect("admit admin2");

    // A grant signed by admin2 must now be accepted.
    insert_raw_grant(
        &node,
        &bucket,
        GrantAudience::Peer(PeerId(agent_pk.to_vec())),
        vec![Action::Read],
        admin2.verifying_key().to_bytes(),
        Some(&admin2),
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
    let pop = memvault_auth::sign_admin_pop(&admin2, &node.cluster_id);
    node.client
        .admit_admin_key(admin2_pk, pop, Some(0))
        .await
        .expect("admit admin2");

    // Grant issued while admin2 is valid (not_before = 1).
    insert_raw_grant_at(
        &node,
        &bucket,
        GrantAudience::Peer(PeerId(agent_pk.to_vec())),
        vec![Action::Read],
        admin2_pk,
        Some(&admin2),
        1,
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

/// A grant signed by a registered local founder key is accepted on this
/// node (founder keys are trusted locally for pre-genesis private
/// buckets), even though the key is not in the cluster admin chain.
#[tokio::test]
async fn founder_key_grant_accepted_locally() {
    let node = TestNode::new();
    let (agent_pk, _) = setup_agent(&node, "founder-agent", Role::AgentHost).await;
    let bucket = make_bucket(&node, "founder-bucket").await;

    let mut seed = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut seed);
    let founder = SigningKey::from_bytes(&seed);
    let founder_pk = founder.verifying_key().to_bytes();

    // Before registration: a founder-signed grant is rejected (the key is
    // not a cluster admin).
    insert_raw_grant(
        &node,
        &bucket,
        GrantAudience::Peer(PeerId(agent_pk.to_vec())),
        vec![Action::Read],
        founder_pk,
        Some(&founder),
    );
    assert!(
        acl::check_bucket_access(&node.client, &agent_pk, &bucket, Action::Read).is_err(),
        "unregistered founder key must be rejected"
    );

    // After registration: accepted locally.
    node.client.register_founder_key(founder_pk);
    acl::check_bucket_access(&node.client, &agent_pk, &bucket, Action::Read)
        .expect("registered founder key grant accepted locally");
}

/// migrate_legacy_grants re-issues a legacy (unsigned) grant under the
/// admin key so access works under strict verification, and revokes the
/// legacy original.
#[tokio::test]
async fn migrate_legacy_grants_reissues_under_admin() {
    let node = TestNode::new();
    let (agent_pk, _) = setup_agent(&node, "migrate-agent", Role::AgentHost).await;
    let bucket = make_bucket(&node, "migrate-bucket").await;

    // A legacy unsigned grant (as written before the admin_pubkey field).
    insert_raw_grant(
        &node,
        &bucket,
        GrantAudience::Peer(PeerId(agent_pk.to_vec())),
        vec![Action::Read],
        [0u8; 32],
        None,
    );
    assert_eq!(node.client.count_legacy_grants().unwrap(), 1);
    // Denied under strict (the default).
    assert!(acl::check_bucket_access(&node.client, &agent_pk, &bucket, Action::Read).is_err());

    // Migrate: reissue under the admin key, revoke the legacy original.
    let (scanned, reissued) = node.client.migrate_legacy_grants().await.expect("migrate");
    assert_eq!((scanned, reissued), (1, 1));
    assert_eq!(node.client.count_legacy_grants().unwrap(), 0);

    // Access now works under strict verification.
    acl::check_bucket_access(&node.client, &agent_pk, &bucket, Action::Read)
        .expect("reissued admin-signed grant grants access under strict");
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

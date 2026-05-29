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

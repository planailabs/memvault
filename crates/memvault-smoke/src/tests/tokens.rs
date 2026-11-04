//! Token issuance and revocation smoke tests.

use memvault_api::MemvaultClient;
use memvault_auth::{AgentRole, TokenRole};

use crate::harness::TestNode;

#[tokio::test]
async fn issue_token() {
    let node = TestNode::new();
    let token = node
        .client
        .issue_token(
            TokenRole::Agent(AgentRole::AgentHost),
            3600,
            1,
            Some("test".into()),
        )
        .await
        .unwrap();
    assert!(token.starts_with("mvjoin1:"));
}

#[tokio::test]
async fn issue_token_different_roles() {
    let node = TestNode::new();
    for role in [
        TokenRole::Agent(AgentRole::Admin),
        TokenRole::Agent(AgentRole::AgentHost),
        TokenRole::Agent(AgentRole::Auditor),
        TokenRole::Agent(AgentRole::Service),
    ] {
        let token = node.client.issue_token(role, 3600, 1, None).await.unwrap();
        assert!(token.starts_with("mvjoin1:"));
    }
    assert_eq!(node.client.list_tokens().await.unwrap().len(), 4);
}

#[tokio::test]
async fn list_tokens() {
    let node = TestNode::new();
    node.client
        .issue_token(
            TokenRole::Agent(AgentRole::AgentHost),
            3600,
            1,
            Some("first".into()),
        )
        .await
        .unwrap();
    node.client
        .issue_token(
            TokenRole::Agent(AgentRole::AgentHost),
            7200,
            5,
            Some("second".into()),
        )
        .await
        .unwrap();
    let tokens = node.client.list_tokens().await.unwrap();
    assert_eq!(tokens.len(), 2);
}

#[tokio::test]
async fn revoke_token() {
    let node = TestNode::new();
    node.client
        .issue_token(
            TokenRole::Agent(AgentRole::AgentHost),
            3600,
            1,
            Some("revocable".into()),
        )
        .await
        .unwrap();
    let tokens = node.client.list_tokens().await.unwrap();
    let cid = tokens[0].cid.clone();
    node.client
        .revoke_token(&cid, "no longer needed")
        .await
        .unwrap();
    let tokens = node.client.list_tokens().await.unwrap();
    assert!(tokens[0].revoked);
}

#[tokio::test]
async fn token_with_max_uses() {
    let node = TestNode::new();
    node.client
        .issue_token(
            TokenRole::Agent(AgentRole::AgentHost),
            3600,
            10,
            Some("multi".into()),
        )
        .await
        .unwrap();
    let tokens = node.client.list_tokens().await.unwrap();
    assert_eq!(tokens[0].max_uses, 10);
    assert_eq!(tokens[0].consumed_count, 0);
}

#[tokio::test]
async fn token_decode_roundtrip() {
    let node = TestNode::new();
    let encoded = node
        .client
        .issue_token(
            TokenRole::Agent(AgentRole::AgentHost),
            3600,
            1,
            Some("roundtrip".into()),
        )
        .await
        .unwrap();
    let decoded = memvault_auth::decode_token_string(&encoded).unwrap();
    assert_eq!(decoded.role, TokenRole::Agent(AgentRole::AgentHost));
    assert_eq!(decoded.label, Some("roundtrip".to_string()));
    assert_eq!(decoded.max_uses, 1);
}

#[tokio::test]
async fn issued_token_tolerates_reader_clock_skew() {
    let node = TestNode::new();
    let issued_after_ns = memvault_core::wall_ns();
    let encoded = node
        .client
        .issue_token(
            TokenRole::Agent(AgentRole::AgentHost),
            3600,
            1,
            Some("skew".into()),
        )
        .await
        .unwrap();
    let decoded = memvault_auth::decode_token_string(&encoded).unwrap();

    decoded
        .verify_time_bounds(issued_after_ns.saturating_sub(60_000_000_000))
        .unwrap();
}

/// A node that never founded or joined a cluster: no admin key, the all-zero
/// cluster id, only its own node key.
fn unclustered(cluster_id: [u8; 32]) -> (tempfile::TempDir, std::sync::Arc<memvault_api::LocalClient>) {
    use std::sync::Arc;
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(memvault_store::MemvaultStore::open(dir.path().join("blocks.redb")).unwrap());
    let node_sk = ed25519_dalek::SigningKey::from_bytes(&[0x42; 32]);
    let client = Arc::new(memvault_api::LocalClient::new(
        store,
        Arc::new(tokio::sync::RwLock::new(memvault_query::QuotaManager::default())),
        Arc::new(memvault_api::EventBus::new(64)),
        node_sk.verifying_key().to_bytes().to_vec(),
        cluster_id.to_vec(),
    ));
    client.set_node_signing_key(node_sk);
    (dir, client)
}

#[tokio::test]
async fn a_node_in_no_cluster_issues_and_redeems_agent_tokens() {
    let (_dir, client) = unclustered([0; 32]);
    let trust = memvault_api::bootstrap::bootstrap_cluster_trust(&client).unwrap();
    assert!(trust.admin_pubkey.is_none(), "pre-genesis");

    for role in [AgentRole::AgentHost, AgentRole::Auditor, AgentRole::Service] {
        let token = client
            .issue_token(TokenRole::Agent(role), 3600, 1, None)
            .await
            .unwrap();
        let agent_pk = ed25519_dalek::SigningKey::from_bytes(&[role as u8 + 1; 32])
            .verifying_key()
            .to_bytes();
        let enrolled = memvault_api::agent_identity::enroll_remote_agent(
            &client, &token, "agent", agent_pk, u64::MAX,
        )
        .unwrap();
        assert_eq!(enrolled.attestation.role, role);
    }
    assert_eq!(client.list_tokens().await.unwrap().len(), 3);
}

#[tokio::test]
async fn node_and_admin_tokens_still_need_a_cluster() {
    let (_dir, client) = unclustered([0; 32]);
    for role in [
        TokenRole::Agent(AgentRole::Admin),
        TokenRole::Node(memvault_auth::NodeRole::Node),
        TokenRole::Node(memvault_auth::NodeRole::Admin),
    ] {
        let err = client.issue_token(role, 3600, 1, None).await.unwrap_err();
        assert!(err.to_string().contains("need a cluster"), "{role:?}: {err}");
    }
}

#[tokio::test]
async fn a_node_that_joined_a_cluster_does_not_sign_its_own_tokens() {
    // Joined: a real cluster id, but the admin key is the cluster's, not ours.
    let (_dir, client) = unclustered([7; 32]);
    let err = client
        .issue_token(TokenRole::Agent(AgentRole::AgentHost), 3600, 1, None)
        .await
        .unwrap_err();
    assert!(err.to_string().contains("no admin signing key"), "{err}");
}

#[tokio::test]
async fn an_unclustered_token_is_redeemed_only_by_the_node_that_signed_it() {
    let (_a, issuer) = unclustered([0; 32]);
    let token = issuer
        .issue_token(TokenRole::Agent(AgentRole::AgentHost), 3600, 1, None)
        .await
        .unwrap();
    // Another node in no cluster, with a different key.
    let dir = tempfile::tempdir().unwrap();
    let store = std::sync::Arc::new(
        memvault_store::MemvaultStore::open(dir.path().join("blocks.redb")).unwrap(),
    );
    let other = memvault_api::LocalClient::new(
        store,
        std::sync::Arc::new(tokio::sync::RwLock::new(memvault_query::QuotaManager::default())),
        std::sync::Arc::new(memvault_api::EventBus::new(64)),
        vec![9; 32],
        vec![0; 32],
    );
    other.set_node_signing_key(ed25519_dalek::SigningKey::from_bytes(&[0x43; 32]));
    let err = memvault_api::agent_identity::enroll_remote_agent(
        &other, &token, "agent", [5; 32], u64::MAX,
    )
    .unwrap_err();
    assert!(err.to_string().contains("this node's key"), "{err}");
}

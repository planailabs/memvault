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

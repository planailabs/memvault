//! Renamable agent display labels (`Op::AgentRename` / `LocalClient::agent_rename`).
//!
//! The label is display-only: it is set via a node-signed sigchain block,
//! honoured only when authored by the agent's attesting node, latest-by-wall_ns
//! wins, and it never participates in access control (which keys on the pubkey).

use ed25519_dalek::SigningKey;
use rand::RngCore;

use memvault_api::MemvaultClient;
use memvault_api::{acl, sigchain};
use memvault_auth::{Action, AgentRole, GrantAudience, sign_agent_attestation};
use memvault_core::{AgentName, Visibility};

use crate::harness::TestNode;

/// Mint + publish an attestation for a fresh agent on this node (the node
/// becomes the agent's attesting node, i.e. its rename authority). Returns the
/// agent pubkey.
async fn setup_agent(node: &TestNode, agent_name: &str) -> [u8; 32] {
    let node_sk = node.client.node_signing_key().expect("node key").clone();
    let mut seed = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut seed);
    let agent_pk = SigningKey::from_bytes(&seed).verifying_key().to_bytes();
    let att = sign_agent_attestation(
        &node_sk,
        AgentName(agent_name.to_string()),
        agent_pk,
        AgentRole::AgentHost,
        u64::MAX,
    )
    .expect("sign attestation");
    sigchain::publish_agent_attestation(&node.client, &att).expect("publish attestation");
    agent_pk
}

#[tokio::test]
async fn agent_rename_sets_label() {
    let node = TestNode::new();
    let pk = setup_agent(&node, "robot-7").await;

    assert_eq!(
        sigchain::agent_label(&node.client, &pk).expect("label lookup"),
        None,
        "no label before rename"
    );

    node.client
        .agent_rename(&pk, "Alice")
        .await
        .expect("rename");

    assert_eq!(
        sigchain::agent_label(&node.client, &pk).expect("label lookup"),
        Some("Alice".to_string()),
    );
}

#[tokio::test]
async fn agent_rename_latest_wins() {
    let node = TestNode::new();
    let pk = setup_agent(&node, "robot-7").await;

    node.client.agent_rename(&pk, "first").await.expect("r1");
    node.client.agent_rename(&pk, "second").await.expect("r2");

    assert_eq!(
        sigchain::agent_label(&node.client, &pk).expect("label lookup"),
        Some("second".to_string()),
        "the later relabel (higher wall_ns) must win",
    );
}

#[tokio::test]
async fn agent_rename_does_not_affect_access() {
    let node = TestNode::new();
    let pk = setup_agent(&node, "robot-7").await;

    let bucket = node
        .client
        .bucket_create(
            "renamed-agent-bucket",
            None,
            Visibility::Internal,
            memvault_core::classification::Classification::Internal,
            memvault_doc::BucketRole::Standard,
        )
        .await
        .expect("bucket");
    node.client
        .issue_bucket_grant(
            &bucket,
            GrantAudience::AgentKey(pk),
            vec![Action::Read],
            u64::MAX,
        )
        .await
        .expect("grant");

    acl::check_bucket_access(&node.client, &pk, &bucket, Action::Read)
        .expect("access before rename");
    node.client
        .agent_rename(&pk, "Renamed")
        .await
        .expect("rename");
    acl::check_bucket_access(&node.client, &pk, &bucket, Action::Read)
        .expect("access must be unchanged by a label rename");
}

#[tokio::test]
async fn agent_rename_errors_when_node_is_not_attester() {
    let node = TestNode::new();
    // A pubkey this node never attested: it has no authority to relabel it, so
    // the rename must fail loudly instead of writing a silently-ignored block.
    let mut seed = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut seed);
    let stranger = SigningKey::from_bytes(&seed).verifying_key().to_bytes();

    let err = node
        .client
        .agent_rename(&stranger, "nope")
        .await
        .expect_err("relabel of a non-attested agent must error");
    assert!(
        matches!(err, memvault_api::ApiError::Forbidden(_)),
        "expected Forbidden, got {err:?}"
    );
    // And no label leaked through.
    assert_eq!(
        sigchain::agent_label(&node.client, &stranger).expect("label lookup"),
        None,
    );
}

#[tokio::test]
async fn agent_rename_from_untrusted_signer_ignored() {
    let node = TestNode::new();
    let pk = setup_agent(&node, "robot-7").await;

    // Forge an agent-rename block signed by a random key (NOT the agent's
    // attesting node) and inject it directly into the store, exactly as a
    // malicious synced block would arrive.
    let mut seed = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut seed);
    let forger = SigningKey::from_bytes(&seed);
    let forger_pub = forger.verifying_key().to_bytes();

    let payload = serde_json::json!({
        "AgentRename": {
            "agent_pubkey": pk.to_vec(),
            "new_label": "PWNED",
            "wall_ns": memvault_core::wall_ns(),
        }
    });
    let signed = memvault_core::Signed::sign(
        payload,
        &forger,
        memvault_core::PeerId(forger_pub.to_vec()),
        vec![], // causal
        vec![], // provenance
        vec![], // tags
        Visibility::Internal,
        0, // lamport
        memvault_core::wall_ns(),
        None, // capability
        None, // bucket_id
        None, // node_attestation
        None, // agent_attestation
        None, // agent_signing_key
    )
    .expect("sign forged envelope");
    let bytes = serde_ipld_dagcbor::to_vec(&signed).expect("encode");
    let cid = memvault_core::cid_from_bytes(&bytes);
    node.client
        .store()
        .insert_envelope(
            &cid.to_bytes(),
            &bytes,
            &memvault_store::insert::EnvelopeMeta {
                author: forger_pub.to_vec(),
                tags: vec![
                    ("kind".to_string(), "agent-rename".to_string()),
                    ("agent".to_string(), hex::encode(pk)),
                ],
                wall_ns: memvault_core::wall_ns(),
                ..Default::default()
            },
        )
        .expect("inject forged block");

    // The forged relabel must be ignored — only the attesting node may relabel.
    assert_eq!(
        sigchain::agent_label(&node.client, &pk).expect("label lookup"),
        None,
        "a relabel from a non-attesting signer must not take effect",
    );
}

//! Agent enrollment end-to-end: issue token → enroll agent → write a doc →
//! verify the authorship sidecar chains back to the agent.
//!
//! This is the cryptographic equivalent of `memctl token-issue` followed
//! by `memctl agent-enroll`, with `memctl put` to exercise the
//! agent-attributed write path.

use std::collections::BTreeMap;

use ed25519_dalek::SigningKey;
use rand::RngCore;
use tempfile::tempdir;

use memvault_api::MemvaultClient;
use memvault_api::agent_identity::AgentIdentity;
use memvault_api::sigchain;
use memvault_auth::{AgentRole, TokenRole, decode_token_string};
use memvault_core::{DocId, Visibility};
use memvault_doc::Document;

use crate::harness::TestNode;

#[tokio::test]
async fn enroll_agent_then_write_and_verify_authorship() {
    let node = TestNode::new();

    // ── 1. Wire the node signing key + bootstrap cluster trust ─────
    // The harness only sets `admin_signing_key`. For agent attestation
    // we need a separate node signing key. In production these may be
    // the same key on a single-admin cluster; here we generate a fresh
    // one to exercise the two-key path.
    let mut node_seed = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut node_seed);
    let node_sk = SigningKey::from_bytes(&node_seed);
    node.client.set_node_signing_key(node_sk.clone());

    let client_arc = std::sync::Arc::new({
        // The harness owns `client` by value; we need an Arc for
        // bootstrap_cluster_trust. Copy the necessary handles.
        let c = memvault_api::LocalClient::new(
            std::sync::Arc::clone(&node.store),
            std::sync::Arc::new(tokio::sync::RwLock::new(
                memvault_query::TextIndex::new(),
            )),
            std::sync::Arc::new(tokio::sync::RwLock::new(
                memvault_query::QuotaManager::default(),
            )),
            std::sync::Arc::new(memvault_api::EventBus::new(64)),
            node.client.peer_id().to_vec(),
            node.cluster_id.0.to_vec(),
        );
        c.set_admin_signing_key(
            node.client.admin_signing_key().unwrap().clone(),
        );
        c.set_node_signing_key(node_sk.clone());
        c
    });
    // Production: `memctl genesis` writes the AdminGenesis pin to disk;
    // the daemon loads it and calls `set_pinned_admin_genesis` before
    // bootstrap. The smoke test does the in-memory equivalent so
    // `issue_token` embeds the genesis block.
    let admin_sk = node.client.admin_signing_key().unwrap().clone();
    let now_ns = memvault_core::wall_ns();
    let pin = memvault_auth::sign_admin_genesis(&admin_sk, node.cluster_id.clone(), now_ns)
        .expect("sign admin_genesis");
    client_arc.set_pinned_admin_genesis(pin);

    let trust = memvault_api::bootstrap::bootstrap_cluster_trust(&client_arc)
        .expect("bootstrap cluster trust");
    assert!(
        trust.admin_pubkey.is_some(),
        "admin pubkey must be set after bootstrap with admin signing key"
    );

    // ── 2. Issue a join token (the `memctl token-issue` path) ──────
    let token_str = client_arc
        .issue_token(TokenRole::Agent(AgentRole::AgentHost), 3600, 1, Some("test-agent".into()))
        .await
        .unwrap();
    assert!(token_str.starts_with("mvjoin1:"));

    let token = decode_token_string(&token_str).expect("decode token");
    assert_eq!(token.role, TokenRole::Agent(AgentRole::AgentHost));
    assert_eq!(token.cluster_id.0, node.cluster_id.0);
    // Token should carry the AdminGenesis (so a joining peer can pin).
    assert!(
        token.admin_genesis.is_some(),
        "token must embed AdminGenesis for a real cluster"
    );

    // ── 3. Enroll the agent locally (the `memctl agent-enroll` path) ──
    let agent_dir = tempdir().expect("agent identity dir");
    let (agent, attestation) = AgentIdentity::generate_local(
        agent_dir.path(),
        "test-agent",
        &node.cluster_id,
        &node_sk,
        AgentRole::AgentHost,
        365 * 24 * 60 * 60 * 1_000_000_000,
    )
    .expect("generate agent identity");
    assert_eq!(attestation.role, AgentRole::AgentHost);
    assert_eq!(
        attestation.node_pubkey,
        node_sk.verifying_key().to_bytes(),
        "agent attestation must be signed by the node we asked"
    );
    attestation
        .verify_signature()
        .expect("agent attestation signature verifies");

    // Publish the agent attestation to the local sigchain so peers (and
    // the local verifier) can reach it. Capture the CID so we can hand
    // it to the agent-bound LocalClient below — AgentIdentity no
    // longer carries the CID after the disk-state slimdown, and the
    // cache is per-LocalClient.
    let attestation_cid =
        sigchain::publish_agent_attestation(&client_arc, &attestation)
            .expect("publish agent attestation");

    // ── 4. Bind agent to a writing client + put a bucket and a doc ──
    // We need an agent-bound client to author writes. Build one off the
    // same store / handles.
    let agent_pk_bytes = agent.verifying_key.to_bytes();
    let agent_client = memvault_api::LocalClient::new(
        std::sync::Arc::clone(&node.store),
        std::sync::Arc::new(tokio::sync::RwLock::new(memvault_query::TextIndex::new())),
        std::sync::Arc::new(tokio::sync::RwLock::new(memvault_query::QuotaManager::default())),
        std::sync::Arc::new(memvault_api::EventBus::new(64)),
        node.client.peer_id().to_vec(),
        node.cluster_id.0.to_vec(),
    );
    // Install the node signing key so writes flow through Signed<T> —
    // without it, `build_signed_envelope` falls back to the unsigned
    // raw-JSON envelope shape and the assertions below fail.
    agent_client.set_node_signing_key(node_sk.clone());
    agent_client.set_agent_identity(agent);
    agent_client.set_agent_attestation_cid(attestation_cid);

    // Need a bucket — agent-attributed writes go through the bucket gate.
    let bucket = agent_client
        .bucket_create(
            "agent-test",
            None,
            Visibility::Internal,
            memvault_core::classification::Classification::Internal,
            memvault_doc::BucketRole::Standard,
        )
        .await
        .expect("bucket create");

    let doc = Document::new(
        DocId::random(),
        "Hello from the enrolled agent.".to_string(),
        BTreeMap::new(),
    );
    let doc_id = doc.id.clone();
    let cid = agent_client
        .put_doc(
            doc,
            vec![("kind".into(), "note".into())],
            Visibility::Internal,
            Some(&bucket),
        )
        .await
        .expect("agent put_doc");

    // ── 5. Verify agent attribution travels inline on the Signed<T> envelope
    //       (post-EnvelopeAuthorship-sidecar removal). ────────────────
    let env_bytes = client_arc
        .store()
        .get_block(&cid)
        .expect("get envelope block")
        .expect("envelope block present");
    let signed: memvault_core::Signed<serde_json::Value> =
        serde_ipld_dagcbor::from_slice(&env_bytes).expect("envelope decodes as Signed");
    assert!(
        signed.agent_attestation.is_some(),
        "agent-bound write must carry agent_attestation cid on the envelope"
    );
    assert!(
        !signed.agent_signature.is_empty(),
        "agent-bound write must carry agent co-signature"
    );

    // The agent must be in our trusted-agents cache (chain: admin →
    // node → agent, none revoked).
    let trusted = trust
        .trust_state
        .trusted_agents
        .read()
        .map(|s| s.clone())
        .unwrap_or_default();
    // The cache was computed BEFORE we published the agent attestation.
    // Refresh: scan again now that the attestation is on the chain.
    let nt = trust
        .trust_state
        .node_trust
        .read()
        .map(|m| m.clone())
        .unwrap_or_default();
    let revoked = trust
        .trust_state
        .revoked_agents
        .read()
        .map(|s| s.clone())
        .unwrap_or_default();
    let fresh =
        sigchain::scan_trusted_agents(&client_arc, &nt, &revoked).expect("scan trusted agents");
    assert!(
        fresh.contains(&agent_pk_bytes),
        "agent should be in trusted_agents after attestation is published; \
         pre-publish set was {trusted:?}"
    );

    // Round-trip: the doc is retrievable.
    let got = client_arc.get_doc(&doc_id).await.unwrap();
    assert!(got.is_some(), "doc retrievable by id after agent write");
}

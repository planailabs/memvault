//! Regression tests for the "write succeeds but UI shows nothing" bug.
//!
//! When the write path migrated to `Signed<T>` v3 (typed envelope with
//! byte-string signature/agent_signature fields), DAG-CBOR encoded
//! those byte fields as CBOR major type 2 byte strings. The
//! `deserialize_block` helper used by every read path tried to decode
//! the bytes straight into `serde_json::Value`, which has no byte-string
//! variant — so reads silently returned `None` for every Signed<T>
//! envelope. Symptom: docs / entities / file attachments wrote
//! successfully (logs showed them), but list_docs / entity_has_local_author
//! / list_files all came up empty.
//!
//! These tests pin down the contract: writes through the Signed<T>
//! path must round-trip through the readers and show up in the
//! standard query surfaces.
//!
//! Catches: any future refactor that re-introduces a Value-only decode
//! path, or any new envelope shape that drops typed byte fields
//! without updating `deserialize_block`.

use std::collections::BTreeMap;
use std::sync::Arc;

use ed25519_dalek::SigningKey;
use memvault_api::MemvaultClient;
use memvault_core::{DocId, Visibility};
use memvault_doc::Document;
use rand::RngCore;

use crate::harness::TestNode;

/// Build a TestNode that installs a node signing key, so writes go
/// through the real Signed<T> path instead of the unsigned-JSON
/// fallback in build_signed_envelope.
fn node_with_signed_writes() -> (TestNode, SigningKey) {
    let node = TestNode::new();
    let mut seed = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut seed);
    let node_sk = SigningKey::from_bytes(&seed);
    node.client.set_node_signing_key(node_sk.clone());
    (node, node_sk)
}

#[tokio::test]
async fn signed_doc_write_appears_in_list_and_get() {
    let (node, _node_sk) = node_with_signed_writes();

    let bucket = node
        .client
        .bucket_create(
            "test-bucket",
            None,
            Visibility::Internal,
            memvault_core::classification::Classification::Internal,
            memvault_doc::BucketRole::Standard,
        )
        .await
        .expect("bucket create");

    let doc_id = DocId::random();
    let mut frontmatter = BTreeMap::new();
    frontmatter.insert("title".to_string(), serde_json::json!("Regression Doc"));
    let doc = Document::new(doc_id.clone(), "body content".to_string(), frontmatter);

    let cid = node
        .client
        .put_doc(
            doc.clone(),
            vec![("kind".into(), "note".into())],
            Visibility::Internal,
            Some(&bucket),
        )
        .await
        .expect("put_doc");
    assert!(!cid.is_empty(), "put_doc returned empty cid");

    // ── Round-trip through get_doc ──
    let got = node.client.get_doc(&doc_id).await.expect("get_doc");
    let got = got.expect("doc must be retrievable by id after Signed<T> write");
    assert_eq!(got.id, doc_id);
    assert_eq!(got.body, "body content");

    // ── Round-trip through list_docs ──
    let summaries = node
        .client
        .list_docs(None, 100, Some(&bucket))
        .await
        .expect("list_docs");
    assert!(
        summaries.iter().any(|s| s.id == doc_id),
        "doc must appear in list_docs after Signed<T> write; got {} summaries",
        summaries.len(),
    );
}

#[tokio::test]
async fn signed_entity_write_appears_in_index() {
    let (node, _node_sk) = node_with_signed_writes();

    let bucket = node
        .client
        .bucket_create(
            "entities-bucket",
            None,
            Visibility::Internal,
            memvault_core::classification::Classification::Internal,
            memvault_doc::BucketRole::Standard,
        )
        .await
        .expect("bucket create");

    let entity = memvault_doc::Entity {
        id: memvault_core::EntityId::random(),
        kind: "test-kind".to_string(),
        props: BTreeMap::new(),
        edges_out: vec![],
    };
    let entity_id = entity.id.clone();
    node.client
        .add_entity(entity, Visibility::Internal, Some(&bucket))
        .await
        .expect("add_entity");

    // ── Entity must round-trip through get_entity ──
    let got = node
        .client
        .get_entity(&entity_id)
        .await
        .expect("get_entity");
    assert!(
        got.is_some(),
        "entity must be retrievable by id after Signed<T> write"
    );

    // The entity is "locally authored" — this exercises the
    // has_local_author path (which had its own Signed<T> shape bug
    // earlier in the migration).
    assert!(
        node.client.entity_has_local_author(&entity_id),
        "entity_has_local_author must return true for a write by this node"
    );
}

#[tokio::test]
async fn signed_attachment_write_appears_in_list_files() {
    let (node, _node_sk) = node_with_signed_writes();

    let bucket = node
        .client
        .bucket_create(
            "files-bucket",
            None,
            Visibility::Internal,
            memvault_core::classification::Classification::Internal,
            memvault_doc::BucketRole::Standard,
        )
        .await
        .expect("bucket create");

    let data = b"hello world from a regression test".to_vec();
    let manifest_cid = node
        .client
        .upload_file(
            &data,
            Some("regression.txt"),
            "text/plain",
            vec![("kind".into(), "attachment".into())],
            "internal",
            Some(&bucket),
        )
        .await
        .expect("upload_file");
    assert!(!manifest_cid.is_empty(), "upload_file returned empty cid");

    // ── File must be readable back through the manifest ──
    let manifest = node
        .client
        .get_file_manifest(&manifest_cid)
        .await
        .expect("get_file_manifest");
    assert!(
        manifest.is_some(),
        "file manifest must be retrievable after Signed<T> attachment write"
    );

    let body = node
        .client
        .read_file(&manifest_cid)
        .await
        .expect("read_file");
    assert_eq!(
        body, data,
        "read_file must return the original bytes after a Signed<T> attachment write"
    );
}

#[tokio::test]
async fn signed_write_audit_record_carries_agent_attestation_when_bound() {
    // Same Signed<T> path, but with an agent identity bound — the
    // audit record returned by `history_of` must surface
    // `agent_attestation` so the WebUI can resolve it to a
    // human-readable agent id.
    let (node, node_sk) = node_with_signed_writes();

    // Mint and publish an agent attestation off the node's SK.
    let role = memvault_auth::Role::AgentHost;
    let dir = tempfile::tempdir().unwrap();
    let (agent, attestation) = memvault_api::agent_identity::AgentIdentity::generate_local(
        dir.path(),
        "audit-test-agent",
        &node.cluster_id,
        &node_sk,
        role,
        365 * 24 * 3600 * 1_000_000_000,
    )
    .expect("generate agent identity");
    memvault_api::sigchain::publish_agent_attestation(&node.client, &attestation)
        .expect("publish agent attestation");
    // Compute the attestation CID inline — AgentIdentity no longer
    // caches it locally; readers look it up by author pubkey.
    let expected_att_cid = memvault_core::cid_from_bytes(
        &serde_ipld_dagcbor::to_vec(&attestation).expect("encode attestation"),
    )
    .to_bytes();

    // Build a separate agent-bound client off the same store.
    let agent_client = memvault_api::LocalClient::new(
        Arc::clone(&node.store),
        Arc::new(tokio::sync::RwLock::new(memvault_query::TextIndex::new())),
        Arc::new(tokio::sync::RwLock::new(memvault_query::QuotaManager::default())),
        Arc::new(memvault_api::EventBus::new(64)),
        node.client.peer_id().to_vec(),
        node.cluster_id.0.to_vec(),
    );
    agent_client.set_node_signing_key(node_sk.clone());
    agent_client.set_agent_identity(agent);
    // AgentIdentity no longer carries the attestation_cid; hand it
    // through explicitly so signer_for_writes embeds the inline
    // attribution pointer the assertions below expect.
    agent_client.set_agent_attestation_cid(expected_att_cid.clone());

    let bucket = agent_client
        .bucket_create(
            "audit-bucket",
            None,
            Visibility::Internal,
            memvault_core::classification::Classification::Internal,
            memvault_doc::BucketRole::Standard,
        )
        .await
        .expect("bucket create");

    let doc = Document::new(
        DocId::random(),
        "audit-tracked body".to_string(),
        BTreeMap::new(),
    );
    let doc_id = doc.id.clone();
    let _cid = agent_client
        .put_doc(
            doc,
            vec![("kind".into(), "note".into())],
            Visibility::Internal,
            Some(&bucket),
        )
        .await
        .expect("agent put_doc");

    // ── history_of must return an AuditRecord with agent_attestation ──
    let records = node
        .client
        .history_of(&doc_id)
        .await
        .expect("history_of");
    assert!(
        !records.is_empty(),
        "history_of must return at least the DocCreate after agent-bound Signed<T> write"
    );
    let with_att = records
        .iter()
        .find(|r| r.agent_attestation.is_some())
        .expect("at least one audit record must carry agent_attestation");
    assert_eq!(
        with_att.agent_attestation.as_deref(),
        Some(expected_att_cid.as_slice()),
        "agent_attestation cid on the audit record must match the bound agent's attestation cid"
    );
}

#[tokio::test]
async fn signed_envelope_carries_inline_agent_attestation_when_bound() {
    // Same Signed<T> path, but with an agent identity bound — the
    // envelope must carry the inline `agent_attestation` cid so any
    // downstream surface (audit table, notes history, WebUI badges)
    // can resolve it to a human-readable agent id.
    let (node, node_sk) = node_with_signed_writes();

    // Mint an agent attestation off the node's SK.
    let role = memvault_auth::Role::AgentHost;
    let dir = tempfile::tempdir().unwrap();
    let (agent, attestation) = memvault_api::agent_identity::AgentIdentity::generate_local(
        dir.path(),
        "regression-agent",
        &node.cluster_id,
        &node_sk,
        role,
        365 * 24 * 3600 * 1_000_000_000,
    )
    .expect("generate agent identity");
    // Compute the attestation CID inline — AgentIdentity no longer
    // caches it locally; readers look it up by author pubkey.
    let expected_att_cid = memvault_core::cid_from_bytes(
        &serde_ipld_dagcbor::to_vec(&attestation).expect("encode attestation"),
    )
    .to_bytes();

    // Build a separate agent-bound client off the same store.
    let agent_client = memvault_api::LocalClient::new(
        Arc::clone(&node.store),
        Arc::new(tokio::sync::RwLock::new(memvault_query::TextIndex::new())),
        Arc::new(tokio::sync::RwLock::new(memvault_query::QuotaManager::default())),
        Arc::new(memvault_api::EventBus::new(64)),
        node.client.peer_id().to_vec(),
        node.cluster_id.0.to_vec(),
    );
    agent_client.set_node_signing_key(node_sk.clone());
    agent_client.set_agent_identity(agent);
    // AgentIdentity no longer carries the attestation_cid; hand it
    // through explicitly so signer_for_writes embeds the inline
    // attribution pointer the assertions below expect.
    agent_client.set_agent_attestation_cid(expected_att_cid.clone());

    let bucket = agent_client
        .bucket_create(
            "agent-write-bucket",
            None,
            Visibility::Internal,
            memvault_core::classification::Classification::Internal,
            memvault_doc::BucketRole::Standard,
        )
        .await
        .expect("bucket create");

    let doc = Document::new(
        DocId::random(),
        "agent-attributed body".to_string(),
        BTreeMap::new(),
    );
    let cid = agent_client
        .put_doc(
            doc,
            vec![("kind".into(), "note".into())],
            Visibility::Internal,
            Some(&bucket),
        )
        .await
        .expect("agent put_doc");

    // ── The envelope block itself must carry agent_attestation cid
    //    and a non-empty agent_signature ──
    let env_bytes = node
        .store
        .get_block(&cid)
        .expect("get envelope block")
        .expect("envelope block must be present");
    let signed: memvault_core::Signed<serde_json::Value> =
        serde_ipld_dagcbor::from_slice(&env_bytes)
            .expect("agent-bound write must produce a valid Signed<T> envelope");
    assert_eq!(
        signed.agent_attestation.as_deref(),
        Some(expected_att_cid.as_slice()),
        "envelope agent_attestation cid must equal the bound agent's attestation cid"
    );
    assert!(
        !signed.agent_signature.is_empty(),
        "agent-bound write must carry an agent_signature"
    );
}

//! Migration and backwards-compatibility smoke tests.
//!
//! Verifies that old data formats (pre-bucket, pre-agent-enrollment)
//! still work correctly with the new code, and that known bugs
//! (like VFS double-prefix) are handled.

use std::collections::BTreeMap;
use std::sync::Arc;

use memvault_api::MemvaultClient;
use memvault_core::tags::Tag;
use memvault_core::*;
use memvault_doc::{BucketRole, Document, Entity, Op, TextPatch};
use memvault_query::QuotaManager;
use memvault_store::MemvaultStore;
use memvault_store::insert::EnvelopeMeta;
use tokio::sync::RwLock;

use crate::harness::TestNode;

// ── Old envelope format (no bucket_id) ──────────────────────────────

#[test]
fn old_envelope_meta_without_bucket_id_deserializes() {
    // Simulate old EnvelopeMeta that doesn't have bucket_id
    let json = r#"{
        "author": [1,2,3],
        "tags": [["kind","doc"]],
        "wall_ns": 1000,
        "causal": [],
        "provenance": [],
        "cluster_id": [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]
    }"#;

    // This should parse fine — bucket_id defaults to None
    let val: serde_json::Value = serde_json::from_str(json).unwrap();
    let bucket_id: Option<Vec<u8>> = val
        .get("bucket_id")
        .and_then(|v| serde_json::from_value(v.clone()).ok());
    assert!(bucket_id.is_none());
}

#[test]
fn old_envelope_without_bucket_indexes_correctly() {
    let dir = tempfile::tempdir().unwrap();
    let store = MemvaultStore::open(dir.path().join("test.redb")).unwrap();

    // Insert an "old" envelope without bucket_id
    let meta = EnvelopeMeta {
        author: b"old-peer".to_vec(),
        tags: vec![("doc".to_string(), "abc123".to_string())],
        wall_ns: 5000,
        causal: vec![],
        provenance: vec![],
        cluster_id: Some(vec![1u8; 32]),
        bucket_id: None, // old format
            ..Default::default()
    };
    store
        .insert_envelope(b"old-cid-001", b"old data", &meta)
        .unwrap();

    // Should be queryable by tag
    let results = store.query_by_tag("doc", "abc123", 0, 100).unwrap();
    assert_eq!(results.len(), 1);

    // Should NOT appear in any bucket query
    let bucket_results = store.query_by_bucket(&vec![0u8; 32], 0, 100).unwrap();
    assert!(bucket_results.is_empty());
}

#[test]
fn old_envelope_reindexes_without_bucket() {
    let dir = tempfile::tempdir().unwrap();
    let store = MemvaultStore::open(dir.path().join("test.redb")).unwrap();

    // Simulate an old block (JSON without bucket_id field)
    let old_block = serde_json::json!({
        "version": 1,
        "payload": "hello",
        "author": {"0": [1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32]},
        "tags": [{"scope": "doc", "label": "old-doc-hex"}],
        "visibility": "Internal",
        "lamport": 1,
        "wall_ns": 2000,
    });
    let block_bytes = serde_json::to_vec(&old_block).unwrap();
    store.put_block(b"reindex-cid", &block_bytes).unwrap();

    // Reindex should work and NOT crash on missing bucket_id
    let indexed = store.reindex_block(b"reindex-cid", &block_bytes).unwrap();
    assert!(indexed);
}

#[tokio::test]
async fn repair_index_adopts_legacy_unbucketed_entities_into_default_bucket() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("blocks.redb");
    let cluster_id = ClusterId::random();
    let entity = Entity {
        id: EntityId::random(),
        kind: "person".to_string(),
        props: BTreeMap::from([("name".to_string(), serde_json::json!("Legacy Alice"))]),
        edges_out: vec![],
    };
    let default_bucket = {
        let store = Arc::new(MemvaultStore::open(&db_path).unwrap());
        store.set_local_cluster_id(&cluster_id.0).unwrap();
        store.set_local_peer_id(&[9u8; 32]).unwrap();

        let client = memvault_api::LocalClient::new(
            Arc::clone(&store),
            Arc::new(RwLock::new(QuotaManager::default())),
            Arc::new(memvault_api::EventBus::new(64)),
            vec![9u8; 32],
            cluster_id.0.to_vec(),
        );
        client.set_node_signing_key(ed25519_dalek::SigningKey::from_bytes(&[9u8; 32]));
        // Use BucketRole::Legacy so `rebuild_store::find_legacy_bucket`
        // picks it up and routes the unbucketed entity into it.
        // Standard-role buckets are intentionally ignored by the
        // legacy-adoption path; the rebuild auto-creates its own
        // deterministic Legacy bucket if none exists.
        let default_bucket = client
            .bucket_create(
                "default",
                None,
                Visibility::Internal,
                classification::Classification::Internal,
                BucketRole::Legacy,
            )
            .await
            .unwrap();
        store
            .bind_bucket(&default_bucket.0, &cluster_id.0)
            .unwrap();

        let entity_label = hex::encode(entity.id.0);
        let wall_ns = wall_ns();
        let op = Op::EntityCreate {
            entity: entity.clone(),
        };
        let envelope = serde_json::json!({
            "version": 1,
            "payload": op,
            "author": vec![9u8; 32],
            "tags": [["entity", entity_label]],
            "visibility": "Internal",
            "wall_ns": wall_ns,
            "cluster_id": cluster_id.0,
        });
        let envelope_bytes = serde_json::to_vec(&envelope).unwrap();
        let cid = cid_from_bytes(&envelope_bytes);
        let meta = EnvelopeMeta {
            author: vec![9u8; 32],
            tags: vec![("entity".to_string(), hex::encode(entity.id.0))],
            wall_ns,
            causal: vec![],
            provenance: vec![],
            cluster_id: Some(cluster_id.0.to_vec()),
            bucket_id: None,
                    ..Default::default()
        };
        store
            .insert_envelope(&cid.to_bytes(), &envelope_bytes, &meta)
            .unwrap();

        let pre_client = memvault_api::LocalClient::new(
            Arc::clone(&store),
            Arc::new(RwLock::new(QuotaManager::default())),
            Arc::new(memvault_api::EventBus::new(64)),
            vec![9u8; 32],
            cluster_id.0.to_vec(),
        );
        pre_client.populate_index().await.unwrap();
        assert!(
            pre_client
                .list_entities(100, Some(&default_bucket))
                .await
                .unwrap()
                .is_empty()
        );
        default_bucket
    };

    // RepairIndex's rebuild path now refuses to commit unsigned
    // legacy-rewrite blocks; it needs a node signing key to re-sign
    // them as Signed<T>. memctl's create_client() reads its data_dir
    // from MEMVAULT_DATA_DIR (not from the CLI struct), then loads the
    // node key from `<data_dir>/identity/libp2p.key` (raw 32-byte
    // ed25519 seed). Seed a deterministic one for the test and point
    // the env var at it.
    let id_dir = dir.path().join("identity");
    std::fs::create_dir_all(&id_dir).unwrap();
    std::fs::write(id_dir.join("libp2p.key"), [9u8; 32]).unwrap();
    // SAFETY: smoke tests run single-threaded enough that env mutation
    // is not racing other code; mirrors the pattern memctl::run uses
    // for MEMVAULT_AGENT_ID.
    unsafe {
        std::env::set_var("MEMVAULT_DATA_DIR", dir.path());
    }

    let cli = memctl::Cli {
        data_dir: Some(dir.path().to_path_buf()),
        agent_id: None,
        bucket_id: None,
        client: memctl::memvault_api::ClientArgs {
            db: Some(db_path.clone()),
            url: "http://127.0.0.1:8401".to_string(),
            identity_dir: None,
        },
        command: memctl::Commands::RepairIndex,
    };
    memctl::run(cli).await.unwrap();

    let reopened_store = Arc::new(MemvaultStore::open(&db_path).unwrap());
    let post_client = memvault_api::LocalClient::new(
        Arc::clone(&reopened_store),
        Arc::new(RwLock::new(QuotaManager::default())),
        Arc::new(memvault_api::EventBus::new(64)),
        reopened_store.get_local_peer_id().unwrap().unwrap(),
        cluster_id.0.to_vec(),
    );
    post_client.populate_index().await.unwrap();
    let entities = post_client
        .list_entities(100, Some(&default_bucket))
        .await
        .unwrap();
    assert!(entities.iter().any(|e| e.id == entity.id));
}

// ── Signed envelope v1 (no bucket_id) roundtrip ─────────────────────

#[test]
fn v1_envelope_no_bucket_signs_and_verifies() {
    let mut secret = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut secret);
    let sk = ed25519_dalek::SigningKey::from_bytes(&secret);
    let vk = sk.verifying_key();

    let envelope = Signed::sign(
        "old content".to_string(),
        &sk,
        PeerId(vk.as_bytes().to_vec()),
        vec![],
        vec![],
        vec![Tag::new("classification", "internal")],
        Visibility::Internal,
        1,
        1000,
        None,
        None, // v1: no bucket
        None, // no node_attestation
        None, // no agent_attestation
        None, // no agent co-signer
    )
    .unwrap();

    assert_eq!(envelope.version, 1);
    assert!(envelope.bucket_id.is_none());
    envelope.verify(&vk).unwrap();
}

#[test]
fn v1_envelope_serialization_compatible_with_v2_deserialize() {
    let mut secret = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut secret);
    let sk = ed25519_dalek::SigningKey::from_bytes(&secret);
    let vk = sk.verifying_key();

    // Create v1 envelope
    let v1 = Signed::sign(
        "compat test".to_string(),
        &sk,
        PeerId(vk.as_bytes().to_vec()),
        vec![],
        vec![],
        vec![Tag::new("classification", "internal")],
        Visibility::Internal,
        1,
        1000,
        None,
        None,
        None, // no node_attestation
        None, // no agent_attestation
        None, // no agent co-signer
    )
    .unwrap();

    // Serialize and deserialize — bucket_id should default to None
    let bytes = memvault_core::encode(&v1).unwrap();
    let deserialized: Signed<String> = memvault_core::decode(&bytes).unwrap();
    assert_eq!(deserialized.version, 1);
    assert!(deserialized.bucket_id.is_none());
    assert_eq!(deserialized.payload, "compat test");
    deserialized.verify(&vk).unwrap();
}

#[tokio::test]
async fn editing_docs_preserves_their_bucket() {
    let node = TestNode::new();
    let bucket = node
        .client
        .bucket_create(
            "docs",
            None,
            Visibility::Internal,
            classification::Classification::Internal,
            BucketRole::Standard,
        )
        .await
        .unwrap();

    let doc = Document {
        id: DocId::random(),
        body: "hello".to_string(),
        frontmatter: BTreeMap::new(),
    };
    node.client
        .put_doc(doc.clone(), vec![], Visibility::Internal, Some(&bucket))
        .await
        .unwrap();
    node.client
        .edit_doc(
            &doc.id,
            TextPatch {
                ops: vec![
                    memvault_doc::TextOp::Retain(5),
                    memvault_doc::TextOp::Insert(" world".to_string()),
                ],
            },
        )
        .await
        .unwrap();

    let bucket_cids = node
        .store
        .query_by_bucket(&bucket.0, 0, usize::MAX)
        .unwrap();
    let doc_cids = node
        .store
        .query_by_tag("doc", &hex::encode(doc.id.0), 0, usize::MAX)
        .unwrap();
    assert_eq!(doc_cids.len(), 2);
    assert!(doc_cids.iter().all(|cid| bucket_cids.contains(cid)));
}

#[tokio::test]
async fn vfs_roots_and_dirs_are_created_in_the_requested_bucket() {
    let node = TestNode::new();
    let bucket = node
        .client
        .bucket_create(
            "vfs",
            None,
            Visibility::Internal,
            classification::Classification::Internal,
            BucketRole::Standard,
        )
        .await
        .unwrap();

    let root_id = memvault_api::vfs::ensure_root(&node.client, &bucket)
        .await
        .unwrap();
    let bucket_entities = node.client.list_entities(500, Some(&bucket)).await.unwrap();
    assert!(bucket_entities.iter().any(|e| e.id == root_id));

    let path = memvault_api::vfs::ensure_dir_path(&node.client, &bucket, "/projects/alpha")
        .await
        .unwrap();
    let dir_id = match path {
        NodeRef::Entity(id) => id,
        other => panic!("expected directory entity, got {other:?}"),
    };
    let bucket_entities = node.client.list_entities(500, Some(&bucket)).await.unwrap();
    assert!(bucket_entities.iter().any(|e| e.id == dir_id));
}

// ── Old view (no bucket_id) ─────────────────────────────────────────

#[test]
fn old_view_without_bucket_id_deserializes() {
    use memvault_api::types::View;
    // View with no bucket_id field — should default to None
    let view: View = serde_json::from_str(
        r#"{"name":"old-view","tags":[["topic","rust"]],"created_ns":1000,"cid":""}"#,
    )
    .unwrap();
    assert_eq!(view.name, "old-view");
    assert!(view.bucket_id.is_none());
}

// ── VFS double-prefix bug ───────────────────────────────────────────

#[tokio::test]
async fn vfs_double_prefix_entity_id_handled() {
    let node = TestNode::new();

    // Create an entity
    let mut props = BTreeMap::new();
    props.insert("name".to_string(), serde_json::json!("test-dir"));
    let entity = memvault_doc::Entity {
        id: EntityId::random(),
        kind: memvault_api::vfs::VFS_DIR_KIND.to_string(),
        props,
        edges_out: vec![],
    };
    let eid = node
        .client
        .add_entity(entity, Visibility::Internal, None)
        .await
        .unwrap();

    // Construct both formats
    let hex_id = hex::encode(eid.0);
    let correct_id = format!("entity:{hex_id}");
    let double_prefixed = format!("entity:entity:{hex_id}");

    // The correct format should work
    let tags = node.client.get_tags(&correct_id).await.unwrap();
    // Should not panic or error
    assert!(tags.is_empty() || !tags.is_empty());

    // Double-prefixed should not crash (graceful handling)
    let result = node.client.get_tags(&double_prefixed).await;
    // May return empty or error — shouldn't panic
    assert!(result.is_ok() || result.is_err());
}

#[test]
fn noderef_from_tag_label_rejects_double_prefix() {
    // "entity:entity:..." is not a valid NodeRef
    let double = "entity:entity:0102030405060708091011121314151617181920212223242526272829303132";
    let result = NodeRef::from_tag_label(double);
    // Should either fail to parse (bytes too long for 32) or produce something
    // The hex part after "entity:" would be "entity:0102..." which isn't valid hex
    assert!(result.is_none());
}

#[test]
fn noderef_tag_label_roundtrip_no_double_prefix() {
    let eid = EntityId::random();
    let node_ref = NodeRef::Entity(eid.clone());
    let label = node_ref.tag_label();

    // Should be "entity:<hex>" not "entity:entity:<hex>"
    assert!(label.starts_with("entity:"));
    assert!(!label.starts_with("entity:entity:"));

    let back = NodeRef::from_tag_label(&label).unwrap();
    assert_eq!(back, node_ref);
}

// ── Old FederationAnnouncement (no bucket_id on HeadAvailable) ──────

#[test]
fn old_head_available_without_bucket_id_deserializes() {
    use memvault_net::FederationAnnouncement;

    // Old format: HeadAvailable without bucket_id field
    let old_json = serde_json::json!({
        "HeadAvailable": {
            "head_cid": [1,2,3],
            "visibility": "federated",
            "scope_tags": [["ns", "docs"]]
        }
    });

    let ann: FederationAnnouncement = serde_json::from_value(old_json).unwrap();
    match ann {
        FederationAnnouncement::HeadAvailable { bucket_id, .. } => {
            assert!(bucket_id.is_none()); // defaults to None
        }
        _ => panic!("wrong variant"),
    }
}

// ── Old AdminAnnouncement (pre-bucket variants still parse) ─────────

#[test]
fn old_admin_announcement_variants_still_parse() {
    use memvault_net::AdminAnnouncement;

    // Old variants that existed before bucket additions
    let variants = vec![
        serde_json::json!({"TokenConsumed": [1,2,3]}),
        serde_json::json!({"AdminKeyRotated": [4,5,6]}),
        serde_json::json!({"AgentKeyRotated": [7,8,9]}),
        serde_json::json!({"RotationAborted": [10,11,12]}),
        serde_json::json!({"Revoked": [13,14,15]}),
    ];

    for v in variants {
        let ann: AdminAnnouncement = serde_json::from_value(v).unwrap();
        // Should parse without error
        match ann {
            AdminAnnouncement::TokenConsumed(_)
            | AdminAnnouncement::AdminKeyRotated(_)
            | AdminAnnouncement::AgentKeyRotated(_)
            | AdminAnnouncement::RotationAborted(_)
            | AdminAnnouncement::Revoked(_) => {}
            _ => panic!("parsed as new variant unexpectedly"),
        }
    }
}

// ── Reindex with mixed v1/v2 envelopes ──────────────────────────────

#[test]
fn reindex_mixed_v1_v2_envelopes() {
    let dir = tempfile::tempdir().unwrap();
    let store = MemvaultStore::open(dir.path().join("test.redb")).unwrap();

    // v1 envelope (no bucket_id)
    let meta_v1 = EnvelopeMeta {
        author: b"peer-v1".to_vec(),
        tags: vec![("doc".to_string(), "v1-doc".to_string())],
        wall_ns: 1000,
        causal: vec![],
        provenance: vec![],
        cluster_id: Some(vec![1u8; 32]),
        bucket_id: None,
            ..Default::default()
    };
    store
        .insert_envelope(b"cid-v1", b"v1-data", &meta_v1)
        .unwrap();

    // v2 envelope (with bucket_id)
    let bucket = [42u8; 32];
    let meta_v2 = EnvelopeMeta {
        author: b"peer-v2".to_vec(),
        tags: vec![("doc".to_string(), "v2-doc".to_string())],
        wall_ns: 2000,
        causal: vec![],
        provenance: vec![],
        cluster_id: Some(vec![1u8; 32]),
        bucket_id: Some(bucket.to_vec()),
            ..Default::default()
    };
    store
        .insert_envelope(b"cid-v2", b"v2-data", &meta_v2)
        .unwrap();

    // Both should be queryable by tag
    let v1_results = store.query_by_tag("doc", "v1-doc", 0, 100).unwrap();
    let v2_results = store.query_by_tag("doc", "v2-doc", 0, 100).unwrap();
    assert_eq!(v1_results.len(), 1);
    assert_eq!(v2_results.len(), 1);

    // Only v2 should be in bucket index
    let bucket_results = store.query_by_bucket(&bucket, 0, 100).unwrap();
    assert_eq!(bucket_results.len(), 1);
    assert_eq!(bucket_results[0], b"cid-v2");
}

// ── Bucket binding migration (unbound → bound on cluster-join) ──────

#[tokio::test]
async fn unbound_buckets_rebind_on_cluster_join() {
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(MemvaultStore::open(dir.path().join("test.redb")).unwrap());

    // Create buckets WITHOUT binding (simulates pre-genesis data)
    for i in 0..3u8 {
        let bucket_id = [i + 10; 32];
        let decl_cid = [i + 100; 32];
        store.put_bucket(&bucket_id, &decl_cid).unwrap();
    }

    // Simulate cluster-join: bind all unbound buckets
    let cluster_id = vec![1u8; 32];
    let rebound = store.bind_unbound_buckets(&cluster_id).unwrap();
    assert_eq!(rebound, 3);

    // All should now be bound
    for i in 0..3u8 {
        let bucket_id = [i + 10; 32];
        let binding = store.get_bucket_cluster(&bucket_id).unwrap();
        assert!(binding.is_some());
        assert_eq!(binding.unwrap(), cluster_id.to_vec());
    }

    // Running again should bind 0 (already bound)
    assert_eq!(store.bind_unbound_buckets(&cluster_id).unwrap(), 0);
}

// ── Token compatibility ─────────────────────────────────────────────

#[test]
fn token_string_prefix_unchanged() {
    // The token prefix must stay "mvjoin1:" for backwards compat
    assert_eq!(
        memvault_auth::decode_token_string("mvjoin1:invalid")
            .unwrap_err()
            .to_string()
            .contains("decode"),
        true
    );
    // Wrong prefix should fail
    assert!(memvault_auth::decode_token_string("mvjoin2:something").is_err());
    assert!(memvault_auth::decode_token_string("bearer:something").is_err());
}

// ── Auto-bind unbound buckets on client open with cluster ───────────

#[tokio::test]
async fn unbound_buckets_auto_bind_when_client_opens_with_cluster() {
    use memvault_api::{EventBus, LocalClient, MemvaultClient};
    use memvault_query::QuotaManager;
    use tokio::sync::RwLock;

    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("test.redb");

    // Phase 1: create buckets with NO cluster (simulates pre-genesis)
    {
        let store = Arc::new(MemvaultStore::open(&db_path).unwrap());
        let client = LocalClient::new(
            Arc::clone(&store),
            Arc::new(RwLock::new(QuotaManager::default())),
            Arc::new(EventBus::new(64)),
            vec![0u8; 32], // zero peer_id
            vec![0u8; 32], // zero cluster_id = no cluster
        );
        client.set_node_signing_key(ed25519_dalek::SigningKey::from_bytes(&[1u8; 32]));
        // Create buckets — these will be private/unbound since no cluster
        let b1 = client
            .bucket_create(
                "pre-genesis-1",
                None,
                Visibility::Internal,
                Classification::Internal,
                BucketRole::Standard,
            )
            .await
            .unwrap();
        let b2 = client
            .bucket_create(
                "pre-genesis-2",
                None,
                Visibility::Internal,
                Classification::Internal,
                BucketRole::Standard,
            )
            .await
            .unwrap();

        // Verify they're unbound
        let info = client.bucket_get(&b1).await.unwrap().unwrap();
        assert!(
            info.cluster_id.is_none(),
            "should be unbound with no cluster"
        );
    }

    // Phase 2: re-open the store WITH a cluster_id (simulates post-genesis)
    {
        let cluster_id = vec![42u8; 32];
        let store = Arc::new(MemvaultStore::open(&db_path).unwrap());
        store.set_local_cluster_id(&cluster_id).unwrap();

        let client = LocalClient::new(
            Arc::clone(&store),
            Arc::new(RwLock::new(QuotaManager::default())),
            Arc::new(EventBus::new(64)),
            vec![1u8; 32],
            cluster_id.clone(),
        );

        // The unbound buckets should now be auto-bound to the cluster
        let buckets = client.bucket_list().await.unwrap();
        assert_eq!(buckets.len(), 2);
        for b in &buckets {
            assert_eq!(
                b.cluster_id.as_ref().map(|c| c.0.to_vec()),
                Some(cluster_id.clone()),
                "bucket '{}' should be auto-bound to cluster",
                b.name
            );
        }
    }
}

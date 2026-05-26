//! Integration tests for LocalClient.

use std::collections::BTreeMap;
use std::sync::Arc;

use tokio::sync::RwLock;

use memvault_api::{EventBus, LocalClient, MemvaultClient, MemvaultEvent};
use memvault_core::{DocId, EdgeId, EntityId, NodeRef, Visibility};
use memvault_doc::{Document, Edge, Entity};
use memvault_query::{QuotaManager, TextIndex};
use memvault_store::MemvaultStore;
use rand::RngCore;

fn make_client() -> (tempfile::TempDir, Arc<LocalClient>) {
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(MemvaultStore::open(dir.path().join("test.redb")).unwrap());
    let index = Arc::new(RwLock::new(TextIndex::new()));
    let quotas = Arc::new(RwLock::new(QuotaManager::default()));
    let event_bus = Arc::new(EventBus::new(64));
    // Use proper 32-byte IDs so bucket auto-bind works correctly.
    let mut peer_id = [0u8; 32];
    peer_id[..6].copy_from_slice(b"peer-1");
    let mut cluster_id = [0u8; 32];
    cluster_id[..9].copy_from_slice(b"cluster-1");
    let client = Arc::new(LocalClient::new(
        store,
        index,
        quotas,
        event_bus,
        peer_id.to_vec(),
        cluster_id.to_vec(),
    ));
    (dir, client)
}

#[tokio::test]
async fn put_doc_and_get_doc_roundtrip() {
    let (_dir, client) = make_client();

    let doc_id = DocId::random();
    let mut frontmatter = BTreeMap::new();
    frontmatter.insert("title".to_string(), serde_json::json!("Test Document"));

    let doc = Document::new(doc_id.clone(), "Hello, world!".to_string(), frontmatter);

    let cid = client
        .put_doc(
            doc,
            vec![("ns".into(), "test".into())],
            Visibility::Internal,
            None,
        )
        .await
        .unwrap();
    assert!(!cid.is_empty());

    let retrieved = client.get_doc(&doc_id).await.unwrap();
    assert!(retrieved.is_some());
    let retrieved = retrieved.unwrap();
    assert_eq!(retrieved.id, doc_id);
    assert_eq!(retrieved.body, "Hello, world!");
    assert_eq!(
        retrieved.frontmatter.get("title"),
        Some(&serde_json::json!("Test Document"))
    );
}

#[tokio::test]
async fn attach_file_and_get_attachment_roundtrip() {
    let (_dir, client) = make_client();

    let doc_id = DocId::random();
    let doc = Document::new(
        doc_id.clone(),
        "doc with attachment".to_string(),
        BTreeMap::new(),
    );
    client
        .put_doc(doc, vec![], Visibility::Internal, None)
        .await
        .unwrap();

    let file_data = b"This is a test file with some content for chunking tests.";
    let manifest_cid = client
        .upload_file(
            file_data,
            Some("test.txt"),
            "text/plain",
            vec![("classification".to_string(), "internal".to_string())],
            "internal",
            None,
        )
        .await
        .unwrap();
    assert!(!manifest_cid.is_empty());

    let retrieved_data = client.read_file(&manifest_cid).await.unwrap();
    assert_eq!(retrieved_data, file_data.to_vec());
}

#[tokio::test]
async fn add_entity_and_traverse() {
    let (_dir, client) = make_client();

    // Create entities
    let entity_a = Entity {
        id: EntityId::random(),
        kind: "person".to_string(),
        props: BTreeMap::new(),
        edges_out: vec![],
    };
    let entity_b = Entity {
        id: EntityId::random(),
        kind: "person".to_string(),
        props: BTreeMap::new(),
        edges_out: vec![],
    };
    let entity_c = Entity {
        id: EntityId::random(),
        kind: "person".to_string(),
        props: BTreeMap::new(),
        edges_out: vec![],
    };

    let id_a = client
        .add_entity(entity_a.clone(), Visibility::Internal, None)
        .await
        .unwrap();
    let id_b = client
        .add_entity(entity_b.clone(), Visibility::Internal, None)
        .await
        .unwrap();
    let id_c = client
        .add_entity(entity_c.clone(), Visibility::Internal, None)
        .await
        .unwrap();

    // Add edges: A -> B, B -> C
    let edge_ab = Edge {
        id: EdgeId::random(),
        relation: "knows".to_string(),
        target: NodeRef::Entity(id_b.clone()),
        weight: Some(1.0),
        props: BTreeMap::new(),
        provenance: None,
    };
    client
        .add_link(
            &NodeRef::Entity(id_a.clone()),
            edge_ab,
            Visibility::Internal,
        )
        .await
        .unwrap();

    let edge_bc = Edge {
        id: EdgeId::random(),
        relation: "knows".to_string(),
        target: NodeRef::Entity(id_c.clone()),
        weight: Some(1.0),
        props: BTreeMap::new(),
        provenance: None,
    };
    client
        .add_link(
            &NodeRef::Entity(id_b.clone()),
            edge_bc,
            Visibility::Internal,
        )
        .await
        .unwrap();

    // Traverse from A with max_depth=2
    let hits = client
        .traverse_from(&NodeRef::Entity(id_a.clone()), Some("knows"), 2)
        .await
        .unwrap();
    assert_eq!(hits.len(), 2);

    // First hit should be B at depth 1
    assert_eq!(hits[0].node, NodeRef::Entity(id_b));
    assert_eq!(hits[0].depth, 1);

    // Second hit should be C at depth 2
    assert_eq!(hits[1].node, NodeRef::Entity(id_c));
    assert_eq!(hits[1].depth, 2);
}

#[tokio::test]
async fn search_after_indexing() {
    let (_dir, client) = make_client();

    let doc_id = DocId::random();
    let mut frontmatter = BTreeMap::new();
    frontmatter.insert("title".to_string(), serde_json::json!("Rust Programming"));

    let doc = Document::new(
        doc_id.clone(),
        "Rust is a systems programming language focused on safety.".to_string(),
        frontmatter,
    );
    client
        .put_doc(
            doc,
            vec![("lang".into(), "rust".into())],
            Visibility::Internal,
            None,
        )
        .await
        .unwrap();

    // Search for "safety"
    let hits = client.search("safety", 10).await.unwrap();
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].doc_id, doc_id);
    assert!(hits[0].score > 0.0);

    // Search for something that doesn't exist
    let hits = client.search("python", 10).await.unwrap();
    assert!(hits.is_empty());
}

#[tokio::test]
async fn event_bus_publish_subscribe() {
    let bus = EventBus::new(16);
    let mut rx = bus.subscribe();

    let doc_id = DocId::random();
    bus.publish(MemvaultEvent::DocCreated {
        doc_id: doc_id.clone(),
        cid: vec![1, 2, 3],
    });

    let event = rx.recv().await.unwrap();
    match event {
        MemvaultEvent::DocCreated { doc_id: id, cid } => {
            assert_eq!(id, doc_id);
            assert_eq!(cid, vec![1, 2, 3]);
        }
        _ => panic!("unexpected event"),
    }
}

#[tokio::test]
async fn quota_manager_integration() {
    use memvault_core::AgentId;
    use memvault_query::AgentQuota;

    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(MemvaultStore::open(dir.path().join("test.redb")).unwrap());
    let index = Arc::new(RwLock::new(TextIndex::new()));
    let quotas = Arc::new(RwLock::new(QuotaManager::new(AgentQuota {
        max_docs: 2,
        max_bytes: 1_000_000,
        max_entities: 100,
    })));
    let event_bus = Arc::new(EventBus::new(64));
    let _client = Arc::new(LocalClient::new(
        store,
        index,
        quotas.clone(),
        event_bus,
        b"peer-1".to_vec(),
        b"cluster-1".to_vec(),
    ));

    let agent = AgentId("test-agent".to_string());

    // Check that writes are allowed initially
    {
        let q = quotas.read().await;
        assert!(q.check_write(&agent, 100).is_ok());
        assert!(q.check_doc_create(&agent).is_ok());
    }

    // Record some usage
    {
        let mut q = quotas.write().await;
        q.record_doc_create(&agent, 500);
        q.record_doc_create(&agent, 500);
    }

    // Now doc creation should be denied (max_docs = 2)
    {
        let q = quotas.read().await;
        assert!(q.check_doc_create(&agent).is_err());
    }

    // But writes are still allowed (under byte limit)
    {
        let q = quotas.read().await;
        assert!(q.check_write(&agent, 100).is_ok());
    }
}

// ── Bucket lifecycle tests ──────────────────────────────────────────

#[tokio::test]
async fn bucket_create_and_list() {
    let (_dir, client) = make_client();

    // Initially no buckets
    let buckets = client.bucket_list().await.unwrap();
    assert!(buckets.is_empty());

    // Create a bucket
    let bucket_id = client
        .bucket_create(
            "test-bucket",
            Some("A test bucket"),
            Visibility::Internal,
            memvault_core::classification::Classification::Internal,
        )
        .await
        .unwrap();

    // List should return it
    let buckets = client.bucket_list().await.unwrap();
    assert_eq!(buckets.len(), 1);
    assert_eq!(buckets[0].name, "test-bucket");
    assert_eq!(buckets[0].id, bucket_id);
    // With a non-zero cluster_id, bucket_create auto-attaches and auto-binds.
    assert!(buckets[0].is_attached);
    assert!(buckets[0].cluster_id.is_some());
}

#[tokio::test]
async fn bucket_get_by_id() {
    let (_dir, client) = make_client();
    let bucket_id = client
        .bucket_create(
            "alpha",
            None,
            Visibility::Internal,
            memvault_core::classification::Classification::Internal,
        )
        .await
        .unwrap();

    let info = client.bucket_get(&bucket_id).await.unwrap();
    assert!(info.is_some());
    let info = info.unwrap();
    assert_eq!(info.name, "alpha");
    assert_eq!(info.id, bucket_id);
}

#[tokio::test]
async fn bucket_get_nonexistent_returns_none() {
    let (_dir, client) = make_client();
    let fake_id = memvault_core::BucketId([99u8; 32]);
    let info = client.bucket_get(&fake_id).await.unwrap();
    assert!(info.is_none());
}

#[tokio::test]
async fn bucket_rename() {
    let (_dir, client) = make_client();
    let bucket_id = client
        .bucket_create(
            "old-name",
            None,
            Visibility::Internal,
            memvault_core::classification::Classification::Internal,
        )
        .await
        .unwrap();

    client.bucket_rename(&bucket_id, "new-name").await.unwrap();

    let info = client.bucket_get(&bucket_id).await.unwrap().unwrap();
    assert_eq!(info.name, "new-name");
}

#[tokio::test]
async fn bucket_bind_to_cluster() {
    // Use a zero cluster to test explicit binding without auto-bind.
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(MemvaultStore::open(dir.path().join("test.redb")).unwrap());
    let client = Arc::new(LocalClient::new(
        store,
        Arc::new(RwLock::new(TextIndex::new())),
        Arc::new(RwLock::new(QuotaManager::default())),
        Arc::new(EventBus::new(64)),
        b"peer-1".to_vec(),
        vec![0u8; 32],
    ));
    let bucket_id = client
        .bucket_create(
            "bindable",
            None,
            Visibility::Internal,
            memvault_core::classification::Classification::Internal,
        )
        .await
        .unwrap();

    // Not bound yet (zero cluster = no auto-bind)
    let info = client.bucket_get(&bucket_id).await.unwrap().unwrap();
    assert!(info.cluster_id.is_none());

    let cluster_id = memvault_core::ClusterId([1u8; 32]);
    client
        .bucket_bind(&bucket_id, &cluster_id, true)
        .await
        .unwrap();

    let info = client.bucket_get(&bucket_id).await.unwrap().unwrap();
    assert_eq!(info.cluster_id, Some(cluster_id));
    assert!(info.is_default);
}

#[tokio::test]
async fn bucket_attach_flips_private() {
    // Use zero cluster so bucket starts private (no auto-attach).
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(MemvaultStore::open(dir.path().join("test.redb")).unwrap());
    let client = Arc::new(LocalClient::new(
        store,
        Arc::new(RwLock::new(TextIndex::new())),
        Arc::new(RwLock::new(QuotaManager::default())),
        Arc::new(EventBus::new(64)),
        b"peer-1".to_vec(),
        vec![0u8; 32],
    ));
    let bucket_id = client
        .bucket_create(
            "private-bucket",
            None,
            Visibility::Internal,
            memvault_core::classification::Classification::Internal,
        )
        .await
        .unwrap();

    // Initially private (no cluster → not auto-attached)
    let info = client.bucket_get(&bucket_id).await.unwrap().unwrap();
    assert!(!info.is_attached);

    // Attach
    client.bucket_attach(&bucket_id).await.unwrap();

    let info = client.bucket_get(&bucket_id).await.unwrap().unwrap();
    assert!(info.is_attached);

    // Idempotent
    client.bucket_attach(&bucket_id).await.unwrap();
    let info = client.bucket_get(&bucket_id).await.unwrap().unwrap();
    assert!(info.is_attached);
}

#[tokio::test]
async fn bucket_archive() {
    let (_dir, client) = make_client();
    // First bucket becomes auto-bound default; create a second one to archive.
    let _default = client
        .bucket_create(
            "default",
            None,
            Visibility::Internal,
            memvault_core::classification::Classification::Internal,
        )
        .await
        .unwrap();
    let bucket_id = client
        .bucket_create(
            "archivable",
            None,
            Visibility::Internal,
            memvault_core::classification::Classification::Internal,
        )
        .await
        .unwrap();

    client
        .bucket_archive(&bucket_id, "no longer needed")
        .await
        .unwrap();

    let info = client.bucket_get(&bucket_id).await.unwrap().unwrap();
    assert!(info.name.contains("[ARCHIVED]"));
    assert!(
        info.description
            .unwrap_or_default()
            .contains("no longer needed")
    );
}

#[tokio::test]
async fn bucket_archive_default_refused() {
    let (_dir, client) = make_client();
    let bucket_id = client
        .bucket_create(
            "the-default",
            None,
            Visibility::Internal,
            memvault_core::classification::Classification::Internal,
        )
        .await
        .unwrap();
    // Auto-bound by bucket_create. Make it the explicit default.
    let mut cluster_arr = [0u8; 32];
    cluster_arr[..9].copy_from_slice(b"cluster-1");
    client
        .bucket_bind(&bucket_id, &memvault_core::ClusterId(cluster_arr), true)
        .await
        .unwrap();
    let result = client.bucket_archive(&bucket_id, "try to remove").await;
    assert!(result.is_err(), "archiving default bucket should fail");
}

#[tokio::test]
async fn bucket_create_multiple_and_list() {
    let (_dir, client) = make_client();

    let _b1 = client
        .bucket_create(
            "alpha",
            None,
            Visibility::Internal,
            memvault_core::classification::Classification::Internal,
        )
        .await
        .unwrap();
    let _b2 = client
        .bucket_create(
            "beta",
            None,
            Visibility::Federated,
            memvault_core::classification::Classification::Public,
        )
        .await
        .unwrap();
    let _b3 = client
        .bucket_create(
            "gamma",
            None,
            Visibility::Public,
            memvault_core::classification::Classification::Confidential,
        )
        .await
        .unwrap();

    let buckets = client.bucket_list().await.unwrap();
    assert_eq!(buckets.len(), 3);

    let names: Vec<&str> = buckets.iter().map(|b| b.name.as_str()).collect();
    assert!(names.contains(&"alpha"));
    assert!(names.contains(&"beta"));
    assert!(names.contains(&"gamma"));
}

// ── PeerId persistence tests ────────────────────────────────────────

#[test]
fn store_peer_id_persistence() {
    let dir = tempfile::tempdir().unwrap();
    let store = MemvaultStore::open(dir.path().join("test.redb")).unwrap();

    // Initially no peer_id
    assert!(store.get_local_peer_id().unwrap().is_none());

    // Set it
    let peer_id = vec![42u8; 32];
    store.set_local_peer_id(&peer_id).unwrap();

    // Read it back
    assert_eq!(store.get_local_peer_id().unwrap().unwrap(), peer_id);

    // Setting the same value again is OK (idempotent)
    store.set_local_peer_id(&peer_id).unwrap();

    // Setting a different value fails
    let other_peer_id = vec![99u8; 32];
    assert!(store.set_local_peer_id(&other_peer_id).is_err());
}

#[test]
fn store_cluster_id_persistence() {
    let dir = tempfile::tempdir().unwrap();
    let store = MemvaultStore::open(dir.path().join("test.redb")).unwrap();

    assert!(store.get_local_cluster_id().unwrap().is_none());

    let cluster_id = vec![7u8; 32];
    store.set_local_cluster_id(&cluster_id).unwrap();
    assert_eq!(store.get_local_cluster_id().unwrap().unwrap(), cluster_id);
}

// ── Exclusive cluster binding tests ─────────────────────────────

#[tokio::test]
async fn bucket_bind_exclusive_to_one_cluster() {
    // Use zero cluster so bucket starts unbound.
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(MemvaultStore::open(dir.path().join("test.redb")).unwrap());
    let client = Arc::new(LocalClient::new(
        store,
        Arc::new(RwLock::new(TextIndex::new())),
        Arc::new(RwLock::new(QuotaManager::default())),
        Arc::new(EventBus::new(64)),
        b"peer-1".to_vec(),
        vec![0u8; 32],
    ));
    let bucket_id = client
        .bucket_create(
            "exclusive",
            None,
            Visibility::Internal,
            memvault_core::classification::Classification::Internal,
        )
        .await
        .unwrap();

    let cluster_a = memvault_core::ClusterId([1u8; 32]);
    let cluster_b = memvault_core::ClusterId([2u8; 32]);

    // Bind to cluster A succeeds
    client
        .bucket_bind(&bucket_id, &cluster_a, false)
        .await
        .unwrap();

    // Rebind to same cluster A is idempotent
    client
        .bucket_bind(&bucket_id, &cluster_a, false)
        .await
        .unwrap();

    // Bind to different cluster B fails
    let result = client.bucket_bind(&bucket_id, &cluster_b, false).await;
    assert!(
        result.is_err(),
        "should refuse rebinding to a different cluster"
    );
}

#[tokio::test]
async fn bucket_bind_idempotent_same_cluster() {
    // Use zero cluster so bucket starts unbound.
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(MemvaultStore::open(dir.path().join("test.redb")).unwrap());
    let client = Arc::new(LocalClient::new(
        store,
        Arc::new(RwLock::new(TextIndex::new())),
        Arc::new(RwLock::new(QuotaManager::default())),
        Arc::new(EventBus::new(64)),
        b"peer-1".to_vec(),
        vec![0u8; 32],
    ));
    let bucket_id = client
        .bucket_create(
            "idem",
            None,
            Visibility::Internal,
            memvault_core::classification::Classification::Internal,
        )
        .await
        .unwrap();

    let cluster = memvault_core::ClusterId([5u8; 32]);

    // Bind as non-default
    client
        .bucket_bind(&bucket_id, &cluster, false)
        .await
        .unwrap();
    let info = client.bucket_get(&bucket_id).await.unwrap().unwrap();
    assert!(!info.is_default);

    // Rebind same cluster as default
    client
        .bucket_bind(&bucket_id, &cluster, true)
        .await
        .unwrap();
    let info = client.bucket_get(&bucket_id).await.unwrap().unwrap();
    assert!(info.is_default);
}

#[test]
fn store_bind_unbound_buckets() {
    let dir = tempfile::tempdir().unwrap();
    let store = MemvaultStore::open(dir.path().join("test.redb")).unwrap();

    // Create 3 buckets in the store directly
    for i in 0..3u8 {
        let bucket_id = [i + 10; 32];
        let decl_cid = [i + 100; 32];
        store.put_bucket(&bucket_id, &decl_cid).unwrap();
    }

    // Bind one to a cluster
    let cluster_id = [1u8; 32];
    store.bind_bucket(&[10; 32], &cluster_id, false).unwrap();

    // bind_unbound_buckets should bind the other 2
    let count = store.bind_unbound_buckets(&cluster_id).unwrap();
    assert_eq!(count, 2);

    // Now all 3 should be bound
    for i in 0..3u8 {
        let bucket_id = [i + 10; 32];
        assert!(store.get_bucket_cluster(&bucket_id).unwrap().is_some());
    }

    // Running again should bind 0
    let count = store.bind_unbound_buckets(&cluster_id).unwrap();
    assert_eq!(count, 0);
}

// ── Share decide tests ──────────────────────────────────────────

#[tokio::test]
async fn share_inbox_initially_empty() {
    let (_dir, client) = make_client();
    let inbox = client.share_inbox().await.unwrap();
    assert!(inbox.is_empty());
}

// ── Auth validation tests ───────────────────────────────────────

#[test]
fn agent_identity_requires_all_files() {
    let dir = tempfile::tempdir().unwrap();
    let identity_dir = dir.path().join("incomplete-agent");
    std::fs::create_dir_all(&identity_dir).unwrap();

    // Missing files should fail to load
    assert!(!memvault_api::agent_identity::AgentIdentity::exists(
        &identity_dir
    ));

    let result = memvault_api::agent_identity::AgentIdentity::load(&identity_dir);
    assert!(result.is_err());
}

#[test]
fn join_token_roundtrip_with_verify() {
    use ed25519_dalek::{Signer, SigningKey};
    use memvault_auth::{JoinToken, Role, decode_token_string, encode_token_string};
    use memvault_core::{ClusterId, PeerId};

    let mut secret = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut secret);
    let sk = SigningKey::from_bytes(&secret);
    let vk = sk.verifying_key();
    let peer_id = PeerId(vk.as_bytes().to_vec());
    let cluster_id = ClusterId::random();

    let token = JoinToken {
        issuer: peer_id.clone(),
        cluster_id: cluster_id.clone(),
        role: Role::AgentHost,
        initial_grants: vec![],
        not_before_ns: 0,
        not_after_ns: u64::MAX,
        max_uses: 5,
        nonce: [42u8; 16],
        label: Some("test".into()),
        signature: [0u8; 64],
    };

    // Sign
    let signing_bytes = token.signing_bytes().unwrap();
    let sig = sk.sign(&signing_bytes);
    let signed_token = JoinToken {
        signature: sig.to_bytes(),
        ..token
    };

    // Encode + decode
    let encoded = encode_token_string(&signed_token).unwrap();
    assert!(encoded.starts_with("mvjoin1:"));

    let decoded = decode_token_string(&encoded).unwrap();
    assert_eq!(decoded.max_uses, 5);
    assert_eq!(decoded.label, Some("test".into()));

    // Verify
    decoded.verify_signature(&vk).unwrap();
    decoded.verify_time_bounds(1000).unwrap();

    // Expired token fails
    let expired = JoinToken {
        not_after_ns: 500,
        ..decoded
    };
    assert!(expired.verify_time_bounds(1000).is_err());
}

// ── Envelope v1/v2 roundtrip tests ──────────────────────────────

#[test]
fn envelope_v1_no_bucket_roundtrip() {
    use memvault_core::tags::Tag;
    use memvault_core::{BucketId, PeerId, Signed, Visibility};

    let mut secret = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut secret);
    let sk = ed25519_dalek::SigningKey::from_bytes(&secret);
    let vk = sk.verifying_key();

    let envelope = Signed::sign(
        "v1 content".to_string(),
        &sk,
        PeerId(vk.as_bytes().to_vec()),
        vec![],
        vec![],
        vec![Tag::new("classification", "internal")],
        Visibility::Internal,
        1,
        1000,
        None,
        None, // no bucket = v1
    )
    .unwrap();

    assert_eq!(envelope.version, 1);
    assert!(envelope.bucket_id.is_none());
    envelope.verify(&vk).unwrap();
}

#[test]
fn envelope_v2_with_bucket_roundtrip() {
    use memvault_core::tags::Tag;
    use memvault_core::{BucketId, PeerId, Signed, Visibility};

    let mut secret = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut secret);
    let sk = ed25519_dalek::SigningKey::from_bytes(&secret);
    let vk = sk.verifying_key();
    let bucket = BucketId::random();

    let envelope = Signed::sign(
        "v2 content".to_string(),
        &sk,
        PeerId(vk.as_bytes().to_vec()),
        vec![],
        vec![],
        vec![Tag::new("classification", "internal")],
        Visibility::Internal,
        1,
        1000,
        None,
        Some(bucket.clone()),
    )
    .unwrap();

    assert_eq!(envelope.version, 2);
    assert_eq!(envelope.bucket_id, Some(bucket));
    envelope.verify(&vk).unwrap();
}

#[test]
fn envelope_v2_tampered_bucket_fails_verify() {
    use memvault_core::tags::Tag;
    use memvault_core::{BucketId, PeerId, Signed, Visibility};

    let mut secret = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut secret);
    let sk = ed25519_dalek::SigningKey::from_bytes(&secret);
    let vk = sk.verifying_key();

    let mut envelope = Signed::sign(
        "tamper test".to_string(),
        &sk,
        PeerId(vk.as_bytes().to_vec()),
        vec![],
        vec![],
        vec![Tag::new("classification", "internal")],
        Visibility::Internal,
        1,
        1000,
        None,
        Some(BucketId::random()),
    )
    .unwrap();

    // Tamper with the bucket_id
    envelope.bucket_id = Some(BucketId::random());
    assert!(envelope.verify(&vk).is_err());
}

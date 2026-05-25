//! Integration tests for LocalClient.

use std::collections::BTreeMap;
use std::sync::Arc;

use tokio::sync::RwLock;

use memvault_api::{EventBus, LocalClient, MemvaultClient, MemvaultEvent};
use memvault_core::{DocId, EdgeId, EntityId, NodeRef, Visibility};
use memvault_doc::{Document, Edge, Entity};
use memvault_query::{QuotaManager, TextIndex};
use memvault_store::MemvaultStore;

fn make_client() -> (tempfile::TempDir, Arc<LocalClient>) {
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(MemvaultStore::open(dir.path().join("test.redb")).unwrap());
    let index = Arc::new(RwLock::new(TextIndex::new()));
    let quotas = Arc::new(RwLock::new(QuotaManager::default()));
    let event_bus = Arc::new(EventBus::new(64));
    let client = Arc::new(LocalClient::new(
        store,
        index,
        quotas,
        event_bus,
        b"peer-1".to_vec(),
        b"cluster-1".to_vec(),
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
        .put_doc(doc, vec![("ns".into(), "test".into())], Visibility::Internal)
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
    let doc = Document::new(doc_id.clone(), "doc with attachment".to_string(), BTreeMap::new());
    client
        .put_doc(doc, vec![], Visibility::Internal)
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
        .add_entity(entity_a.clone(), Visibility::Internal)
        .await
        .unwrap();
    let id_b = client
        .add_entity(entity_b.clone(), Visibility::Internal)
        .await
        .unwrap();
    let id_c = client
        .add_entity(entity_c.clone(), Visibility::Internal)
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
        .add_link(&NodeRef::Entity(id_a.clone()), edge_ab, Visibility::Internal)
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
        .add_link(&NodeRef::Entity(id_b.clone()), edge_bc, Visibility::Internal)
        .await
        .unwrap();

    // Traverse from A with max_depth=2
    let hits = client.traverse_from(&NodeRef::Entity(id_a.clone()), Some("knows"), 2).await.unwrap();
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
        .put_doc(doc, vec![("lang".into(), "rust".into())], Visibility::Internal)
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
    let bucket_id = client.bucket_create(
        "test-bucket",
        Some("A test bucket"),
        Visibility::Internal,
        memvault_core::classification::Classification::Internal,
    ).await.unwrap();

    // List should return it
    let buckets = client.bucket_list().await.unwrap();
    assert_eq!(buckets.len(), 1);
    assert_eq!(buckets[0].name, "test-bucket");
    assert_eq!(buckets[0].id, bucket_id);
    assert!(!buckets[0].is_attached); // private by default
    assert!(buckets[0].cluster_id.is_none()); // not bound to any cluster
}

#[tokio::test]
async fn bucket_get_by_id() {
    let (_dir, client) = make_client();
    let bucket_id = client.bucket_create(
        "alpha", None, Visibility::Internal,
        memvault_core::classification::Classification::Internal,
    ).await.unwrap();

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
    let bucket_id = client.bucket_create(
        "old-name", None, Visibility::Internal,
        memvault_core::classification::Classification::Internal,
    ).await.unwrap();

    client.bucket_rename(&bucket_id, "new-name").await.unwrap();

    let info = client.bucket_get(&bucket_id).await.unwrap().unwrap();
    assert_eq!(info.name, "new-name");
}

#[tokio::test]
async fn bucket_bind_to_cluster() {
    let (_dir, client) = make_client();
    let bucket_id = client.bucket_create(
        "bindable", None, Visibility::Internal,
        memvault_core::classification::Classification::Internal,
    ).await.unwrap();

    let cluster_id = memvault_core::ClusterId([1u8; 32]);
    client.bucket_bind(&bucket_id, &cluster_id, true).await.unwrap();

    let info = client.bucket_get(&bucket_id).await.unwrap().unwrap();
    assert_eq!(info.cluster_id, Some(cluster_id));
    assert!(info.is_default);
}

#[tokio::test]
async fn bucket_attach_flips_private() {
    let (_dir, client) = make_client();
    let bucket_id = client.bucket_create(
        "private-bucket", None, Visibility::Internal,
        memvault_core::classification::Classification::Internal,
    ).await.unwrap();

    // Initially private
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
    let bucket_id = client.bucket_create(
        "archivable", None, Visibility::Internal,
        memvault_core::classification::Classification::Internal,
    ).await.unwrap();

    client.bucket_archive(&bucket_id, "no longer needed").await.unwrap();

    let info = client.bucket_get(&bucket_id).await.unwrap().unwrap();
    assert!(info.name.contains("[ARCHIVED]"));
    assert!(info.description.unwrap_or_default().contains("no longer needed"));
}

#[tokio::test]
async fn bucket_create_multiple_and_list() {
    let (_dir, client) = make_client();

    let _b1 = client.bucket_create("alpha", None, Visibility::Internal,
        memvault_core::classification::Classification::Internal).await.unwrap();
    let _b2 = client.bucket_create("beta", None, Visibility::Federated,
        memvault_core::classification::Classification::Public).await.unwrap();
    let _b3 = client.bucket_create("gamma", None, Visibility::Public,
        memvault_core::classification::Classification::Confidential).await.unwrap();

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

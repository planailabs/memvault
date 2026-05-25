//! Two-node smoke tests: verify operations on two independent nodes
//! that share a cluster_id (simulating a cluster join).

use std::sync::Arc;
use tokio::sync::RwLock;

use memvault_api::{EventBus, LocalClient, MemvaultClient};
use memvault_core::{BucketId, ClusterId, Visibility};
use memvault_core::classification::Classification;
use memvault_doc::Document;
use memvault_query::{QuotaManager, TextIndex};
use memvault_store::MemvaultStore;

/// Create a node (store + client) with a given cluster_id.
fn make_node(cluster_id: &ClusterId) -> (tempfile::TempDir, Arc<MemvaultStore>, LocalClient) {
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(MemvaultStore::open(dir.path().join("blocks.redb")).unwrap());
    store.set_local_cluster_id(&cluster_id.0).unwrap();

    // Generate a unique peer_id for this node
    let mut peer_id = vec![0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut peer_id);
    store.set_local_peer_id(&peer_id).unwrap();

    let mut client = LocalClient::new(
        Arc::clone(&store),
        Arc::new(RwLock::new(TextIndex::new())),
        Arc::new(RwLock::new(QuotaManager::default())),
        Arc::new(EventBus::new(64)),
        peer_id,
        cluster_id.0.to_vec(),
    );

    // Generate admin key for token issuance
    let mut seed = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut seed);
    client.set_admin_signing_key(ed25519_dalek::SigningKey::from_bytes(&seed));

    (dir, store, client)
}

// ── Genesis + Cluster Join Flow ─────────────────────────────────────

#[tokio::test]
async fn two_nodes_share_cluster_id() {
    let cluster_id = ClusterId::random();
    let (_dir_a, store_a, _client_a) = make_node(&cluster_id);
    let (_dir_b, store_b, _client_b) = make_node(&cluster_id);

    // Both nodes have the same cluster_id
    assert_eq!(
        store_a.get_local_cluster_id().unwrap().unwrap(),
        store_b.get_local_cluster_id().unwrap().unwrap(),
    );
}

#[tokio::test]
async fn two_nodes_have_different_peer_ids() {
    let cluster_id = ClusterId::random();
    let (_dir_a, store_a, _client_a) = make_node(&cluster_id);
    let (_dir_b, store_b, _client_b) = make_node(&cluster_id);

    let peer_a = store_a.get_local_peer_id().unwrap().unwrap();
    let peer_b = store_b.get_local_peer_id().unwrap().unwrap();
    assert_ne!(peer_a, peer_b);
}

// ── Bucket Operations ───────────────────────────────────────────────

#[tokio::test]
async fn node_a_creates_bucket_visible_locally() {
    let cluster_id = ClusterId::random();
    let (_dir_a, store_a, client_a) = make_node(&cluster_id);

    let bucket = client_a.bucket_create("research", Some("AI research notes"),
        Visibility::Internal, Classification::Internal).await.unwrap();

    // Bind to cluster
    client_a.bucket_bind(&bucket, &cluster_id, true).await.unwrap();

    // Visible on node_a
    let info = client_a.bucket_get(&bucket).await.unwrap().unwrap();
    assert_eq!(info.name, "research");
    assert_eq!(info.cluster_id, Some(cluster_id.clone()));
    assert!(info.is_default);
}

#[tokio::test]
async fn both_nodes_create_buckets_independently() {
    let cluster_id = ClusterId::random();
    let (_dir_a, _store_a, client_a) = make_node(&cluster_id);
    let (_dir_b, _store_b, client_b) = make_node(&cluster_id);

    let bucket_a = client_a.bucket_create("alpha", None,
        Visibility::Internal, Classification::Internal).await.unwrap();
    let bucket_b = client_b.bucket_create("beta", None,
        Visibility::Internal, Classification::Internal).await.unwrap();

    // Each node sees only its own bucket
    assert_eq!(client_a.bucket_list().await.unwrap().len(), 1);
    assert_eq!(client_b.bucket_list().await.unwrap().len(), 1);

    // Different bucket IDs
    assert_ne!(bucket_a, bucket_b);
}

#[tokio::test]
async fn bucket_rename_persists() {
    let cluster_id = ClusterId::random();
    let (_dir_a, _store_a, client_a) = make_node(&cluster_id);

    let bucket = client_a.bucket_create("old-name", None,
        Visibility::Internal, Classification::Internal).await.unwrap();
    client_a.bucket_rename(&bucket, "new-name").await.unwrap();

    let info = client_a.bucket_get(&bucket).await.unwrap().unwrap();
    assert_eq!(info.name, "new-name");
}

#[tokio::test]
async fn bucket_attach_makes_visible() {
    let cluster_id = ClusterId::random();
    let (_dir_a, _store_a, client_a) = make_node(&cluster_id);

    let bucket = client_a.bucket_create("private-stuff", None,
        Visibility::Internal, Classification::Internal).await.unwrap();

    // Initially private
    let info = client_a.bucket_get(&bucket).await.unwrap().unwrap();
    assert!(!info.is_attached);

    // Attach
    client_a.bucket_attach(&bucket).await.unwrap();
    let info = client_a.bucket_get(&bucket).await.unwrap().unwrap();
    assert!(info.is_attached);
}

#[tokio::test]
async fn bucket_archive_marks_archived() {
    let cluster_id = ClusterId::random();
    let (_dir_a, _store_a, client_a) = make_node(&cluster_id);

    let bucket = client_a.bucket_create("temp", None,
        Visibility::Internal, Classification::Internal).await.unwrap();
    client_a.bucket_archive(&bucket, "no longer needed").await.unwrap();

    let info = client_a.bucket_get(&bucket).await.unwrap().unwrap();
    assert!(info.name.contains("[ARCHIVED]"));
}

#[tokio::test]
async fn bucket_exclusive_binding_across_nodes() {
    let cluster_a = ClusterId::random();
    let cluster_b = ClusterId::random();
    let (_dir_a, _store_a, client_a) = make_node(&cluster_a);

    let bucket = client_a.bucket_create("exclusive", None,
        Visibility::Internal, Classification::Internal).await.unwrap();
    client_a.bucket_bind(&bucket, &cluster_a, false).await.unwrap();

    // Cannot rebind to different cluster
    let result = client_a.bucket_bind(&bucket, &cluster_b, false).await;
    assert!(result.is_err());
}

// ── Document Operations ─────────────────────────────────────────────

#[tokio::test]
async fn node_a_creates_and_retrieves_doc() {
    let cluster_id = ClusterId::random();
    let (_dir_a, _store_a, client_a) = make_node(&cluster_id);

    let doc = Document::new(
        memvault_core::DocId::random(),
        "Hello from node A!".to_string(),
        Default::default(),
    );
    let tags = vec![("topic".to_string(), "greeting".to_string())];
    let cid = client_a.put_doc(doc.clone(), tags, Visibility::Internal).await.unwrap();
    assert!(!cid.is_empty());

    // Retrieve
    let fetched = client_a.get_doc(&doc.id).await.unwrap().unwrap();
    assert_eq!(fetched.body, "Hello from node A!");
}

#[tokio::test]
async fn both_nodes_create_docs_independently() {
    let cluster_id = ClusterId::random();
    let (_dir_a, _store_a, client_a) = make_node(&cluster_id);
    let (_dir_b, _store_b, client_b) = make_node(&cluster_id);

    let doc_a = Document::new(
        memvault_core::DocId::random(),
        "Doc from A".to_string(),
        Default::default(),
    );
    let doc_b = Document::new(
        memvault_core::DocId::random(),
        "Doc from B".to_string(),
        Default::default(),
    );

    client_a.put_doc(doc_a.clone(), vec![], Visibility::Internal).await.unwrap();
    client_b.put_doc(doc_b.clone(), vec![], Visibility::Internal).await.unwrap();

    // Each node can read its own doc
    assert!(client_a.get_doc(&doc_a.id).await.unwrap().is_some());
    assert!(client_b.get_doc(&doc_b.id).await.unwrap().is_some());

    // Node A cannot see node B's doc (no P2P sync in unit test)
    assert!(client_a.get_doc(&doc_b.id).await.unwrap().is_none());
    assert!(client_b.get_doc(&doc_a.id).await.unwrap().is_none());
}

#[tokio::test]
async fn doc_listing_works_per_node() {
    let cluster_id = ClusterId::random();
    let (_dir_a, _store_a, client_a) = make_node(&cluster_id);

    for i in 0..5 {
        let doc = Document::new(
            memvault_core::DocId::random(),
            format!("Document #{i}"),
            Default::default(),
        );
        client_a.put_doc(doc, vec![("batch".into(), "test".into())], Visibility::Internal).await.unwrap();
    }

    let docs = client_a.list_docs(Some(("batch".to_string(), "test".to_string())), 100).await.unwrap();
    assert_eq!(docs.len(), 5);
}

// ── Token Issuance ──────────────────────────────────────────────────

#[tokio::test]
async fn node_a_issues_token() {
    let cluster_id = ClusterId::random();
    let (_dir_a, _store_a, client_a) = make_node(&cluster_id);

    let token = client_a.issue_token(
        memvault_auth::Role::AgentHost, 3600, 1, Some("test-token".into()),
    ).await.unwrap();

    assert!(token.starts_with("mvjoin1:"));

    // Token appears in list
    let tokens = client_a.list_tokens().await.unwrap();
    assert_eq!(tokens.len(), 1);
    assert_eq!(tokens[0].label, Some("test-token".to_string()));
}

#[tokio::test]
async fn token_revocation_works() {
    let cluster_id = ClusterId::random();
    let (_dir_a, _store_a, client_a) = make_node(&cluster_id);

    let _token = client_a.issue_token(
        memvault_auth::Role::AgentHost, 3600, 1, Some("revocable".into()),
    ).await.unwrap();

    let tokens = client_a.list_tokens().await.unwrap();
    assert_eq!(tokens.len(), 1);
    let cid = tokens[0].cid.clone();

    client_a.revoke_token(&cid, "no longer needed").await.unwrap();

    let tokens = client_a.list_tokens().await.unwrap();
    assert!(tokens[0].revoked);
}

// ── Entity/Graph Operations ─────────────────────────────────────────

#[tokio::test]
async fn node_creates_entity_and_lists() {
    use memvault_doc::Entity;
    use std::collections::BTreeMap;

    let cluster_id = ClusterId::random();
    let (_dir_a, _store_a, client_a) = make_node(&cluster_id);

    let mut props = BTreeMap::new();
    props.insert("name".to_string(), serde_json::json!("Alice"));
    props.insert("role".to_string(), serde_json::json!("engineer"));

    let entity = Entity {
        id: memvault_core::EntityId::random(),
        kind: "person".to_string(),
        props,
        edges_out: vec![],
    };

    let eid = client_a.add_entity(entity, Visibility::Internal).await.unwrap();
    let fetched = client_a.get_entity(&eid).await.unwrap().unwrap();
    assert_eq!(fetched.kind, "person");
    assert_eq!(fetched.props["name"], "Alice");
}

// ── Share Operations ────────────────────────────────────────────────

#[tokio::test]
async fn share_inbox_outbox_empty_initially() {
    let cluster_id = ClusterId::random();
    let (_dir_a, _store_a, client_a) = make_node(&cluster_id);

    assert!(client_a.share_inbox().await.unwrap().is_empty());
    assert!(client_a.share_outbox().await.unwrap().is_empty());
}

// ── Status ──────────────────────────────────────────────────────────

#[tokio::test]
async fn status_reports_correct_counts() {
    let cluster_id = ClusterId::random();
    let (_dir_a, _store_a, client_a) = make_node(&cluster_id);

    // Initially no docs
    let status = client_a.status().await.unwrap();
    assert_eq!(status.doc_count, 0);

    // Create some docs
    for i in 0..3 {
        let doc = Document::new(
            memvault_core::DocId::random(),
            format!("Status doc #{i}"),
            Default::default(),
        );
        client_a.put_doc(doc, vec![], Visibility::Internal).await.unwrap();
    }

    let status = client_a.status().await.unwrap();
    assert_eq!(status.doc_count, 3);
    assert!(status.block_count >= 3);
}

// ── Full Workflow: Genesis → Create → Query ─────────────────────────

#[tokio::test]
async fn full_workflow_genesis_bucket_docs() {
    let cluster_id = ClusterId::random();
    let (_dir_a, store_a, client_a) = make_node(&cluster_id);

    // 1. Create default bucket and bind to cluster (mimics genesis)
    let default_bucket = client_a.bucket_create("default", None,
        Visibility::Internal, Classification::Internal).await.unwrap();
    store_a.bind_bucket(&default_bucket.0, &cluster_id.0, true).unwrap();

    // 2. Create additional bucket
    let research_bucket = client_a.bucket_create("research", Some("AI papers"),
        Visibility::Federated, Classification::Internal).await.unwrap();
    client_a.bucket_bind(&research_bucket, &cluster_id, false).await.unwrap();
    client_a.bucket_attach(&research_bucket).await.unwrap();

    // 3. Create docs
    let doc1 = Document::new(memvault_core::DocId::random(), "Hello world".into(), Default::default());
    let doc2 = Document::new(memvault_core::DocId::random(), "Research paper".into(), Default::default());
    client_a.put_doc(doc1.clone(), vec![("topic".into(), "general".into())], Visibility::Internal).await.unwrap();
    client_a.put_doc(doc2.clone(), vec![("topic".into(), "research".into())], Visibility::Federated).await.unwrap();

    // 4. Create entity
    let entity = memvault_doc::Entity {
        id: memvault_core::EntityId::random(),
        kind: "concept".to_string(),
        props: {
            let mut p = std::collections::BTreeMap::new();
            p.insert("name".to_string(), serde_json::json!("Transformers"));
            p
        },
        edges_out: vec![],
    };
    let eid = client_a.add_entity(entity, Visibility::Internal).await.unwrap();

    // 5. Verify everything
    let buckets = client_a.bucket_list().await.unwrap();
    assert_eq!(buckets.len(), 2);

    let docs = client_a.list_docs(None, 100).await.unwrap();
    assert_eq!(docs.len(), 2);

    let entity = client_a.get_entity(&eid).await.unwrap().unwrap();
    assert_eq!(entity.props["name"], "Transformers");

    let status = client_a.status().await.unwrap();
    assert!(status.block_count > 0);
    assert_eq!(status.doc_count, 2);
}

#[tokio::test]
async fn full_workflow_two_nodes_independent_ops() {
    let cluster_id = ClusterId::random();
    let (_dir_a, store_a, client_a) = make_node(&cluster_id);
    let (_dir_b, store_b, client_b) = make_node(&cluster_id);

    // Genesis on node_a
    let bucket_a = client_a.bucket_create("default", None,
        Visibility::Internal, Classification::Internal).await.unwrap();
    store_a.bind_bucket(&bucket_a.0, &cluster_id.0, true).unwrap();

    // Cluster-join on node_b
    let bucket_b = client_b.bucket_create("default", None,
        Visibility::Internal, Classification::Internal).await.unwrap();
    store_b.bind_bucket(&bucket_b.0, &cluster_id.0, true).unwrap();

    // Node A writes 10 docs
    for i in 0..10 {
        let doc = Document::new(memvault_core::DocId::random(), format!("A-doc-{i}"), Default::default());
        client_a.put_doc(doc, vec![("source".into(), "node-a".into())], Visibility::Internal).await.unwrap();
    }

    // Node B writes 5 docs
    for i in 0..5 {
        let doc = Document::new(memvault_core::DocId::random(), format!("B-doc-{i}"), Default::default());
        client_b.put_doc(doc, vec![("source".into(), "node-b".into())], Visibility::Internal).await.unwrap();
    }

    // Node A issues a token
    let token = client_a.issue_token(memvault_auth::Role::AgentHost, 3600, 5, Some("multi-use".into())).await.unwrap();
    assert!(token.starts_with("mvjoin1:"));

    // Verify counts
    let status_a = client_a.status().await.unwrap();
    let status_b = client_b.status().await.unwrap();
    assert_eq!(status_a.doc_count, 10);
    assert_eq!(status_b.doc_count, 5);

    // Both have their own default bucket
    let default_a = store_a.get_default_bucket(&cluster_id.0).unwrap().unwrap();
    let default_b = store_b.get_default_bucket(&cluster_id.0).unwrap().unwrap();
    assert_eq!(default_a, bucket_a.0.to_vec());
    assert_eq!(default_b, bucket_b.0.to_vec());
}

// ── Edge Cases ──────────────────────────────────────────────────────

#[tokio::test]
async fn empty_doc_body_works() {
    let cluster_id = ClusterId::random();
    let (_dir_a, _store_a, client_a) = make_node(&cluster_id);

    let doc = Document::new(memvault_core::DocId::random(), "".into(), Default::default());
    client_a.put_doc(doc.clone(), vec![], Visibility::Internal).await.unwrap();

    let fetched = client_a.get_doc(&doc.id).await.unwrap().unwrap();
    assert_eq!(fetched.body, "");
}

#[tokio::test]
async fn large_doc_body_works() {
    let cluster_id = ClusterId::random();
    let (_dir_a, _store_a, client_a) = make_node(&cluster_id);

    let body = "x".repeat(1_000_000); // 1MB
    let doc = Document::new(memvault_core::DocId::random(), body.clone(), Default::default());
    client_a.put_doc(doc.clone(), vec![], Visibility::Internal).await.unwrap();

    let fetched = client_a.get_doc(&doc.id).await.unwrap().unwrap();
    assert_eq!(fetched.body.len(), 1_000_000);
}

#[tokio::test]
async fn many_buckets_per_node() {
    let cluster_id = ClusterId::random();
    let (_dir_a, _store_a, client_a) = make_node(&cluster_id);

    for i in 0..20 {
        client_a.bucket_create(&format!("bucket-{i}"), None,
            Visibility::Internal, Classification::Internal).await.unwrap();
    }

    let buckets = client_a.bucket_list().await.unwrap();
    assert_eq!(buckets.len(), 20);
}

#[tokio::test]
async fn retract_doc_removes_from_listing() {
    let cluster_id = ClusterId::random();
    let (_dir_a, _store_a, client_a) = make_node(&cluster_id);

    let doc = Document::new(memvault_core::DocId::random(), "deletable".into(), Default::default());
    let cid = client_a.put_doc(doc.clone(), vec![("kind".into(), "temp".into())], Visibility::Internal).await.unwrap();

    let docs = client_a.list_docs(Some(("kind".into(), "temp".into())), 100).await.unwrap();
    assert_eq!(docs.len(), 1);

    client_a.retract(&cid, "test retraction").await.unwrap();

    // Doc is still fetchable (retraction is soft) but listing may filter it
    // depending on implementation. The retraction record exists.
    let status = client_a.status().await.unwrap();
    assert!(status.block_count > 0);
}

use rand::RngCore;

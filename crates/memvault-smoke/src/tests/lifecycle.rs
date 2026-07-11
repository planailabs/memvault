//! End-to-end lifecycle smoke tests covering full workflows.

use memvault_api::MemvaultClient;
use memvault_core::classification::Classification;
use memvault_core::{DocId, EdgeId, EntityId, NodeRef, Visibility};
use memvault_doc::{BucketRole, Document, Edge, Entity};
use std::collections::BTreeMap;

use crate::harness::TestNode;

#[tokio::test]
async fn full_genesis_workflow() {
    let node = TestNode::new();

    // Genesis: create default bucket
    let bucket = node
        .client
        .bucket_create(
            "default",
            None,
            Visibility::Internal,
            Classification::Internal,
            BucketRole::Standard,
        )
        .await
        .unwrap();
    node.store
        .bind_bucket(&bucket.0, &node.cluster_id.0)
        .unwrap();

    // Create docs
    for i in 0..10 {
        let doc = Document::new(DocId::random(), format!("Note #{i}"), Default::default());
        node.client
            .put_doc(
                doc,
                vec![("kind".into(), "note".into())],
                Visibility::Internal,
                Some(&bucket),
            )
            .await
            .unwrap();
    }

    // Create entities
    for name in ["Alice", "Bob", "Charlie"] {
        let mut props = BTreeMap::new();
        props.insert("name".to_string(), serde_json::json!(name));
        let e = Entity {
            id: EntityId::random(),
            kind: "person".into(),
            props,
            edges_out: vec![],
        };
        node.client
            .add_entity(e, Visibility::Internal, Some(&bucket))
            .await
            .unwrap();
    }

    // Verify counts
    let status = node.client.status().await.unwrap();
    assert_eq!(status.doc_count, 10);
    assert!(status.block_count >= 10);

    let entities = node.client.list_entities(100, None).await.unwrap();
    assert_eq!(entities.len(), 3);

    let buckets = node.client.bucket_list().await.unwrap();
    assert_eq!(buckets.len(), 1);
    assert!(buckets[0].cluster_id.is_some());
}

#[tokio::test]
async fn two_node_independent_workflow() {
    let (node_a, node_b) = TestNode::cluster_pair();

    // Node A: genesis
    let bucket_a = node_a
        .client
        .bucket_create(
            "default",
            None,
            Visibility::Internal,
            Classification::Internal,
            BucketRole::Standard,
        )
        .await
        .unwrap();
    node_a
        .store
        .bind_bucket(&bucket_a.0, &node_a.cluster_id.0)
        .unwrap();

    // Node B: cluster-join
    let bucket_b = node_b
        .client
        .bucket_create(
            "default",
            None,
            Visibility::Internal,
            Classification::Internal,
            BucketRole::Standard,
        )
        .await
        .unwrap();
    node_b
        .store
        .bind_bucket(&bucket_b.0, &node_b.cluster_id.0)
        .unwrap();

    // Node A writes docs
    for i in 0..20 {
        let doc = Document::new(DocId::random(), format!("A-{i}"), Default::default());
        node_a
            .client
            .put_doc(
                doc,
                vec![("source".into(), "a".into())],
                Visibility::Internal,
                Some(&bucket_a),
            )
            .await
            .unwrap();
    }

    // Node B writes docs
    for i in 0..15 {
        let doc = Document::new(DocId::random(), format!("B-{i}"), Default::default());
        node_b
            .client
            .put_doc(
                doc,
                vec![("source".into(), "b".into())],
                Visibility::Internal,
                Some(&bucket_b),
            )
            .await
            .unwrap();
    }

    // Verify isolation
    assert_eq!(node_a.client.status().await.unwrap().doc_count, 20);
    assert_eq!(node_b.client.status().await.unwrap().doc_count, 15);

    // Node A issues tokens
    let token = node_a
        .client
        .issue_token(
            memvault_auth::TokenRole::Agent(memvault_auth::AgentRole::AgentHost),
            3600,
            5,
            Some("shared".into()),
        )
        .await
        .unwrap();
    assert!(token.starts_with("mvjoin1:"));
}

#[tokio::test]
async fn bucket_lifecycle_full() {
    let node = TestNode::new();

    // Create
    let id = node
        .client
        .bucket_create(
            "lifecycle",
            Some("full test"),
            Visibility::Federated,
            Classification::Internal,
            BucketRole::Standard,
        )
        .await
        .unwrap();

    // Auto-attached and auto-bound since node has a cluster
    let info = node.client.bucket_get(&id).await.unwrap().unwrap();
    assert!(info.is_attached);
    assert_eq!(info.cluster_id, Some(node.cluster_id.clone()));

    // Attach again (idempotent)
    node.client.bucket_attach(&id).await.unwrap();
    let info = node.client.bucket_get(&id).await.unwrap().unwrap();
    assert!(info.is_attached);

    // Rename
    node.client
        .bucket_rename(&id, "renamed-lifecycle")
        .await
        .unwrap();
    let info = node.client.bucket_get(&id).await.unwrap().unwrap();
    assert_eq!(info.name, "renamed-lifecycle");

    // Archive
    node.client
        .bucket_archive(&id, "test complete")
        .await
        .unwrap();
    let info = node.client.bucket_get(&id).await.unwrap().unwrap();
    assert!(info.name.contains("[ARCHIVED]"));
}

#[tokio::test]
async fn knowledge_graph_workflow() {
    let node = TestNode::new();

    // Create entities
    let mut alice_props = BTreeMap::new();
    alice_props.insert("name".to_string(), serde_json::json!("Alice"));
    alice_props.insert("role".to_string(), serde_json::json!("engineer"));
    let alice = Entity {
        id: EntityId::random(),
        kind: "person".into(),
        props: alice_props,
        edges_out: vec![],
    };
    let alice_id = node
        .client
        .add_entity(alice, Visibility::Internal, None)
        .await
        .unwrap();

    let mut rust_props = BTreeMap::new();
    rust_props.insert("name".to_string(), serde_json::json!("Rust"));
    let rust = Entity {
        id: EntityId::random(),
        kind: "language".into(),
        props: rust_props,
        edges_out: vec![],
    };
    let rust_id = node
        .client
        .add_entity(rust, Visibility::Internal, None)
        .await
        .unwrap();

    let mut project_props = BTreeMap::new();
    project_props.insert("name".to_string(), serde_json::json!("memvault"));
    let project = Entity {
        id: EntityId::random(),
        kind: "project".into(),
        props: project_props,
        edges_out: vec![],
    };
    let project_id = node
        .client
        .add_entity(project, Visibility::Internal, None)
        .await
        .unwrap();

    // Link: Alice --works_on--> memvault
    let edge1 = Edge {
        id: EdgeId::random(),
        target: NodeRef::Entity(project_id.clone()),
        relation: "works_on".into(),
        weight: Some(1.0),
        provenance: None,
        props: Default::default(),
    };
    node.client
        .add_link(
            &NodeRef::Entity(alice_id.clone()),
            edge1,
            Visibility::Internal,
        )
        .await
        .unwrap();

    // Link: memvault --written_in--> Rust
    let edge2 = Edge {
        id: EdgeId::random(),
        target: NodeRef::Entity(rust_id.clone()),
        relation: "written_in".into(),
        weight: Some(1.0),
        provenance: None,
        props: Default::default(),
    };
    node.client
        .add_link(
            &NodeRef::Entity(project_id.clone()),
            edge2,
            Visibility::Internal,
        )
        .await
        .unwrap();

    // Traverse: Alice → works_on → memvault
    let hits = node
        .client
        .traverse_from(&NodeRef::Entity(alice_id.clone()), Some("works_on"), 1)
        .await
        .unwrap();
    assert!(!hits.is_empty());

    // Edges of project
    let edges = node
        .client
        .edges_of(&NodeRef::Entity(project_id))
        .await
        .unwrap();
    assert!(!edges.is_empty());
}

#[tokio::test]
async fn tags_workflow() {
    let node = TestNode::new();
    let doc = Document::new(DocId::random(), "taggable".into(), Default::default());
    node.client
        .put_doc(
            doc.clone(),
            vec![("initial".into(), "tag".into())],
            Visibility::Internal,
            None,
        )
        .await
        .unwrap();

    let node_id = format!("doc:{}", hex::encode(doc.id.0));

    // Add tags
    node.client
        .add_tags(
            &node_id,
            vec![
                ("priority".into(), "high".into()),
                ("status".into(), "review".into()),
            ],
        )
        .await
        .unwrap();

    // Get tags
    let tags = node.client.get_tags(&node_id).await.unwrap();
    assert!(tags.len() >= 2);

    // Remove a tag
    node.client
        .remove_tags(&node_id, vec![("status".into(), "review".into())])
        .await
        .unwrap();

    let tags = node.client.get_tags(&node_id).await.unwrap();
    assert!(!tags.contains(&("status".to_string(), "review".to_string())));
}

#[tokio::test]
async fn retraction_workflow() {
    let node = TestNode::new();
    let doc = Document::new(DocId::random(), "retractable".into(), Default::default());
    let cid = node
        .client
        .put_doc(doc.clone(), vec![], Visibility::Internal, None)
        .await
        .unwrap();

    // Retract
    let tombstone = node
        .client
        .retract(&cid, "published by mistake")
        .await
        .unwrap();
    assert!(!tombstone.is_empty());

    // Retract by node_id
    let doc2 = Document::new(
        DocId::random(),
        "also retractable".into(),
        Default::default(),
    );
    node.client
        .put_doc(doc2.clone(), vec![], Visibility::Internal, None)
        .await
        .unwrap();
    let node_id = format!("doc:{}", hex::encode(doc2.id.0));
    node.client.retract_node(&node_id, "cleanup").await.unwrap();
}

#[tokio::test]
async fn auditor_bypasses_retraction() {
    let node = TestNode::new();
    let doc = Document::new(
        DocId::random(),
        "secret then retracted".into(),
        Default::default(),
    );
    let id = doc.id.clone();
    node.client
        .put_doc(doc, vec![], Visibility::Internal, None)
        .await
        .unwrap();

    let node_id = format!("doc:{}", hex::encode(id.0));
    node.client.retract_node(&node_id, "mistake").await.unwrap();

    // Default (filtered) view: the retracted doc is hidden.
    assert!(
        node.client.get_doc(&id).await.unwrap().is_none(),
        "retracted doc should be hidden from the default view"
    );
    let listed = node.client.list_docs(None, 100, None).await.unwrap();
    assert!(
        !listed.iter().any(|d| d.id == id),
        "retracted doc should not appear in the default list"
    );

    // Auditor/admin bypass (include_retracted = true): the doc reappears.
    assert!(
        node.client
            .get_doc_scoped(
                &id,
                &memvault_core::QueryScope::all().with_include_retracted(true)
            )
            .await
            .unwrap()
            .is_some(),
        "include_retracted should surface the retracted doc"
    );
    let listed_ex = node
        .client
        .list_docs_ex(None, 100, None, true)
        .await
        .unwrap();
    assert!(
        listed_ex.iter().any(|d| d.id == id),
        "include_retracted should include the retracted doc in the list"
    );
}

#[tokio::test]
async fn status_counts_accurate() {
    let node = TestNode::new();

    let s0 = node.client.status().await.unwrap();
    assert_eq!(s0.doc_count, 0);

    for i in 0..7 {
        let doc = Document::new(DocId::random(), format!("doc-{i}"), Default::default());
        node.client
            .put_doc(doc, vec![], Visibility::Internal, None)
            .await
            .unwrap();
    }

    let s1 = node.client.status().await.unwrap();
    assert_eq!(s1.doc_count, 7);
    assert!(s1.block_count >= 7);
    // Sanity bound only: uptime is a small, sane number (not a unix timestamp
    // or garbage), not a tight timing assertion — under heavy parallel test
    // load this node's wall-clock lifetime can exceed a minute even though its
    // own work is trivial.
    assert!(s1.uptime_secs < 3600);
}

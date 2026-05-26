//! Document operation smoke tests.

use memvault_api::MemvaultClient;
use memvault_core::{DocId, Visibility};
use memvault_doc::Document;

use crate::harness::TestNode;

#[tokio::test]
async fn create_and_get_doc() {
    let node = TestNode::new();
    let doc = Document::new(DocId::random(), "Hello!".into(), Default::default());
    node.client.put_doc(doc.clone(), vec![], Visibility::Internal, None).await.unwrap();
    let fetched = node.client.get_doc(&doc.id).await.unwrap().unwrap();
    assert_eq!(fetched.body, "Hello!");
}

#[tokio::test]
async fn get_nonexistent_doc() {
    let node = TestNode::new();
    assert!(node.client.get_doc(&DocId::random()).await.unwrap().is_none());
}

#[tokio::test]
async fn create_doc_with_tags() {
    let node = TestNode::new();
    let doc = Document::new(DocId::random(), "tagged".into(), Default::default());
    let tags = vec![("topic".into(), "rust".into()), ("priority".into(), "high".into())];
    node.client.put_doc(doc.clone(), tags, Visibility::Internal, None).await.unwrap();
    let docs = node.client.list_docs(Some(("topic".into(), "rust".into())), 100, None).await.unwrap();
    assert_eq!(docs.len(), 1);
}

#[tokio::test]
async fn list_docs_by_tag() {
    let node = TestNode::new();
    for i in 0..5 {
        let doc = Document::new(DocId::random(), format!("doc-{i}"), Default::default());
        node.client.put_doc(doc, vec![("batch".into(), "alpha".into())], Visibility::Internal, None).await.unwrap();
    }
    for i in 0..3 {
        let doc = Document::new(DocId::random(), format!("other-{i}"), Default::default());
        node.client.put_doc(doc, vec![("batch".into(), "beta".into())], Visibility::Internal, None).await.unwrap();
    }
    let alpha = node.client.list_docs(Some(("batch".into(), "alpha".into())), 100, None).await.unwrap();
    let beta = node.client.list_docs(Some(("batch".into(), "beta".into())), 100, None).await.unwrap();
    assert_eq!(alpha.len(), 5);
    assert_eq!(beta.len(), 3);
}

#[tokio::test]
async fn list_all_docs() {
    let node = TestNode::new();
    for i in 0..7 {
        let doc = Document::new(DocId::random(), format!("all-{i}"), Default::default());
        node.client.put_doc(doc, vec![], Visibility::Internal, None).await.unwrap();
    }
    let all = node.client.list_docs(None, 100, None).await.unwrap();
    assert_eq!(all.len(), 7);
}

#[tokio::test]
async fn empty_doc_body() {
    let node = TestNode::new();
    let doc = Document::new(DocId::random(), "".into(), Default::default());
    node.client.put_doc(doc.clone(), vec![], Visibility::Internal, None).await.unwrap();
    let fetched = node.client.get_doc(&doc.id).await.unwrap().unwrap();
    assert_eq!(fetched.body, "");
}

#[tokio::test]
async fn large_doc_body() {
    let node = TestNode::new();
    let body = "x".repeat(500_000);
    let doc = Document::new(DocId::random(), body.clone(), Default::default());
    node.client.put_doc(doc.clone(), vec![], Visibility::Internal, None).await.unwrap();
    let fetched = node.client.get_doc(&doc.id).await.unwrap().unwrap();
    assert_eq!(fetched.body.len(), 500_000);
}

#[tokio::test]
async fn doc_with_frontmatter() {
    let node = TestNode::new();
    let mut fm = std::collections::BTreeMap::new();
    fm.insert("title".to_string(), serde_json::json!("My Title"));
    fm.insert("author".to_string(), serde_json::json!("Alice"));
    let doc = Document::new(DocId::random(), "content".into(), fm);
    node.client.put_doc(doc.clone(), vec![], Visibility::Internal, None).await.unwrap();
    let fetched = node.client.get_doc(&doc.id).await.unwrap().unwrap();
    assert_eq!(fetched.frontmatter["title"], "My Title");
}

#[tokio::test]
async fn doc_visibility_internal() {
    let node = TestNode::new();
    let doc = Document::new(DocId::random(), "internal".into(), Default::default());
    node.client.put_doc(doc.clone(), vec![], Visibility::Internal, None).await.unwrap();
    let fetched = node.client.get_doc(&doc.id).await.unwrap().unwrap();
    assert_eq!(fetched.body, "internal");
}

#[tokio::test]
async fn doc_visibility_federated() {
    let node = TestNode::new();
    let doc = Document::new(DocId::random(), "federated".into(), Default::default());
    node.client.put_doc(doc.clone(), vec![], Visibility::Federated, None).await.unwrap();
    assert!(node.client.get_doc(&doc.id).await.unwrap().is_some());
}

#[tokio::test]
async fn doc_visibility_public() {
    let node = TestNode::new();
    let doc = Document::new(DocId::random(), "public".into(), Default::default());
    node.client.put_doc(doc.clone(), vec![], Visibility::Public, None).await.unwrap();
    assert!(node.client.get_doc(&doc.id).await.unwrap().is_some());
}

#[tokio::test]
async fn retract_doc() {
    let node = TestNode::new();
    let doc = Document::new(DocId::random(), "retractable".into(), Default::default());
    let cid = node.client.put_doc(doc.clone(), vec![], Visibility::Internal, None).await.unwrap();
    node.client.retract(&cid, "mistake").await.unwrap();
}

#[tokio::test]
async fn doc_history() {
    let node = TestNode::new();
    let doc = Document::new(DocId::random(), "versioned".into(), Default::default());
    node.client.put_doc(doc.clone(), vec![], Visibility::Internal, None).await.unwrap();
    let history = node.client.history_of(&doc.id).await.unwrap();
    assert!(!history.is_empty());
}

#[tokio::test]
async fn two_nodes_docs_isolated() {
    let (node_a, node_b) = TestNode::cluster_pair();
    let doc_a = Document::new(DocId::random(), "from A".into(), Default::default());
    let doc_b = Document::new(DocId::random(), "from B".into(), Default::default());
    node_a.client.put_doc(doc_a.clone(), vec![], Visibility::Internal, None).await.unwrap();
    node_b.client.put_doc(doc_b.clone(), vec![], Visibility::Internal, None).await.unwrap();
    assert!(node_a.client.get_doc(&doc_b.id).await.unwrap().is_none());
    assert!(node_b.client.get_doc(&doc_a.id).await.unwrap().is_none());
}

#[tokio::test]
async fn create_100_docs() {
    let node = TestNode::new();
    for i in 0..100 {
        let doc = Document::new(DocId::random(), format!("bulk-{i}"), Default::default());
        node.client.put_doc(doc, vec![("bulk".into(), "yes".into())], Visibility::Internal, None).await.unwrap();
    }
    let docs = node.client.list_docs(Some(("bulk".into(), "yes".into())), 200, None).await.unwrap();
    assert_eq!(docs.len(), 100);
}

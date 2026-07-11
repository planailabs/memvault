//! Smoke tests for the document-link extractor → reconciler → graph-edge
//! pipeline. Exercises the happy path (two-doc backlink), edit-removes-link,
//! alias resolution, and pending alias promotion.

use std::collections::BTreeMap;

use memvault_api::MemvaultClient;
use memvault_core::{DocId, NodeRef, Visibility};
use memvault_doc::Document;

use crate::harness::TestNode;

fn link_provenance(edge: &memvault_doc::Edge) -> Option<String> {
    edge.props
        .get("provenance")
        .and_then(|v| v.as_str())
        .map(String::from)
}

fn body_edge_targets(edges: &[(NodeRef, memvault_doc::Edge)]) -> Vec<NodeRef> {
    edges
        .iter()
        .filter(|(_, e)| link_provenance(e).as_deref() == Some("body_markdown"))
        .map(|(_, e)| e.target.clone())
        .collect()
}

#[tokio::test]
async fn cache_annotation_populated_for_doc_body() {
    let node = TestNode::new();
    let body = "[[doc:abcd1234567890abcdef1234567890abcdef1234567890abcdef1234567890ab]]";
    let source_doc = Document::new(DocId::random(), body.into(), Default::default());
    node.client
        .put_doc(source_doc.clone(), vec![], Visibility::Internal, None)
        .await
        .unwrap();

    // The latest doc head should have an extraction annotation with links.
    assert!(node.client.latest_doc_head_cid(&source_doc.id).is_some());
    let links = node.client.doc_outlinks(&source_doc.id);
    assert_eq!(links.len(), 1, "expected one cached extracted link");
}

#[tokio::test]
async fn wikilink_creates_body_provenance_edge() {
    let node = TestNode::new();

    let target_doc = Document::new(
        DocId::random(),
        "I am the target".into(),
        Default::default(),
    );
    node.client
        .put_doc(target_doc.clone(), vec![], Visibility::Internal, None)
        .await
        .unwrap();

    let body = format!(
        "See [[doc:{}]] for the answer.",
        hex::encode(target_doc.id.0)
    );
    let source_doc = Document::new(DocId::random(), body, Default::default());
    node.client
        .put_doc(source_doc.clone(), vec![], Visibility::Internal, None)
        .await
        .unwrap();

    let edges = node
        .client
        .edges_of(&NodeRef::Doc(source_doc.id.clone()))
        .await
        .unwrap();
    let body_edges: Vec<_> = edges
        .iter()
        .filter(|(s, _)| *s == NodeRef::Doc(source_doc.id.clone()))
        .filter(|(_, e)| link_provenance(e).as_deref() == Some("body_markdown"))
        .collect();
    assert_eq!(body_edges.len(), 1, "expected one body-extracted edge");
    assert_eq!(body_edges[0].1.target, NodeRef::Doc(target_doc.id.clone()));
    assert_eq!(body_edges[0].1.relation, "mentions");
}

#[tokio::test]
async fn backlink_visible_from_target() {
    let node = TestNode::new();
    let target_doc = Document::new(DocId::random(), "target".into(), Default::default());
    node.client
        .put_doc(target_doc.clone(), vec![], Visibility::Internal, None)
        .await
        .unwrap();

    let source_doc = Document::new(
        DocId::random(),
        format!("link to [[doc:{}]]", hex::encode(target_doc.id.0)),
        Default::default(),
    );
    node.client
        .put_doc(source_doc.clone(), vec![], Visibility::Internal, None)
        .await
        .unwrap();

    let backs = node
        .client
        .edges_of(&NodeRef::Doc(target_doc.id.clone()))
        .await
        .unwrap();
    let body_backs: Vec<_> = backs
        .iter()
        .filter(|(_, e)| {
            e.target == NodeRef::Doc(target_doc.id.clone())
                && link_provenance(e).as_deref() == Some("body_markdown")
        })
        .collect();
    assert_eq!(body_backs.len(), 1);
    assert_eq!(body_backs[0].0, NodeRef::Doc(source_doc.id.clone()));
}

#[tokio::test]
async fn dangling_alias_emits_pending_edge() {
    let node = TestNode::new();
    let body = "I refer to [[Alice]] but Alice does not exist.";
    let source_doc = Document::new(DocId::random(), body.into(), Default::default());
    node.client
        .put_doc(source_doc.clone(), vec![], Visibility::Internal, None)
        .await
        .unwrap();

    let edges = node
        .client
        .edges_of(&NodeRef::Doc(source_doc.id.clone()))
        .await
        .unwrap();
    let pending: Vec<_> = edges
        .iter()
        .filter(|(s, _)| *s == NodeRef::Doc(source_doc.id.clone()))
        .filter(|(_, e)| e.props.get("pending_alias").and_then(|v| v.as_str()) == Some("Alice"))
        .collect();
    assert_eq!(pending.len(), 1, "expected a single pending alias edge");
}

#[tokio::test]
async fn alias_resolves_when_target_has_alias_in_frontmatter() {
    let node = TestNode::new();

    let mut fm = BTreeMap::new();
    fm.insert("title".to_string(), serde_json::Value::String("Bob".into()));
    let target_doc = Document::new(DocId::random(), "I am Bob".into(), fm);
    node.client
        .put_doc(target_doc.clone(), vec![], Visibility::Internal, None)
        .await
        .unwrap();

    let source_doc = Document::new(
        DocId::random(),
        "Tell [[Bob]] I said hi.".into(),
        Default::default(),
    );
    node.client
        .put_doc(source_doc.clone(), vec![], Visibility::Internal, None)
        .await
        .unwrap();

    let edges = node
        .client
        .edges_of(&NodeRef::Doc(source_doc.id.clone()))
        .await
        .unwrap();
    let resolved: Vec<_> = edges
        .iter()
        .filter(|(s, _)| *s == NodeRef::Doc(source_doc.id.clone()))
        .filter(|(_, e)| link_provenance(e).as_deref() == Some("body_markdown"))
        .collect();
    assert_eq!(resolved.len(), 1);
    assert_eq!(resolved[0].1.target, NodeRef::Doc(target_doc.id.clone()));
    assert!(
        resolved[0].1.props.get("pending_alias").is_none(),
        "edge should not be pending once alias resolves"
    );
}

#[tokio::test]
async fn relation_demoted_when_outside_allowlist() {
    let node = TestNode::new();
    let target_doc = Document::new(DocId::random(), "t".into(), Default::default());
    node.client
        .put_doc(target_doc.clone(), vec![], Visibility::Internal, None)
        .await
        .unwrap();

    let body = format!(
        "[link](memvault://doc/{}?rel=super-secret)",
        hex::encode(target_doc.id.0)
    );
    let source_doc = Document::new(DocId::random(), body, Default::default());
    node.client
        .put_doc(source_doc.clone(), vec![], Visibility::Internal, None)
        .await
        .unwrap();

    let edges = node
        .client
        .edges_of(&NodeRef::Doc(source_doc.id.clone()))
        .await
        .unwrap();
    let body_edge = edges
        .iter()
        .find(|(s, e)| {
            *s == NodeRef::Doc(source_doc.id.clone())
                && link_provenance(e).as_deref() == Some("body_markdown")
        })
        .expect("expected body-provenance edge");
    assert_eq!(body_edge.1.relation, "mentions");
}

#[tokio::test]
async fn allowlisted_relation_kept() {
    let node = TestNode::new();
    let target_doc = Document::new(DocId::random(), "t".into(), Default::default());
    node.client
        .put_doc(target_doc.clone(), vec![], Visibility::Internal, None)
        .await
        .unwrap();

    let body = format!(
        "[citation](memvault://doc/{}?rel=cites)",
        hex::encode(target_doc.id.0)
    );
    let source_doc = Document::new(DocId::random(), body, Default::default());
    node.client
        .put_doc(source_doc.clone(), vec![], Visibility::Internal, None)
        .await
        .unwrap();

    let edges = node
        .client
        .edges_of(&NodeRef::Doc(source_doc.id.clone()))
        .await
        .unwrap();
    let body_edge = edges
        .iter()
        .find(|(s, e)| {
            *s == NodeRef::Doc(source_doc.id.clone())
                && link_provenance(e).as_deref() == Some("body_markdown")
        })
        .expect("expected body-provenance edge");
    assert_eq!(body_edge.1.relation, "cites");
}

#[tokio::test]
async fn reindex_idempotent() {
    let node = TestNode::new();
    let target_doc = Document::new(DocId::random(), "t".into(), Default::default());
    node.client
        .put_doc(target_doc.clone(), vec![], Visibility::Internal, None)
        .await
        .unwrap();

    let body = format!("[[doc:{}]]", hex::encode(target_doc.id.0));
    let source_doc = Document::new(DocId::random(), body, Default::default());
    node.client
        .put_doc(source_doc.clone(), vec![], Visibility::Internal, None)
        .await
        .unwrap();

    let before = node
        .client
        .edges_of(&NodeRef::Doc(source_doc.id.clone()))
        .await
        .unwrap();
    let before_targets = body_edge_targets(&before);
    assert_eq!(before_targets.len(), 1);

    // Reindex this doc — should produce no new edges (idempotent).
    node.client.reindex_doc_links(&source_doc.id).await.unwrap();

    let after = node
        .client
        .edges_of(&NodeRef::Doc(source_doc.id.clone()))
        .await
        .unwrap();
    let after_targets = body_edge_targets(&after);
    assert_eq!(after_targets, before_targets);
}

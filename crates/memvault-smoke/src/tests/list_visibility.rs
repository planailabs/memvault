//! Regression tests for the empty-list bug: docs/files/entities must
//! appear in `list_*` and `audit` queries after they're created. Each
//! test creates one or more objects through the LocalClient and then
//! immediately asserts the standard list/discovery paths return them.

use memvault_api::MemvaultClient;
use memvault_core::{DocId, Visibility};
use memvault_doc::{Document, Entity};
use memvault_query::{AuditQuery, OpKind};

use crate::harness::TestNode;

#[tokio::test]
async fn list_docs_returns_created_doc() {
    let node = TestNode::new();
    let doc = Document::new(DocId::random(), "hello".into(), Default::default());
    node.client
        .put_doc(doc.clone(), vec![], Visibility::Internal, None)
        .await
        .unwrap();

    let docs = node.client.list_docs(None, 100, None).await.unwrap();
    assert!(
        docs.iter().any(|d| d.id == doc.id),
        "list_docs returned {} docs but the just-created doc wasn't among them",
        docs.len()
    );
}

#[tokio::test]
async fn list_entities_returns_created_entity() {
    let node = TestNode::new();
    let entity = Entity {
        id: memvault_core::EntityId::random(),
        kind: "person".into(),
        props: Default::default(),
        edges_out: vec![],
    };
    let eid = node
        .client
        .add_entity(entity.clone(), Visibility::Internal, None)
        .await
        .unwrap();

    let entities = node.client.list_entities(100, None).await.unwrap();
    assert!(
        entities.iter().any(|e| e.id == eid),
        "list_entities returned {} entities but the just-created entity wasn't among them",
        entities.len()
    );
}

#[tokio::test]
async fn audit_lists_attachfile_op_for_uploaded_file() {
    let node = TestNode::new();
    let cid = node
        .client
        .upload_file(
            b"hello world",
            Some("hello.txt"),
            "text/plain",
            vec![],
            "internal",
            None,
        )
        .await
        .unwrap();

    let attach_records = node
        .client
        .audit(AuditQuery {
            op_kind: Some(OpKind::AttachFile),
            limit: Some(100),
            ..Default::default()
        })
        .await
        .unwrap();
    assert!(
        attach_records
            .iter()
            .any(|r| r.attachment_cid.as_deref() == Some(&cid[..])),
        "audit query for AttachFile returned {} records but missed the just-uploaded file (cid={})",
        attach_records.len(),
        hex::encode(&cid),
    );
}

#[tokio::test]
async fn audit_distinguishes_extraction_annotation_from_unknown() {
    // Doc with a wikilink triggers the extractor pipeline → cached
    // extraction annotation. Audit must classify it as Extraction, not
    // Other("unknown"), so downstream UI filters work.
    let node = TestNode::new();
    let target_doc = Document::new(DocId::random(), "target".into(), Default::default());
    node.client
        .put_doc(target_doc.clone(), vec![], Visibility::Internal, None)
        .await
        .unwrap();

    let body = format!("see [[doc:{}]]", hex::encode(target_doc.id.0));
    let src_doc = Document::new(DocId::random(), body, Default::default());
    node.client
        .put_doc(src_doc.clone(), vec![], Visibility::Internal, None)
        .await
        .unwrap();

    let records = node
        .client
        .audit(AuditQuery {
            limit: Some(500),
            ..Default::default()
        })
        .await
        .unwrap();
    let unknowns: Vec<_> = records
        .iter()
        .filter(|r| matches!(&r.op_kind, OpKind::Other(s) if s == "unknown"))
        .collect();
    assert!(
        unknowns.is_empty(),
        "audit returned {} envelopes classified as Other(\"unknown\"); the parser is missing a branch",
        unknowns.len()
    );
}

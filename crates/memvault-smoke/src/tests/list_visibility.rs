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
async fn file_manifest_round_trips_metadata() {
    // The files page reads file rows by fetching the manifest block and
    // pulling filename / mime_type / content_size out. Manifests are
    // CBOR-encoded today, so a JSON-only parser would silently return
    // defaults — "unnamed" / "application/octet-stream" / 0. Make sure
    // the round-trip preserves the real values through the canonical
    // deserialize helper.
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

    let bytes = node
        .client
        .get_file_manifest(&cid)
        .await
        .unwrap()
        .expect("manifest block should exist after upload");
    let manifest: serde_json::Value = memvault_store::deserialize_block(&bytes)
        .expect("manifest must decode via the canonical helper");
    assert_eq!(
        manifest.get("filename").and_then(|v| v.as_str()),
        Some("hello.txt"),
        "filename missing from decoded manifest: {manifest}"
    );
    assert_eq!(
        manifest.get("mime_type").and_then(|v| v.as_str()),
        Some("text/plain"),
        "mime_type missing from decoded manifest: {manifest}"
    );
    assert_eq!(
        manifest.get("content_size").and_then(|v| v.as_u64()),
        Some(b"hello world".len() as u64),
        "content_size missing from decoded manifest: {manifest}"
    );
}

#[tokio::test]
async fn audit_edge_add_tags_round_trip() {
    // Signed<T>.tags is serialized as `[{scope, label}, …]`; AuditRecord
    // exposes them as `Vec<(String, String)>`. The audit UI uses
    // `edge_source` / `edge_target` tags to render EdgeAdd rows as
    // "Linked X → Y", so if the conversion drops them we get "? → ?".
    let node = TestNode::new();
    let entity_src = Entity {
        id: memvault_core::EntityId::random(),
        kind: "person".into(),
        props: Default::default(),
        edges_out: vec![],
    };
    let entity_tgt = Entity {
        id: memvault_core::EntityId::random(),
        kind: "service".into(),
        props: Default::default(),
        edges_out: vec![],
    };
    let src_id = node
        .client
        .add_entity(entity_src.clone(), Visibility::Internal, None)
        .await
        .unwrap();
    let tgt_id = node
        .client
        .add_entity(entity_tgt.clone(), Visibility::Internal, None)
        .await
        .unwrap();

    let edge = memvault_doc::Edge {
        id: memvault_core::EdgeId::random(),
        relation: "works_with".into(),
        target: memvault_core::NodeRef::Entity(tgt_id.clone()),
        weight: None,
        props: Default::default(),
        provenance: None,
    };
    node.client
        .add_link(
            &memvault_core::NodeRef::Entity(src_id.clone()),
            edge,
            Visibility::Internal,
        )
        .await
        .unwrap();

    let records = node
        .client
        .audit(AuditQuery {
            op_kind: Some(OpKind::EdgeAdd),
            limit: Some(100),
            ..Default::default()
        })
        .await
        .unwrap();
    let edge_record = records
        .iter()
        .find(|r| {
            r.tags
                .iter()
                .any(|(s, l)| s == "edge_source" && l.contains(&hex::encode(src_id.0)))
        })
        .expect("EdgeAdd audit record should carry edge_source/edge_target tags");
    assert!(
        edge_record
            .tags
            .iter()
            .any(|(s, l)| s == "edge_target" && l.contains(&hex::encode(tgt_id.0))),
        "edge_target tag missing on EdgeAdd audit record: tags={:?}",
        edge_record.tags
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

/// `limit` caps the *matching* records: an upload older than `limit` other
/// operations is still found by an `op_kind` query (the scan used to take
/// the newest `limit` records and filter those).
#[tokio::test]
async fn audit_kind_filter_applies_before_limit() {
    let node = TestNode::new();
    let cid = node
        .client
        .upload_file(
            b"old upload",
            Some("old.txt"),
            "text/plain",
            vec![],
            "internal",
            None,
        )
        .await
        .unwrap();
    for i in 0..10 {
        let doc = Document::new(DocId::random(), format!("newer {i}"), Default::default());
        node.client
            .put_doc(doc, vec![], Visibility::Internal, None)
            .await
            .unwrap();
    }

    let records = node
        .client
        .audit(AuditQuery {
            op_kind: Some(OpKind::AttachFile),
            limit: Some(5),
            ..Default::default()
        })
        .await
        .unwrap();
    assert!(
        records
            .iter()
            .any(|r| r.attachment_cid.as_deref() == Some(&cid[..])),
        "AttachFile query (limit 5) missed the upload behind 10 newer docs: {records:?}"
    );
    assert!(records.iter().all(|r| r.op_kind == OpKind::AttachFile));
}

/// An author-filtered audit query is newest first like every other one
/// (it returned the author's *oldest* records and ignored `before_ns`).
#[tokio::test]
async fn audit_by_author_returns_newest_first() {
    let node = TestNode::new();
    let mut doc_ids = Vec::new();
    for i in 0..6 {
        let doc = Document::new(DocId::random(), format!("doc {i}"), Default::default());
        doc_ids.push(doc.id.clone());
        node.client
            .put_doc(doc, vec![], Visibility::Internal, None)
            .await
            .unwrap();
    }
    let newest = node
        .client
        .audit(AuditQuery {
            op_kind: Some(OpKind::DocCreate),
            limit: Some(1),
            ..Default::default()
        })
        .await
        .unwrap();
    let newest = newest.first().expect("a DocCreate record");
    assert_eq!(newest.doc_id.as_ref(), doc_ids.last());

    let by_author = node
        .client
        .audit(AuditQuery {
            author: Some(newest.author.clone()),
            op_kind: Some(OpKind::DocCreate),
            limit: Some(2),
            ..Default::default()
        })
        .await
        .unwrap();
    let got: Vec<_> = by_author.iter().filter_map(|r| r.doc_id.clone()).collect();
    assert_eq!(got, vec![doc_ids[5].clone(), doc_ids[4].clone()]);

    // `before_ns` bounds the author scan too.
    let older = node
        .client
        .audit(AuditQuery {
            author: Some(newest.author.clone()),
            op_kind: Some(OpKind::DocCreate),
            before_ns: Some(newest.wall_ns),
            limit: Some(1),
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(
        older.first().and_then(|r| r.doc_id.clone()),
        Some(doc_ids[4].clone())
    );
}

/// A document's history is found however many operations came after it
/// (it used to look only among the newest 100 operations of the vault).
#[tokio::test]
async fn history_of_finds_doc_behind_many_newer_ops() {
    let node = TestNode::new();
    let doc = Document::new(DocId::random(), "x".repeat(50_000), Default::default());
    node.client
        .put_doc(doc.clone(), vec![], Visibility::Internal, None)
        .await
        .unwrap();
    for i in 0..60 {
        let other = Document::new(DocId::random(), format!("later {i}"), Default::default());
        node.client
            .put_doc(other, vec![], Visibility::Internal, None)
            .await
            .unwrap();
    }
    let history = node.client.history_of(&doc.id).await.unwrap();
    assert!(
        history
            .iter()
            .any(|r| r.op_kind == OpKind::DocCreate && r.doc_id.as_ref() == Some(&doc.id)),
        "history_of missed the DocCreate: {history:?}"
    );
}

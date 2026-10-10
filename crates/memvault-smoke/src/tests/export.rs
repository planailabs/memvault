//! Export smoke tests — bucket scoping of the vault export.
//!
//! Regression shape: `memctl export --bucket-id <hex>` / the standalone
//! `memvault-export --bucket-id` must read *only* the named bucket. The export
//! planner used to drop the bucket and call `list_all(.., None)`, so an
//! explicitly scoped export silently fell back to the caller's agent bucket
//! and returned nothing for a bucket the caller had been granted access to
//! (the cross-bucket grant sync VM check). See standards/bucket-scoping.md.

use memvault_api::MemvaultClient;
use memvault_core::classification::Classification;
use memvault_core::{BucketId, BucketRole, DocId, Visibility};
use memvault_doc::Document;
use memvault_export::{ExportOptions, create_sink, run_export};

use crate::harness::TestNode;

async fn make_bucket(node: &TestNode, name: &str) -> BucketId {
    node.client
        .bucket_create(
            name,
            None,
            Visibility::Internal,
            Classification::Internal,
            BucketRole::Standard,
        )
        .await
        .unwrap()
}

/// Read every exported `documents/*.md` body under `dir`.
fn exported_doc_bodies(dir: &std::path::Path) -> Vec<String> {
    let mut out = Vec::new();
    let docs = dir.join("documents");
    if let Ok(entries) = std::fs::read_dir(&docs) {
        for entry in entries.flatten() {
            if entry.path().extension().and_then(|s| s.to_str()) == Some("md") {
                out.push(std::fs::read_to_string(entry.path()).unwrap());
            }
        }
    }
    out
}

/// A bucket-scoped export returns exactly the named bucket's documents and
/// never leaks another bucket's.
#[tokio::test]
async fn export_honours_explicit_bucket() {
    let node = TestNode::new();
    let alpha = make_bucket(&node, "alpha").await;
    let beta = make_bucket(&node, "beta").await;

    let doc_alpha = Document::new(
        DocId::random(),
        "in-bucket-alpha".into(),
        Default::default(),
    );
    node.client
        .put_doc(
            doc_alpha.clone(),
            vec![],
            Visibility::Internal,
            Some(&alpha),
        )
        .await
        .unwrap();
    let doc_beta = Document::new(DocId::random(), "in-bucket-beta".into(), Default::default());
    node.client
        .put_doc(doc_beta.clone(), vec![], Visibility::Internal, Some(&beta))
        .await
        .unwrap();

    let out = tempfile::tempdir().unwrap();
    let export_dir = out.path().join("exp");
    let sink = create_sink(&export_dir, false, false).unwrap();
    let opts = ExportOptions {
        bucket: Some(alpha),
        ..Default::default()
    };
    let stats = run_export(&node.client, sink, opts).await.unwrap();

    assert_eq!(
        stats.documents, 1,
        "a bucket-scoped export must return only the named bucket's documents"
    );

    let bodies = exported_doc_bodies(&export_dir);
    assert!(
        bodies.iter().any(|b| b.contains("in-bucket-alpha")),
        "the named bucket's document should be exported: {bodies:?}"
    );
    assert!(
        !bodies.iter().any(|b| b.contains("in-bucket-beta")),
        "a document from another bucket must not leak into a scoped export: {bodies:?}"
    );
}

/// An unscoped export (`bucket: None`) is unchanged from before the fix: the
/// LocalClient lists every accessible bucket, so both documents appear.
#[tokio::test]
async fn export_without_bucket_lists_accessible_buckets() {
    let node = TestNode::new();
    let alpha = make_bucket(&node, "alpha").await;
    let beta = make_bucket(&node, "beta").await;

    for (bucket, body) in [(&alpha, "in-bucket-alpha"), (&beta, "in-bucket-beta")] {
        let doc = Document::new(DocId::random(), body.into(), Default::default());
        node.client
            .put_doc(doc, vec![], Visibility::Internal, Some(bucket))
            .await
            .unwrap();
    }

    let out = tempfile::tempdir().unwrap();
    let export_dir = out.path().join("exp");
    let sink = create_sink(&export_dir, false, false).unwrap();
    let stats = run_export(&node.client, sink, ExportOptions::default())
        .await
        .unwrap();

    assert_eq!(
        stats.documents, 2,
        "an unscoped export lists every accessible bucket"
    );
}

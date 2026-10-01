//! View management smoke tests.

use memvault_api::MemvaultClient;
use memvault_api::types::View;

use crate::harness::TestNode;

#[tokio::test]
async fn create_view() {
    let node = TestNode::new();
    let view = View {
        name: "rust-notes".into(),
        tags: vec![("topic".into(), "rust".into())],
        created_ns: memvault_core::wall_ns(),
        cid: String::new(),
        bucket_id: None,
    };
    node.client.create_view(view).await.unwrap();
    let views = node.client.list_views().await.unwrap();
    assert_eq!(views.len(), 1);
    assert_eq!(views[0].name, "rust-notes");
}

#[tokio::test]
async fn delete_view() {
    let node = TestNode::new();
    let view = View {
        name: "temp".into(),
        tags: vec![],
        created_ns: memvault_core::wall_ns(),
        cid: String::new(),
        bucket_id: None,
    };
    node.client.create_view(view).await.unwrap();
    node.client.delete_view("temp").await.unwrap();
    let views = node.client.list_views().await.unwrap();
    assert!(views.is_empty());
}

#[tokio::test]
async fn get_view() {
    let node = TestNode::new();
    let view = View {
        name: "findable".into(),
        tags: vec![("a".into(), "b".into())],
        created_ns: memvault_core::wall_ns(),
        cid: String::new(),
        bucket_id: None,
    };
    node.client.create_view(view).await.unwrap();
    let found = node.client.get_view("findable").await.unwrap();
    assert!(found.is_some());
    assert_eq!(found.unwrap().tags, vec![("a".into(), "b".into())]);
}

#[tokio::test]
async fn update_view() {
    let node = TestNode::new();
    let view = View {
        name: "updatable".into(),
        tags: vec![("old".into(), "tag".into())],
        created_ns: memvault_core::wall_ns(),
        cid: String::new(),
        bucket_id: None,
    };
    node.client.create_view(view).await.unwrap();
    let updated = View {
        name: "updatable".into(),
        tags: vec![("new".into(), "tag".into())],
        created_ns: memvault_core::wall_ns(),
        cid: String::new(),
        bucket_id: None,
    };
    node.client.update_view(updated).await.unwrap();
    let found = node.client.get_view("updatable").await.unwrap().unwrap();
    assert_eq!(found.tags, vec![("new".into(), "tag".into())]);
}

#[tokio::test]
async fn multiple_views() {
    let node = TestNode::new();
    for name in ["alpha", "beta", "gamma"] {
        let view = View {
            name: name.into(),
            tags: vec![("kind".into(), name.into())],
            created_ns: memvault_core::wall_ns(),
            cid: String::new(),
            bucket_id: None,
        };
        node.client.create_view(view).await.unwrap();
    }
    assert_eq!(node.client.list_views().await.unwrap().len(), 3);
}

/// A view's filter tags are not tags of the view block: they must not show
/// up in tag lookups, and a synced copy must still be listed as a view
/// (the bare `View` block used to be indexed under its filter tags and
/// lost its `("view", …)` tag on sync and rebuild).
#[tokio::test]
async fn view_filter_tags_are_not_indexed_and_views_sync() {
    let a = TestNode::new();
    let view = View {
        name: "rusty".into(),
        tags: vec![("topic".into(), "rust".into())],
        created_ns: memvault_core::wall_ns(),
        cid: String::new(),
        bucket_id: None,
    };
    a.client.create_view(view).await.unwrap();
    assert!(
        a.store
            .query_by_tag("topic", "rust", 0, usize::MAX)
            .unwrap()
            .is_empty(),
        "the view's filter tag leaked into the tag index"
    );

    let b = TestNode::with_cluster(&a.cluster_id);
    let mut gate = memvault_api::admission::SyncGate::new(&b.store, a.cluster_id.0, None);
    for (cid, data) in a.store.iter_blocks().unwrap() {
        gate.admit(&cid, &data);
    }
    let views = b.client.list_views().await.unwrap();
    assert_eq!(views.len(), 1, "synced view is listed");
    assert_eq!(views[0].tags, vec![("topic".into(), "rust".into())]);
    assert!(
        b.store
            .query_by_tag("topic", "rust", 0, usize::MAX)
            .unwrap()
            .is_empty()
    );
}

/// Views stored by older builds (the bare `View` struct) still load, also
/// after a sync or rebuild, without their filter tags being indexed.
#[tokio::test]
async fn legacy_view_blocks_still_load() {
    let node = TestNode::new();
    // A view as older builds wrote it: the bare struct, its bucket id in the
    // byte-newtype form (a sequence of 32 numbers, before `View.bucket_id`
    // went hex).
    #[derive(serde::Serialize)]
    struct OldView {
        name: String,
        tags: Vec<(String, String)>,
        created_ns: u64,
        bucket_id: Option<memvault_core::BucketId>,
    }
    let bucket = memvault_core::BucketId([0x5a; 32]);
    let legacy = OldView {
        name: "old-view".into(),
        tags: vec![("project".into(), "x".into())],
        created_ns: 12345,
        bucket_id: Some(bucket.clone()),
    };
    let bytes = serde_ipld_dagcbor::to_vec(&legacy).unwrap();
    let cid = memvault_core::cid_from_bytes(&bytes).to_bytes();
    // As a synced copy arrives: no caller metadata.
    node.store
        .ingest_block(&cid, &bytes, &memvault_store::IngestMeta::default())
        .unwrap();
    let check = |views: Vec<View>| {
        assert_eq!(views.len(), 1);
        assert_eq!(views[0].name, "old-view");
        assert_eq!(views[0].bucket_id, Some(bucket.clone()));
        // The view's CID is a CID string (standards/api-wire-conventions.md).
        assert_eq!(views[0].cid, memvault_api::wire::cid_string(&cid));
    };
    check(node.client.list_views().await.unwrap());
    assert!(
        node.store
            .query_by_tag("project", "x", 0, usize::MAX)
            .unwrap()
            .is_empty()
    );
    memvault_api::rebuild::rebuild_store(&node.client).unwrap();
    check(node.client.list_views().await.unwrap());
}

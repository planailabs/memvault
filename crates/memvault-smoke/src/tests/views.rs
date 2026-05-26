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

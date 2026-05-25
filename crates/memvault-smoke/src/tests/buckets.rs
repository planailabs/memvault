//! Bucket lifecycle smoke tests.

use memvault_api::MemvaultClient;
use memvault_core::{BucketId, ClusterId, Visibility};
use memvault_core::classification::Classification;

use crate::harness::TestNode;

#[tokio::test]
async fn create_bucket() {
    let node = TestNode::new();
    let id = node.client.bucket_create("test", None, Visibility::Internal, Classification::Internal).await.unwrap();
    assert_ne!(id, BucketId([0u8; 32]));
}

#[tokio::test]
async fn create_bucket_with_description() {
    let node = TestNode::new();
    let id = node.client.bucket_create("notes", Some("Daily notes"), Visibility::Internal, Classification::Internal).await.unwrap();
    let info = node.client.bucket_get(&id).await.unwrap().unwrap();
    assert_eq!(info.name, "notes");
    assert_eq!(info.description, Some("Daily notes".to_string()));
}

#[tokio::test]
async fn create_bucket_default_visibility() {
    let node = TestNode::new();
    let id = node.client.bucket_create("public-stuff", None, Visibility::Public, Classification::Public).await.unwrap();
    let info = node.client.bucket_get(&id).await.unwrap().unwrap();
    assert_eq!(info.default_visibility, Visibility::Public);
    assert_eq!(info.default_classification, Classification::Public);
}

#[tokio::test]
async fn list_empty_buckets() {
    let node = TestNode::new();
    let buckets = node.client.bucket_list().await.unwrap();
    assert!(buckets.is_empty());
}

#[tokio::test]
async fn list_multiple_buckets() {
    let node = TestNode::new();
    node.client.bucket_create("a", None, Visibility::Internal, Classification::Internal).await.unwrap();
    node.client.bucket_create("b", None, Visibility::Internal, Classification::Internal).await.unwrap();
    node.client.bucket_create("c", None, Visibility::Internal, Classification::Internal).await.unwrap();
    let buckets = node.client.bucket_list().await.unwrap();
    assert_eq!(buckets.len(), 3);
}

#[tokio::test]
async fn get_nonexistent_bucket() {
    let node = TestNode::new();
    let fake = BucketId([99u8; 32]);
    assert!(node.client.bucket_get(&fake).await.unwrap().is_none());
}

#[tokio::test]
async fn rename_bucket() {
    let node = TestNode::new();
    let id = node.client.bucket_create("old", None, Visibility::Internal, Classification::Internal).await.unwrap();
    node.client.bucket_rename(&id, "new").await.unwrap();
    let info = node.client.bucket_get(&id).await.unwrap().unwrap();
    assert_eq!(info.name, "new");
}

#[tokio::test]
async fn rename_bucket_multiple_times() {
    let node = TestNode::new();
    let id = node.client.bucket_create("v1", None, Visibility::Internal, Classification::Internal).await.unwrap();
    node.client.bucket_rename(&id, "v2").await.unwrap();
    node.client.bucket_rename(&id, "v3").await.unwrap();
    node.client.bucket_rename(&id, "final").await.unwrap();
    let info = node.client.bucket_get(&id).await.unwrap().unwrap();
    assert_eq!(info.name, "final");
}

#[tokio::test]
async fn bucket_initially_private() {
    let node = TestNode::new();
    let id = node.client.bucket_create("private", None, Visibility::Internal, Classification::Internal).await.unwrap();
    let info = node.client.bucket_get(&id).await.unwrap().unwrap();
    assert!(!info.is_attached);
}

#[tokio::test]
async fn bucket_attach() {
    let node = TestNode::new();
    let id = node.client.bucket_create("attachable", None, Visibility::Internal, Classification::Internal).await.unwrap();
    node.client.bucket_attach(&id).await.unwrap();
    let info = node.client.bucket_get(&id).await.unwrap().unwrap();
    assert!(info.is_attached);
}

#[tokio::test]
async fn bucket_attach_idempotent() {
    let node = TestNode::new();
    let id = node.client.bucket_create("idem", None, Visibility::Internal, Classification::Internal).await.unwrap();
    node.client.bucket_attach(&id).await.unwrap();
    node.client.bucket_attach(&id).await.unwrap();
    node.client.bucket_attach(&id).await.unwrap();
    let info = node.client.bucket_get(&id).await.unwrap().unwrap();
    assert!(info.is_attached);
}

#[tokio::test]
async fn bucket_archive() {
    let node = TestNode::new();
    let id = node.client.bucket_create("temp", None, Visibility::Internal, Classification::Internal).await.unwrap();
    node.client.bucket_archive(&id, "done with it").await.unwrap();
    let info = node.client.bucket_get(&id).await.unwrap().unwrap();
    assert!(info.name.contains("[ARCHIVED]"));
    assert!(info.description.unwrap_or_default().contains("done with it"));
}

#[tokio::test]
async fn bucket_bind_to_cluster() {
    let node = TestNode::new();
    let id = node.client.bucket_create("bindable", None, Visibility::Internal, Classification::Internal).await.unwrap();
    node.client.bucket_bind(&id, &node.cluster_id, true).await.unwrap();
    let info = node.client.bucket_get(&id).await.unwrap().unwrap();
    assert_eq!(info.cluster_id, Some(node.cluster_id.clone()));
    assert!(info.is_default);
}

#[tokio::test]
async fn bucket_bind_non_default() {
    let node = TestNode::new();
    let id = node.client.bucket_create("secondary", None, Visibility::Internal, Classification::Internal).await.unwrap();
    node.client.bucket_bind(&id, &node.cluster_id, false).await.unwrap();
    let info = node.client.bucket_get(&id).await.unwrap().unwrap();
    assert_eq!(info.cluster_id, Some(node.cluster_id.clone()));
    assert!(!info.is_default);
}

#[tokio::test]
async fn bucket_exclusive_binding() {
    let node = TestNode::new();
    let other_cluster = ClusterId::random();
    let id = node.client.bucket_create("exclusive", None, Visibility::Internal, Classification::Internal).await.unwrap();
    node.client.bucket_bind(&id, &node.cluster_id, false).await.unwrap();
    let result = node.client.bucket_bind(&id, &other_cluster, false).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn bucket_rebind_same_cluster_ok() {
    let node = TestNode::new();
    let id = node.client.bucket_create("rebindable", None, Visibility::Internal, Classification::Internal).await.unwrap();
    node.client.bucket_bind(&id, &node.cluster_id, false).await.unwrap();
    node.client.bucket_bind(&id, &node.cluster_id, true).await.unwrap();
    let info = node.client.bucket_get(&id).await.unwrap().unwrap();
    assert!(info.is_default);
}

#[tokio::test]
async fn bucket_unbound_initially() {
    let node = TestNode::new();
    let id = node.client.bucket_create("unbound", None, Visibility::Internal, Classification::Internal).await.unwrap();
    let info = node.client.bucket_get(&id).await.unwrap().unwrap();
    assert!(info.cluster_id.is_none());
}

#[tokio::test]
async fn create_20_buckets() {
    let node = TestNode::new();
    for i in 0..20 {
        node.client.bucket_create(&format!("b-{i}"), None, Visibility::Internal, Classification::Internal).await.unwrap();
    }
    assert_eq!(node.client.bucket_list().await.unwrap().len(), 20);
}

#[tokio::test]
async fn two_nodes_buckets_isolated() {
    let (node_a, node_b) = TestNode::cluster_pair();
    let a = node_a.client.bucket_create("from-a", None, Visibility::Internal, Classification::Internal).await.unwrap();
    let b = node_b.client.bucket_create("from-b", None, Visibility::Internal, Classification::Internal).await.unwrap();
    assert_ne!(a, b);
    assert_eq!(node_a.client.bucket_list().await.unwrap().len(), 1);
    assert_eq!(node_b.client.bucket_list().await.unwrap().len(), 1);
}

//! Entity/graph operation smoke tests.

use memvault_api::MemvaultClient;
use memvault_core::{EntityId, NodeRef, Visibility};
use memvault_doc::{Edge, Entity};
use std::collections::BTreeMap;

use crate::harness::TestNode;

fn make_entity(kind: &str, name: &str) -> Entity {
    let mut props = BTreeMap::new();
    props.insert("name".to_string(), serde_json::json!(name));
    Entity {
        id: EntityId::random(),
        kind: kind.to_string(),
        props,
        edges_out: vec![],
    }
}

#[tokio::test]
async fn create_entity() {
    let node = TestNode::new();
    let e = make_entity("person", "Alice");
    let id = node
        .client
        .add_entity(e, Visibility::Internal, None)
        .await
        .unwrap();
    let fetched = node.client.get_entity(&id).await.unwrap().unwrap();
    assert_eq!(fetched.kind, "person");
    assert_eq!(fetched.props["name"], "Alice");
}

#[tokio::test]
async fn get_nonexistent_entity() {
    let node = TestNode::new();
    assert!(
        node.client
            .get_entity(&EntityId::random())
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn list_entities() {
    let node = TestNode::new();
    for name in ["Alice", "Bob", "Charlie"] {
        node.client
            .add_entity(make_entity("person", name), Visibility::Internal, None)
            .await
            .unwrap();
    }
    let entities = node.client.list_entities(100, None).await.unwrap();
    assert_eq!(entities.len(), 3);
}

#[tokio::test]
async fn entity_with_many_properties() {
    let node = TestNode::new();
    let mut props = BTreeMap::new();
    for i in 0..20 {
        props.insert(format!("key_{i}"), serde_json::json!(format!("value_{i}")));
    }
    let e = Entity {
        id: EntityId::random(),
        kind: "config".to_string(),
        props,
        edges_out: vec![],
    };
    let id = node
        .client
        .add_entity(e, Visibility::Internal, None)
        .await
        .unwrap();
    let fetched = node.client.get_entity(&id).await.unwrap().unwrap();
    assert_eq!(fetched.props.len(), 20);
}

#[tokio::test]
async fn entity_history() {
    let node = TestNode::new();
    let e = make_entity("tool", "kubectl");
    let id = node
        .client
        .add_entity(e, Visibility::Internal, None)
        .await
        .unwrap();
    let history = node.client.entity_history(&id).await.unwrap();
    assert!(!history.is_empty());
}

//! Link/edge/traversal smoke tests.

use memvault_api::MemvaultClient;
use memvault_core::{EdgeId, EntityId, NodeRef, Visibility};
use memvault_doc::{Edge, Entity};
use std::collections::BTreeMap;

use crate::harness::TestNode;

fn person(name: &str) -> Entity {
    let mut props = BTreeMap::new();
    props.insert("name".to_string(), serde_json::json!(name));
    Entity {
        id: EntityId::random(),
        kind: "person".to_string(),
        props,
        edges_out: vec![],
    }
}

#[tokio::test]
async fn add_link_between_entities() {
    let node = TestNode::new();
    let a = node
        .client
        .add_entity(person("Alice"), Visibility::Internal, None)
        .await
        .unwrap();
    let b = node
        .client
        .add_entity(person("Bob"), Visibility::Internal, None)
        .await
        .unwrap();

    let edge = Edge {
        id: EdgeId::random(),
        target: NodeRef::Entity(b.clone()),
        relation: "knows".to_string(),
        weight: Some(1.0),
        provenance: None,
        props: Default::default(),
    };
    let eid = node
        .client
        .add_link(&NodeRef::Entity(a.clone()), edge, Visibility::Internal)
        .await
        .unwrap();
    assert_ne!(eid, EdgeId([0u8; 32]));
}

#[tokio::test]
async fn list_edges_of_entity() {
    let node = TestNode::new();
    let a = node
        .client
        .add_entity(person("Alice"), Visibility::Internal, None)
        .await
        .unwrap();
    let b = node
        .client
        .add_entity(person("Bob"), Visibility::Internal, None)
        .await
        .unwrap();
    let c = node
        .client
        .add_entity(person("Charlie"), Visibility::Internal, None)
        .await
        .unwrap();

    for target in [&b, &c] {
        let edge = Edge {
            id: EdgeId::random(),
            target: NodeRef::Entity(target.clone()),
            relation: "knows".to_string(),
            weight: Some(1.0),
            provenance: None,
            props: Default::default(),
        };
        node.client
            .add_link(&NodeRef::Entity(a.clone()), edge, Visibility::Internal)
            .await
            .unwrap();
    }

    let edges = node.client.edges_of(&NodeRef::Entity(a)).await.unwrap();
    assert_eq!(edges.len(), 2);
}

#[tokio::test]
async fn remove_link() {
    let node = TestNode::new();
    let a = node
        .client
        .add_entity(person("Alice"), Visibility::Internal, None)
        .await
        .unwrap();
    let b = node
        .client
        .add_entity(person("Bob"), Visibility::Internal, None)
        .await
        .unwrap();

    let edge_id = EdgeId::random();
    let edge = Edge {
        id: edge_id.clone(),
        target: NodeRef::Entity(b.clone()),
        relation: "knows".to_string(),
        weight: Some(1.0),
        provenance: None,
        props: Default::default(),
    };
    node.client
        .add_link(&NodeRef::Entity(a.clone()), edge, Visibility::Internal)
        .await
        .unwrap();
    node.client
        .remove_link_from(&NodeRef::Entity(a.clone()), &edge_id)
        .await
        .unwrap();

    let edges = node.client.edges_of(&NodeRef::Entity(a)).await.unwrap();
    assert!(edges.is_empty());
}

#[tokio::test]
async fn traverse_graph() {
    let node = TestNode::new();
    let a = node
        .client
        .add_entity(person("Alice"), Visibility::Internal, None)
        .await
        .unwrap();
    let b = node
        .client
        .add_entity(person("Bob"), Visibility::Internal, None)
        .await
        .unwrap();

    let edge = Edge {
        id: EdgeId::random(),
        target: NodeRef::Entity(b.clone()),
        relation: "knows".to_string(),
        weight: Some(1.0),
        provenance: None,
        props: Default::default(),
    };
    node.client
        .add_link(&NodeRef::Entity(a.clone()), edge, Visibility::Internal)
        .await
        .unwrap();

    let hits = node
        .client
        .traverse_from(&NodeRef::Entity(a), Some("knows"), 2)
        .await
        .unwrap();
    assert!(!hits.is_empty());
}

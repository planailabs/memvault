use std::collections::BTreeMap;

use memvault_core::{DocId, EdgeId, EntityId};

use crate::apply::{apply_doc_ops, apply_graph_ops, apply_text_patch};
use crate::compaction::compact;
use crate::document::Document;
use crate::gc::collectible_ops;
use crate::graph::{Edge, Entity};
use crate::history::{doc_at_op, doc_diff};
use crate::op::{Op, TextOp, TextPatch};
use crate::snapshot::Snapshot;

// --- Text Patch Tests ---

#[test]
fn text_patch_retain_all() {
    let text = "hello";
    let patch = TextPatch {
        ops: vec![TextOp::Retain(5)],
    };
    assert_eq!(apply_text_patch(text, &patch).unwrap(), "hello");
}

#[test]
fn text_patch_insert_at_beginning() {
    let text = "world";
    let patch = TextPatch {
        ops: vec![TextOp::Insert("hello ".to_string()), TextOp::Retain(5)],
    };
    assert_eq!(apply_text_patch(text, &patch).unwrap(), "hello world");
}

#[test]
fn text_patch_insert_at_end() {
    let text = "hello";
    let patch = TextPatch {
        ops: vec![TextOp::Retain(5), TextOp::Insert(" world".to_string())],
    };
    assert_eq!(apply_text_patch(text, &patch).unwrap(), "hello world");
}

#[test]
fn text_patch_delete_middle() {
    let text = "hello world";
    let patch = TextPatch {
        ops: vec![TextOp::Retain(5), TextOp::Delete(1), TextOp::Retain(5)],
    };
    assert_eq!(apply_text_patch(text, &patch).unwrap(), "helloworld");
}

#[test]
fn text_patch_replace() {
    let text = "hello world";
    let patch = TextPatch {
        ops: vec![
            TextOp::Retain(6),
            TextOp::Delete(5),
            TextOp::Insert("rust".to_string()),
        ],
    };
    assert_eq!(apply_text_patch(text, &patch).unwrap(), "hello rust");
}

#[test]
fn text_patch_empty_text_insert() {
    let text = "";
    let patch = TextPatch {
        ops: vec![TextOp::Insert("new".to_string())],
    };
    assert_eq!(apply_text_patch(text, &patch).unwrap(), "new");
}

#[test]
fn text_patch_out_of_bounds() {
    let text = "hi";
    let patch = TextPatch {
        ops: vec![TextOp::Retain(5)],
    };
    assert!(apply_text_patch(text, &patch).is_err());
}

#[test]
fn text_patch_delete_out_of_bounds() {
    let text = "hi";
    let patch = TextPatch {
        ops: vec![TextOp::Delete(5)],
    };
    assert!(apply_text_patch(text, &patch).is_err());
}

// --- Document Ops Tests ---

#[test]
fn doc_create_and_edit_roundtrip() {
    let doc_id = DocId::random();
    let mut fm = BTreeMap::new();
    fm.insert("title".to_string(), serde_json::json!("My Doc"));

    let ops = vec![
        Op::DocCreate {
            doc_id: doc_id.clone(),
            initial_body: "Hello".to_string(),
            frontmatter: fm,
        },
        Op::DocEdit {
            doc_id: doc_id.clone(),
            patch: TextPatch {
                ops: vec![TextOp::Retain(5), TextOp::Insert(" World".to_string())],
            },
        },
        Op::DocSetMeta {
            doc_id: doc_id.clone(),
            key: "tags".to_string(),
            value: serde_json::json!(["rust", "crdt"]),
        },
    ];

    let doc = apply_doc_ops(&ops).unwrap();
    assert_eq!(doc.body, "Hello World");
    assert_eq!(doc.frontmatter["title"], serde_json::json!("My Doc"));
    assert_eq!(doc.frontmatter["tags"], serde_json::json!(["rust", "crdt"]));
}

#[test]
fn doc_remove_meta() {
    let doc_id = DocId::random();
    let mut fm = BTreeMap::new();
    fm.insert("key".to_string(), serde_json::json!("value"));

    let ops = vec![
        Op::DocCreate {
            doc_id: doc_id.clone(),
            initial_body: "".to_string(),
            frontmatter: fm,
        },
        Op::DocRemoveMeta {
            doc_id: doc_id.clone(),
            key: "key".to_string(),
        },
    ];

    let doc = apply_doc_ops(&ops).unwrap();
    assert!(!doc.frontmatter.contains_key("key"));
}

#[test]
fn doc_edit_before_create_fails() {
    let doc_id = DocId::random();
    let ops = vec![Op::DocEdit {
        doc_id,
        patch: TextPatch {
            ops: vec![TextOp::Insert("x".to_string())],
        },
    }];
    assert!(apply_doc_ops(&ops).is_err());
}

// --- Graph Tests ---

#[test]
fn graph_entity_crud() {
    let eid = EntityId::random();
    let mut props = BTreeMap::new();
    props.insert("name".to_string(), serde_json::json!("Alice"));

    let ops = vec![
        Op::EntityCreate {
            entity: Entity {
                id: eid.clone(),
                kind: "person".to_string(),
                props: props.clone(),
                edges_out: vec![],
            },
        },
        Op::EntityUpdate {
            entity_id: eid.clone(),
            props: {
                let mut p = BTreeMap::new();
                p.insert("age".to_string(), serde_json::json!(30));
                p
            },
        },
    ];

    let entities = apply_graph_ops(&ops).unwrap();
    let e = entities.get(&eid).unwrap();
    assert_eq!(e.kind, "person");
    assert_eq!(e.props["name"], serde_json::json!("Alice"));
    assert_eq!(e.props["age"], serde_json::json!(30));
}

#[test]
fn graph_entity_delete() {
    let eid = EntityId::random();
    let ops = vec![
        Op::EntityCreate {
            entity: Entity {
                id: eid.clone(),
                kind: "thing".to_string(),
                props: BTreeMap::new(),
                edges_out: vec![],
            },
        },
        Op::EntityDelete {
            entity_id: eid.clone(),
        },
    ];

    let entities = apply_graph_ops(&ops).unwrap();
    assert!(entities.is_empty());
}

#[test]
fn graph_edge_add_remove() {
    let e1 = EntityId::random();
    let e2 = EntityId::random();
    let edge_id = EdgeId::random();

    let ops = vec![
        Op::EntityCreate {
            entity: Entity {
                id: e1.clone(),
                kind: "a".to_string(),
                props: BTreeMap::new(),
                edges_out: vec![],
            },
        },
        Op::EntityCreate {
            entity: Entity {
                id: e2.clone(),
                kind: "b".to_string(),
                props: BTreeMap::new(),
                edges_out: vec![],
            },
        },
        Op::EdgeAdd {
            source: e1.clone(),
            edge: Edge {
                id: edge_id.clone(),
                relation: "knows".to_string(),
                target: e2.clone(),
                weight: Some(1.0),
                props: BTreeMap::new(),
                provenance: None,
            },
        },
    ];

    let entities = apply_graph_ops(&ops).unwrap();
    assert_eq!(entities[&e1].edges_out.len(), 1);
    assert_eq!(entities[&e1].edges_out[0].relation, "knows");

    // Now remove it
    let mut ops2 = ops.clone();
    ops2.push(Op::EdgeRemove {
        source: e1.clone(),
        edge_id: edge_id.clone(),
    });
    let entities2 = apply_graph_ops(&ops2).unwrap();
    assert!(entities2[&e1].edges_out.is_empty());
}

#[test]
fn graph_edge_update() {
    let e1 = EntityId::random();
    let e2 = EntityId::random();
    let edge_id = EdgeId::random();

    let ops = vec![
        Op::EntityCreate {
            entity: Entity {
                id: e1.clone(),
                kind: "a".to_string(),
                props: BTreeMap::new(),
                edges_out: vec![],
            },
        },
        Op::EntityCreate {
            entity: Entity {
                id: e2.clone(),
                kind: "b".to_string(),
                props: BTreeMap::new(),
                edges_out: vec![],
            },
        },
        Op::EdgeAdd {
            source: e1.clone(),
            edge: Edge {
                id: edge_id.clone(),
                relation: "likes".to_string(),
                target: e2.clone(),
                weight: None,
                props: BTreeMap::new(),
                provenance: None,
            },
        },
        Op::EdgeUpdate {
            source: e1.clone(),
            edge_id: edge_id.clone(),
            props: {
                let mut p = BTreeMap::new();
                p.insert("since".to_string(), serde_json::json!("2024"));
                p
            },
        },
    ];

    let entities = apply_graph_ops(&ops).unwrap();
    assert_eq!(
        entities[&e1].edges_out[0].props["since"],
        serde_json::json!("2024")
    );
}

// --- History Tests ---

#[test]
fn history_doc_at_op() {
    let doc_id = DocId::random();
    let ops = vec![
        Op::DocCreate {
            doc_id: doc_id.clone(),
            initial_body: "v1".to_string(),
            frontmatter: BTreeMap::new(),
        },
        Op::DocEdit {
            doc_id: doc_id.clone(),
            patch: TextPatch {
                ops: vec![TextOp::Delete(2), TextOp::Insert("v2".to_string())],
            },
        },
        Op::DocEdit {
            doc_id: doc_id.clone(),
            patch: TextPatch {
                ops: vec![TextOp::Delete(2), TextOp::Insert("v3".to_string())],
            },
        },
    ];

    // At op 1 (after DocCreate only)
    let doc1 = doc_at_op(&ops, 1).unwrap();
    assert_eq!(doc1.body, "v1");

    // At op 2 (after first edit)
    let doc2 = doc_at_op(&ops, 2).unwrap();
    assert_eq!(doc2.body, "v2");

    // At op 3 (after second edit)
    let doc3 = doc_at_op(&ops, 3).unwrap();
    assert_eq!(doc3.body, "v3");
}

#[test]
fn history_doc_at_op_zero_fails() {
    let doc_id = DocId::random();
    let ops = vec![Op::DocCreate {
        doc_id,
        initial_body: "x".to_string(),
        frontmatter: BTreeMap::new(),
    }];
    // At op 0 means no ops applied, so no DocCreate -> error
    assert!(doc_at_op(&ops, 0).is_err());
}

#[test]
fn history_doc_diff() {
    let doc_id = DocId::random();
    let ops = vec![
        Op::DocCreate {
            doc_id: doc_id.clone(),
            initial_body: "".to_string(),
            frontmatter: BTreeMap::new(),
        },
        Op::DocEdit {
            doc_id: doc_id.clone(),
            patch: TextPatch {
                ops: vec![TextOp::Insert("a".to_string())],
            },
        },
        Op::DocEdit {
            doc_id: doc_id.clone(),
            patch: TextPatch {
                ops: vec![TextOp::Retain(1), TextOp::Insert("b".to_string())],
            },
        },
    ];

    let diff = doc_diff(&ops, 1, 3).unwrap();
    assert_eq!(diff.len(), 2);
}

#[test]
fn history_out_of_bounds() {
    let ops: Vec<Op> = vec![];
    assert!(doc_diff(&ops, 0, 5).is_err());
    assert!(doc_diff(&ops, 5, 0).is_err());
}

// --- Compaction Tests ---

#[test]
fn compaction_creates_snapshot() {
    let doc_id = DocId::random();
    let doc = Document::new(doc_id.clone(), "state".to_string(), BTreeMap::new());
    let op_cids = vec![vec![1, 2, 3], vec![4, 5, 6]];

    let snap = compact(&doc, &op_cids, &doc_id);
    assert_eq!(snap.doc_id, doc_id);
    assert_eq!(snap.covers_ops.len(), 2);
    assert_eq!(snap.state_version, 1);
    assert!(snap.cluster_only);
    assert!(!snap.state.is_empty());
}

// --- GC Tests ---

#[test]
fn gc_collectible_ops() {
    let doc_id = DocId::random();
    let covered = vec![vec![1u8, 2, 3], vec![4, 5, 6]];
    let snapshot = Snapshot {
        doc_id,
        covers_ops: covered.clone(),
        state: vec![],
        state_version: 1,
        cluster_only: true,
    };

    let all_ops = vec![vec![1u8, 2, 3], vec![4, 5, 6], vec![7, 8, 9]];
    let collectible = collectible_ops(&snapshot, &all_ops);

    assert_eq!(collectible.len(), 2);
    assert!(collectible.contains(&vec![1u8, 2, 3]));
    assert!(collectible.contains(&vec![4u8, 5, 6]));
    assert!(!collectible.contains(&vec![7u8, 8, 9]));
}

#[test]
fn gc_no_collectible_ops() {
    let doc_id = DocId::random();
    let snapshot = Snapshot {
        doc_id,
        covers_ops: vec![],
        state: vec![],
        state_version: 1,
        cluster_only: true,
    };

    let all_ops = vec![vec![1u8, 2, 3]];
    let collectible = collectible_ops(&snapshot, &all_ops);
    assert!(collectible.is_empty());
}

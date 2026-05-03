use std::collections::BTreeMap;

use memvault_core::{DocId, EdgeId, EntityId, NodeRef};
use serde::{Deserialize, Serialize};

use crate::graph::{Edge, Entity};

/// CRDT operation — the unit of change.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Op {
    // Document ops
    DocCreate {
        doc_id: DocId,
        initial_body: String,
        frontmatter: BTreeMap<String, serde_json::Value>,
    },
    DocEdit {
        doc_id: DocId,
        patch: TextPatch,
    },
    DocSetMeta {
        doc_id: DocId,
        key: String,
        value: serde_json::Value,
    },
    DocRemoveMeta {
        doc_id: DocId,
        key: String,
    },

    // Graph ops
    EntityCreate {
        entity: Entity,
    },
    EntityUpdate {
        entity_id: EntityId,
        props: BTreeMap<String, serde_json::Value>,
    },
    EntityDelete {
        entity_id: EntityId,
    },
    EdgeAdd {
        source: NodeRef,
        edge: Edge,
    },
    EdgeRemove {
        source: NodeRef,
        edge_id: EdgeId,
    },
    EdgeUpdate {
        source: NodeRef,
        edge_id: EdgeId,
        props: BTreeMap<String, serde_json::Value>,
    },
}

/// A text patch (simplified operational transform).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TextPatch {
    pub ops: Vec<TextOp>,
}

/// Individual text operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TextOp {
    Retain(usize),
    Insert(String),
    Delete(usize),
}

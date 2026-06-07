use std::collections::BTreeMap;

use memvault_auth::Action;
use memvault_core::{AgentName, BucketId, ClusterId, DocId, EdgeId, EntityId, NodeRef};
use serde::{Deserialize, Serialize};

use crate::bucket::BucketDecl;
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

    // Bucket ops — appended, never inserted in the middle.
    // added B1, removable never
    BucketCreate {
        decl: BucketDecl,
    },
    // added B1, removable never
    BucketBind {
        bucket_id: BucketId,
        cluster_id: ClusterId,
    },
    // added B1, removable never
    BucketRename {
        bucket_id: BucketId,
        new_name: String,
    },
    // added B1, removable never
    BucketArchive {
        bucket_id: BucketId,
        reason: String,
    },
    // added B1, removable never
    BucketAttach {
        bucket_id: BucketId,
        attached_at_ns: u64,
    },
    // added B1, removable never
    BucketGrantAgent {
        bucket_id: BucketId,
        agent: AgentName,
        actions: Vec<Action>,
    },
    // added B1, removable never
    BucketRevokeAgent {
        bucket_id: BucketId,
        agent: AgentName,
    },
    // Agent ops — appended, never inserted in the middle.
    // added B12, removable never
    //
    // Sets a mutable human-readable display label for an agent identified by
    // its ed25519 pubkey. Display-only — it never participates in access
    // control (which keys on the pubkey / attestation). Mirrors `BucketRename`.
    AgentRename {
        agent_pubkey: [u8; 32],
        new_label: String,
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

use std::collections::BTreeMap;

use memvault_core::{EdgeId, EntityId};
use serde::{Deserialize, Serialize};

/// Knowledge graph entity.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Entity {
    pub id: EntityId,
    pub kind: String,
    pub props: BTreeMap<String, serde_json::Value>,
    pub edges_out: Vec<Edge>,
}

/// A typed, weighted edge between entities.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Edge {
    pub id: EdgeId,
    pub relation: String,
    pub target: EntityId,
    pub weight: Option<f32>,
    pub props: BTreeMap<String, serde_json::Value>,
    pub provenance: Option<Vec<u8>>,
}

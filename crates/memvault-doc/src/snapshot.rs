use memvault_core::DocId;
use serde::{Deserialize, Serialize};

/// A snapshot captures materialized state at a point.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Snapshot {
    pub doc_id: DocId,
    pub covers_ops: Vec<Vec<u8>>,
    pub state: Vec<u8>,
    pub state_version: u8,
    pub cluster_only: bool,
}

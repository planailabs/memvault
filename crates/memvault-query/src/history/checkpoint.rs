//! Named checkpoints for documents.

use memvault_core::{DocId, PeerId};
use serde::{Deserialize, Serialize};

/// A named checkpoint for a document, stored as metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Checkpoint {
    pub name: String,
    pub doc_id: DocId,
    /// CID of the op at this checkpoint.
    pub op_cid: Vec<u8>,
    /// Wall-clock nanosecond timestamp when checkpoint was created.
    pub wall_ns: u64,
    /// Who created this checkpoint.
    pub created_by: PeerId,
}

impl Checkpoint {
    /// Create a new checkpoint.
    pub fn new(
        name: String,
        doc_id: DocId,
        op_cid: Vec<u8>,
        wall_ns: u64,
        created_by: PeerId,
    ) -> Self {
        Self {
            name,
            doc_id,
            op_cid,
            wall_ns,
            created_by,
        }
    }
}

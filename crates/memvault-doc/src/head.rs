use memvault_core::{DocId, PeerId, Visibility};
use serde::{Deserialize, Serialize};

/// Per-writer head tracking.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DocumentHead {
    pub doc_id: DocId,
    pub writer: PeerId,
    pub snapshot_cid: Option<Vec<u8>>,
    pub frontier: Vec<Vec<u8>>,
    pub epoch: u64,
    pub visibility: Visibility,
}

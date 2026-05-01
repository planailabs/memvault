use memvault_core::DocId;

use crate::document::Document;
use crate::snapshot::Snapshot;

/// Create a snapshot from a document's current state and the ops that produced it.
pub fn compact(doc: &Document, op_cids: &[Vec<u8>], doc_id: &DocId) -> Snapshot {
    let state = serde_ipld_dagcbor::to_vec(doc).unwrap_or_default();
    Snapshot {
        doc_id: doc_id.clone(),
        covers_ops: op_cids.to_vec(),
        state,
        state_version: 1,
        cluster_only: true,
    }
}

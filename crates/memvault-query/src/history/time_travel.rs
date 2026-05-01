//! Reconstruct document state at a wall-clock timestamp.

use memvault_core::DocId;
use memvault_doc::{Document, Op};
use memvault_store::MemvaultStore;

use crate::error::QueryError;

/// Reconstruct document state at a given wall-clock nanosecond timestamp.
///
/// Queries all ops for the document up to `at_ns`, deserializes them,
/// and applies them in order to reconstruct the document state.
pub fn doc_at_time(
    store: &MemvaultStore,
    doc_id: &DocId,
    at_ns: u64,
) -> Result<Document, QueryError> {
    // Query blocks by tag (doc_id encoded as scope "doc", label = hex of doc_id)
    let doc_label = doc_id_label(doc_id);
    let cids = store.query_by_tag("doc", &doc_label, 0, usize::MAX)?;

    // Filter by time: we need blocks with wall_ns <= at_ns
    // The tag query already returns in time order, but may include later ones
    // since we pass after_ns=0. We need to filter by retrieving each block's metadata.
    // Since the tag index key contains wall_ns and is sorted, and we pass after_ns=0,
    // all results are from time 0 onwards. We also query by time to get the cutoff.
    let time_cids = store.query_by_time(0, at_ns + 1, usize::MAX)?;

    // Intersect: only keep CIDs that appear in both sets
    let time_set: std::collections::HashSet<Vec<u8>> = time_cids.into_iter().collect();
    let relevant_cids: Vec<Vec<u8>> = cids
        .into_iter()
        .filter(|c| time_set.contains(c))
        .collect();

    // Deserialize ops from blocks
    let mut ops = Vec::new();
    for cid in &relevant_cids {
        if let Some(block_data) = store.get_block(cid)? {
            if let Ok(op) = serde_json::from_slice::<Op>(&block_data) {
                ops.push(op);
            }
        }
    }

    if ops.is_empty() {
        return Err(QueryError::NotFound(doc_id.0.to_vec()));
    }

    // Apply ops to reconstruct state
    memvault_doc::apply_doc_ops(&ops).map_err(|e| QueryError::Other(e.to_string()))
}

/// Encode a DocId as a tag label for indexing.
pub(crate) fn doc_id_label(doc_id: &DocId) -> String {
    doc_id.0.iter().map(|b| format!("{b:02x}")).collect()
}

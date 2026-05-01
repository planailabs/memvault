//! Trace provenance chain for a block.

use memvault_store::MemvaultStore;

use crate::error::QueryError;

/// A single entry in a provenance trace.
#[derive(Debug, Clone)]
pub struct ProvenanceEntry {
    pub cid: Vec<u8>,
    pub depth: usize,
    pub author: Vec<u8>,
    pub wall_ns: u64,
    pub tags: Vec<(String, String)>,
}

/// Trace provenance chain: follow provenance links from a CID to its roots.
///
/// This walks the provenance parents of `start_cid` recursively up to `max_depth`.
/// The store's provenance index maps parent -> child, so we scan for entries
/// where the start_cid appears as a child, then recurse on the parents found.
///
/// For simplicity in Phase 3, we deserialize envelope metadata from the block data.
pub fn trace_provenance(
    store: &MemvaultStore,
    start_cid: &[u8],
    max_depth: usize,
) -> Result<Vec<ProvenanceEntry>, QueryError> {
    let mut result = Vec::new();
    let mut queue = vec![(start_cid.to_vec(), 0usize)];
    let mut visited = std::collections::HashSet::new();
    visited.insert(start_cid.to_vec());

    while let Some((cid, depth)) = queue.pop() {
        if depth > max_depth {
            continue;
        }

        // Try to get block data for metadata extraction
        let block_data = store.get_block(&cid)?;
        let (author, wall_ns, tags) = if let Some(data) = &block_data {
            extract_metadata(data)
        } else {
            (Vec::new(), 0, Vec::new())
        };

        if depth > 0 {
            result.push(ProvenanceEntry {
                cid: cid.clone(),
                depth,
                author,
                wall_ns,
                tags,
            });
        }

        // Find provenance parents of this CID by scanning all blocks
        // In the store, provenance links are stored as parent->child.
        // We need to find parents of `cid`, which means scanning for entries
        // where child == cid. Since the index is keyed by parent, we need
        // to look at the block's own metadata for its provenance parents.
        if depth < max_depth {
            if let Some(data) = &block_data {
                let parents = extract_provenance_parents(data);
                for parent in parents {
                    if visited.insert(parent.clone()) {
                        queue.push((parent, depth + 1));
                    }
                }
            }
        }
    }

    result.sort_by_key(|e| e.depth);
    Ok(result)
}

/// Extract metadata from a block (best-effort JSON deserialization).
fn extract_metadata(data: &[u8]) -> (Vec<u8>, u64, Vec<(String, String)>) {
    if let Ok(val) = serde_json::from_slice::<serde_json::Value>(data) {
        let author = val
            .get("author")
            .and_then(|v| v.as_str())
            .map(|s| s.as_bytes().to_vec())
            .or_else(|| {
                val.get("author")
                    .and_then(|v| v.as_array())
                    .map(|arr| arr.iter().filter_map(|v| v.as_u64().map(|n| n as u8)).collect())
            })
            .unwrap_or_default();

        let wall_ns = val.get("wall_ns").and_then(|v| v.as_u64()).unwrap_or(0);

        let tags = val
            .get("tags")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|t| {
                        let pair = t.as_array()?;
                        let scope = pair.first()?.as_str()?.to_string();
                        let label = pair.get(1)?.as_str()?.to_string();
                        Some((scope, label))
                    })
                    .collect()
            })
            .unwrap_or_default();

        (author, wall_ns, tags)
    } else {
        (Vec::new(), 0, Vec::new())
    }
}

/// Extract provenance parent CIDs from a block's JSON data.
fn extract_provenance_parents(data: &[u8]) -> Vec<Vec<u8>> {
    if let Ok(val) = serde_json::from_slice::<serde_json::Value>(data) {
        val.get("provenance")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| {
                        v.as_str().map(|s| s.as_bytes().to_vec()).or_else(|| {
                            v.as_array()
                                .map(|a| a.iter().filter_map(|n| n.as_u64().map(|n| n as u8)).collect())
                        })
                    })
                    .collect()
            })
            .unwrap_or_default()
    } else {
        Vec::new()
    }
}

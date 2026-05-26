use std::collections::BTreeMap;

use crate::output::Summary;
use crate::scope::SummarizationRequest;

/// In-memory summary cache keyed by (scope_hash, source_cids_hash).
pub struct SummaryCache {
    entries: BTreeMap<Vec<u8>, CacheEntry>,
    max_entries: usize,
}

struct CacheEntry {
    summary: Summary,
    accessed_at_ns: u64,
    source_cids: Vec<Vec<u8>>,
}

impl SummaryCache {
    pub fn new(max_entries: usize) -> Self {
        Self {
            entries: BTreeMap::new(),
            max_entries,
        }
    }

    /// Look up a cached summary by key.
    pub fn get(&self, key: &[u8]) -> Option<&Summary> {
        self.entries.get(key).map(|e| &e.summary)
    }

    /// Insert a summary into the cache.
    pub fn put(&mut self, key: Vec<u8>, summary: Summary, source_cids: Vec<Vec<u8>>, now_ns: u64) {
        self.entries.insert(
            key,
            CacheEntry {
                summary,
                accessed_at_ns: now_ns,
                source_cids,
            },
        );

        if self.entries.len() > self.max_entries {
            self.evict_lru();
        }
    }

    /// Remove all cache entries whose sources contain the given CID.
    /// Returns the number of entries removed.
    pub fn invalidate_by_source(&mut self, source_cid: &[u8]) -> usize {
        let keys_to_remove: Vec<Vec<u8>> = self
            .entries
            .iter()
            .filter(|(_, entry)| {
                entry
                    .source_cids
                    .iter()
                    .any(|cid| cid.as_slice() == source_cid)
            })
            .map(|(key, _)| key.clone())
            .collect();

        let count = keys_to_remove.len();
        for key in keys_to_remove {
            self.entries.remove(&key);
        }
        count
    }

    /// Evict the least-recently-used entry.
    pub fn evict_lru(&mut self) {
        if self.entries.is_empty() {
            return;
        }

        let lru_key = self
            .entries
            .iter()
            .min_by_key(|(_, entry)| entry.accessed_at_ns)
            .map(|(key, _)| key.clone());

        if let Some(key) = lru_key {
            self.entries.remove(&key);
        }
    }

    /// Compute the cache key for a request + source CIDs combination.
    /// Uses blake3 hash of serialized request + sorted source CIDs.
    pub fn cache_key(request: &SummarizationRequest, source_cids: &[Vec<u8>]) -> Vec<u8> {
        let mut hasher = blake3::Hasher::new();

        // Hash the serialized request
        let request_bytes = serde_json::to_vec(request).unwrap_or_default();
        hasher.update(&request_bytes);

        // Hash sorted source CIDs for deterministic ordering
        let mut sorted_cids = source_cids.to_vec();
        sorted_cids.sort();
        for cid in &sorted_cids {
            hasher.update(cid);
        }

        hasher.finalize().as_bytes().to_vec()
    }

    /// Number of entries currently in the cache.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the cache is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

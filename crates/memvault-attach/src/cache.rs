//! LRU cache for lazy attachment chunks.

use std::collections::BTreeMap;

/// LRU cache for lazy attachment chunks.
pub struct AttachmentCache {
    max_bytes: u64,
    current_bytes: u64,
    entries: BTreeMap<Vec<u8>, CacheEntry>,
    access_order: Vec<Vec<u8>>,
}

struct CacheEntry {
    size: u64,
    #[allow(dead_code)]
    accessed_at_ns: u64,
}

impl AttachmentCache {
    /// Create a new cache with the given capacity in bytes.
    pub fn new(max_bytes: u64) -> Self {
        Self {
            max_bytes,
            current_bytes: 0,
            entries: BTreeMap::new(),
            access_order: Vec::new(),
        }
    }

    /// Check if a CID is in cache; if so, move it to front of LRU.
    /// Returns true if the entry was found.
    pub fn get(&mut self, cid: &[u8]) -> bool {
        if self.entries.contains_key(cid) {
            // Move to end of access_order (most recently used).
            self.access_order.retain(|c| c.as_slice() != cid);
            self.access_order.push(cid.to_vec());
            true
        } else {
            false
        }
    }

    /// Insert a block into the cache.
    pub fn put(&mut self, cid: &[u8], size: u64, now_ns: u64) {
        if self.entries.contains_key(cid) {
            // Already present, just touch it.
            self.get(cid);
            return;
        }

        self.entries.insert(
            cid.to_vec(),
            CacheEntry {
                size,
                accessed_at_ns: now_ns,
            },
        );
        self.current_bytes += size;
        self.access_order.push(cid.to_vec());
    }

    /// Evict the least recently used entry. Returns the evicted CID, if any.
    pub fn evict_lru(&mut self) -> Option<Vec<u8>> {
        if self.access_order.is_empty() {
            return None;
        }

        let oldest = self.access_order.remove(0);
        if let Some(entry) = self.entries.remove(&oldest) {
            self.current_bytes -= entry.size;
        }
        Some(oldest)
    }

    /// Returns true if the cache is over capacity and should evict.
    pub fn should_evict(&self) -> bool {
        self.current_bytes > self.max_bytes
    }

    /// Current bytes used.
    pub fn current_usage(&self) -> u64 {
        self.current_bytes
    }
}

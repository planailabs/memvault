// Cache invalidation is handled directly by `SummaryCache::invalidate_by_source`.
// This module provides higher-level invalidation utilities.

use crate::cache::SummaryCache;

/// Invalidate all cached summaries that reference any of the given source CIDs.
/// Returns the total number of cache entries removed.
pub fn invalidate_sources(cache: &mut SummaryCache, source_cids: &[Vec<u8>]) -> usize {
    let mut total = 0;
    for cid in source_cids {
        total += cache.invalidate_by_source(cid);
    }
    total
}

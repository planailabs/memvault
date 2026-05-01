//! Replication hint types and auto-classification.

use serde::{Deserialize, Serialize};

use crate::chunk::EAGER_THRESHOLD;

/// Replication strategy for an attachment.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ReplicationHint {
    /// Auto-replicate to all peers (files <= 10 MiB).
    Eager,
    /// Fetch on demand only.
    Lazy,
    /// Pinned by specific peers.
    PinnedBy(Vec<Vec<u8>>),
}

/// Determine replication hint from file size.
pub fn default_replication(size: u64) -> ReplicationHint {
    if size <= EAGER_THRESHOLD {
        ReplicationHint::Eager
    } else {
        ReplicationHint::Lazy
    }
}

//! Bucket declaration and cluster binding types.
//!
//! A bucket is independent of any cluster. It can be created before genesis,
//! populated with data, and then bound to a cluster later.

use memvault_core::{AgentId, BucketId, ClusterId, PeerId, Visibility};
use memvault_core::classification::Classification;
use serde::{Deserialize, Serialize};

/// Declaration of a bucket — its identity and metadata.
///
/// No `is_default` field: default-ness is a cluster-level binding, not a
/// bucket property (see `BucketBinding`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BucketDecl {
    pub bucket_id: BucketId,
    pub name: String,
    pub description: Option<String>,
    /// If Some, this bucket was created by a specific agent. If None, cluster-owned.
    pub owner_agent: Option<AgentId>,
    pub default_visibility: Visibility,
    pub default_classification: Classification,
    pub created_ns: u64,
    /// If Some, this bucket is private to a single peer and not gossiped.
    /// Set to None when the bucket is attached to the cluster.
    pub private_to_peer: Option<PeerId>,
}

/// Records that a bucket is associated with a cluster.
///
/// Written at genesis (for the default bucket) or when a bucket is
/// attached to a cluster post-genesis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BucketBinding {
    pub bucket_id: BucketId,
    pub cluster_id: ClusterId,
    pub bound_at_ns: u64,
    /// True if this is the cluster's default bucket — the one used when
    /// no explicit bucket is specified on a write.
    pub is_default: bool,
}

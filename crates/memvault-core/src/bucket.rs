//! Bucket declaration and cluster binding types.
//!
//! A bucket is independent of any cluster. It can be created before genesis,
//! populated with data, and then bound to a cluster later. Bucket-related
//! types live in `memvault-core` alongside `ClusterId`, `Visibility`, and
//! `Classification` — they're cluster-scoped envelope payloads, not
//! document- or graph-specific, so net/store can use them without a
//! `memvault-doc` dependency.

use serde::{Deserialize, Serialize};

use crate::classification::Classification;
use crate::ids::{AgentId, BucketId, ClusterId, PeerId};
use crate::visibility::Visibility;

/// The role a bucket plays within the system.
///
/// Set at creation time and stored in `BucketDecl`.  The role is
/// informational / policy — it does not affect storage mechanics.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BucketRole {
    /// Normal user-created bucket (the default for backwards compat).
    Standard,
    /// Holds data adopted from pre-bucket (legacy) envelopes.
    Legacy,
    /// Per-agent bucket, created automatically when an agent is enrolled.
    Agent,
}

impl Default for BucketRole {
    fn default() -> Self {
        Self::Standard
    }
}

/// Declaration of a bucket — its identity and metadata.
///
/// No `is_default` field: default-ness is a cluster-level binding, not a
/// bucket property (see [`BucketBinding`]).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BucketDecl {
    pub bucket_id: BucketId,
    pub name: String,
    pub description: Option<String>,
    /// If Some, this bucket was created by a specific agent. If None, cluster-owned.
    pub owner_agent: Option<AgentId>,
    /// The owner agent's ed25519 pubkey, when known at creation. Lets ACL
    /// enforcement resolve owner/attesting-node grant authority without an
    /// agent_id→pubkey scan. `None` for cluster-owned or node-owned buckets.
    #[serde(default)]
    pub owner_agent_pubkey: Option<[u8; 32]>,
    /// The owning **node**'s ed25519 pubkey, for buckets a node creates for
    /// itself (e.g. the per-node legacy bucket) rather than on behalf of an
    /// agent. Lets that node delegate access to the bucket with its node
    /// key, no admin required. `None` for agent-owned / cluster buckets.
    #[serde(default)]
    pub owner_node_pubkey: Option<[u8; 32]>,
    pub default_visibility: Visibility,
    pub default_classification: Classification,
    pub created_ns: u64,
    /// If Some, this bucket is private to a single peer and not gossiped.
    /// Set to None when the bucket is attached to the cluster.
    pub private_to_peer: Option<PeerId>,
    /// The role this bucket plays.  Absent in pre-role envelopes, which
    /// deserialize as `Standard` via `#[serde(default)]`.
    #[serde(default)]
    pub role: BucketRole,
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
}

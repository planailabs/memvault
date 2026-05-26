//! Request/response types for the memvault API.

use memvault_auth::Role;
use memvault_core::classification::Classification;
use memvault_core::{BucketId, ClusterId, DocId, EdgeId, EntityId, NodeRef, Visibility};
use serde::{Deserialize, Serialize};

/// Summary of a document for list operations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DocSummary {
    pub id: DocId,
    pub cid: Vec<u8>,
    pub title: Option<String>,
    pub tags: Vec<(String, String)>,
    pub updated_ns: u64,
    pub attachment_count: usize,
}

/// A hit from a graph traversal.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraversalHit {
    pub node: NodeRef,
    pub depth: usize,
    pub path: Vec<(EdgeId, String)>,
}

impl TraversalHit {
    /// Returns the EntityId if the node is an Entity.
    pub fn entity_id(&self) -> Option<&EntityId> {
        match &self.node {
            NodeRef::Entity(id) => Some(id),
            _ => None,
        }
    }
}

/// Status of an issued token.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenStatus {
    pub cid: Vec<u8>,
    pub label: Option<String>,
    pub role: Role,
    pub max_uses: u32,
    pub consumed_count: u32,
    pub not_after_ns: u64,
    pub revoked: bool,
}

/// Information about a key rotation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RotationInfo {
    pub rotation_id: Vec<u8>,
    pub kind: String,
    pub valid_from_ns: u64,
    pub overlap_until_ns: u64,
    pub aborted: bool,
}

/// A saved view — a named set of required tags that filters all content.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct View {
    pub name: String,
    /// Required tags — items must have ALL of these to appear in this view.
    pub tags: Vec<(String, String)>,
    pub created_ns: u64,
    /// Block CID (hex). Set after storage, empty on input.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub cid: String,
    /// When set, the view only returns items in this bucket.
    /// None = fan out across all accessible buckets (legacy behavior).
    /// Added in B4. Old views deserialize with None via #[serde(default)].
    #[serde(default)]
    pub bucket_id: Option<BucketId>,
}

/// Options for write operations, allowing callers to specify a target bucket.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct WriteOptions {
    /// Target bucket. None = agent's default bucket → cluster default.
    pub bucket: Option<BucketId>,
}

/// Information about a bucket.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BucketInfo {
    pub id: BucketId,
    pub name: String,
    pub description: Option<String>,
    pub owner_agent: Option<memvault_core::AgentId>,
    /// Which cluster this bucket is bound to (None if unbound/standalone).
    pub cluster_id: Option<ClusterId>,
    /// Whether this bucket is attached to the cluster (private_to_peer is None).
    pub is_attached: bool,
    pub default_visibility: Visibility,
    pub default_classification: Classification,
    pub created_ns: u64,
    /// Number of envelopes in this bucket.
    pub envelope_count: u64,
    /// The role this bucket plays (standard, legacy, agent).
    #[serde(default)]
    pub role: memvault_doc::BucketRole,
}

/// Node status information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeStatus {
    pub peer_id: Vec<u8>,
    pub cluster_id: Vec<u8>,
    pub block_count: u64,
    pub doc_count: u64,
    pub peer_count: u32,
    pub uptime_secs: u64,
}

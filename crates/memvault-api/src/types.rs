//! Request/response types for the memvault API.

use memvault_core::{DocId, EdgeId, EntityId};
use memvault_auth::Role;
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
    pub entity_id: EntityId,
    pub depth: usize,
    pub path: Vec<(EdgeId, String)>,
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

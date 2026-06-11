//! Request/response types for the memvault API.

use memvault_auth::TokenRole;
use memvault_core::classification::Classification;
use memvault_core::{BucketId, ClusterId, DocId, EdgeId, EntityId, NodeRef, Visibility};
use serde::{Deserialize, Serialize};

/// Summary of a document for list operations.
///
/// Wire shape per `standards/`: `id` is an opaque doc id → hex; `cid` is the
/// document's content address → canonical CID string (not hex).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DocSummary {
    #[serde(with = "crate::wire::hex_id")]
    pub id: DocId,
    #[serde(with = "crate::wire::cid_str")]
    pub cid: Vec<u8>,
    pub title: Option<String>,
    pub tags: Vec<(String, String)>,
    pub updated_ns: u64,
    pub attachment_count: usize,
}

/// A node summary for scoped listing — supersedes the
/// `(node_id, node_type, label, tags)` tuple and adds the retracted flag.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeSummary {
    pub node_id: String,
    pub node_type: String,
    pub label: String,
    pub tags: Vec<(String, String)>,
    #[serde(default)]
    pub retracted: bool,
    /// Type-specific detail, populated only when the scope requests
    /// `DetailLevel::Full`. `None` for lean summaries.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<NodeDetail>,
}

/// Type-specific enrichment for a [`NodeSummary`], populated on
/// `DetailLevel::Full`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum NodeDetail {
    Doc {
        updated_ns: u64,
        attachment_count: usize,
    },
    Entity {
        entity_kind: String,
        props: std::collections::BTreeMap<String, serde_json::Value>,
    },
    File {
        filename: String,
        mime_type: String,
        size: u64,
    },
}

/// Active/retracted counts for a query scope.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ScopeCount {
    pub active: u64,
    pub retracted: u64,
}

impl ScopeCount {
    pub fn total(&self) -> u64 {
        self.active + self.retracted
    }
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

/// Spec for publishing a new skill — the manifest props plus an optional inline
/// instruction body (when set, a Document is created and linked as the skill's
/// primary instruction).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SkillSpec {
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub trigger: Option<String>,
    #[serde(default)]
    pub instruction_body: Option<String>,
}

/// Summary of a skill for list/discovery — the manifest props only, no
/// resource traversal (cheap; `DetailLevel::Summary`-equivalent).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SkillInfo {
    #[serde(with = "crate::wire::hex_id")]
    pub id: EntityId,
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub trigger: Option<String>,
    #[serde(default)]
    pub retracted: bool,
}

/// One component node of a skill, paired with the edge that links it. `node` is
/// a `"type:hex"` tag label (parse via [`NodeRef::from_tag_label`]).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SkillResource {
    #[serde(with = "crate::wire::hex_id")]
    pub edge_id: EdgeId,
    pub node: String,
    pub relation: String,
    #[serde(default)]
    pub path: Option<String>,
    #[serde(default)]
    pub executable: bool,
    #[serde(default)]
    pub order: Option<i64>,
    #[serde(default)]
    pub label: Option<String>,
}

/// A fully-assembled skill: the manifest plus its linked components, grouped by
/// relation. This is what `skill_get` returns and what the bundle hydrator
/// walks.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SkillBundle {
    pub info: SkillInfo,
    pub instructions: Vec<SkillResource>,
    pub resources: Vec<SkillResource>,
    pub requires: Vec<SkillResource>,
}

/// Status of an issued token.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenStatus {
    /// Token envelope CID (canonical CID string on the wire).
    #[serde(with = "crate::wire::cid_str")]
    pub cid: Vec<u8>,
    pub label: Option<String>,
    pub role: TokenRole,
    pub max_uses: u32,
    pub consumed_count: u32,
    pub not_after_ns: u64,
    pub revoked: bool,
    /// Unix ns at which the token was explicitly invalidated (revoked or
    /// exhausted). `None` if it is only subject to TTL expiry. After
    /// `INVALIDATED_TOKEN_RETENTION_NS` the record is GC'd.
    #[serde(default)]
    pub invalidated_at_ns: Option<u64>,
}

/// Information about a key rotation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RotationInfo {
    #[serde(with = "crate::wire::hex_bytes")]
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
///
/// Wire shape per `standards/`: IDs are hex strings (the byte-newtype `serde`
/// is reserved for dag-cbor blocks), so the ID fields carry `crate::wire`
/// hex helpers and the type is transmitted as-is — no hand-built JSON.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BucketInfo {
    #[serde(with = "crate::wire::hex_id")]
    pub id: BucketId,
    pub name: String,
    pub description: Option<String>,
    pub owner_agent: Option<memvault_core::AgentName>,
    /// Owner agent's ed25519 pubkey, when recorded at creation. Used by
    /// ACL to resolve owner / attesting-node grant authority.
    #[serde(default, with = "crate::wire::hex_array32_opt")]
    pub owner_agent_pubkey: Option<[u8; 32]>,
    /// Owning node's ed25519 pubkey for node-owned buckets (e.g. the
    /// per-node legacy bucket).
    #[serde(default, with = "crate::wire::hex_array32_opt")]
    pub owner_node_pubkey: Option<[u8; 32]>,
    /// Which cluster this bucket is bound to (None if unbound/standalone).
    #[serde(default, with = "crate::wire::hex_id_opt")]
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
    /// When this bucket has been merged into another, the canonical bucket
    /// it resolves to. `None` for a normal (canonical or unmerged) bucket.
    /// Merged sources are hidden from default bucket listings (treated like
    /// retracted) — surfaced only via an explicit include flag or to
    /// Auditor/Admin roles.
    #[serde(default, with = "crate::wire::hex_id_opt")]
    pub merged_into: Option<BucketId>,
}

/// Node status information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeStatus {
    // peer_id is a libp2p multihash → base58btc canonical string; cluster_id is
    // an opaque id → hex.
    #[serde(with = "crate::wire::b58_bytes")]
    pub peer_id: Vec<u8>,
    #[serde(with = "crate::wire::hex_bytes")]
    pub cluster_id: Vec<u8>,
    pub block_count: u64,
    pub doc_count: u64,
    pub peer_count: u32,
    pub uptime_secs: u64,
}

/// Summary of a capability grant visible to a caller.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GrantInfo {
    /// Grant envelope CID (canonical CID string on the wire).
    #[serde(with = "crate::wire::cid_str")]
    pub cid: Vec<u8>,
    /// Bucket the grant is scoped to (the one the caller asked about).
    #[serde(with = "crate::wire::hex_id")]
    pub bucket_id: BucketId,
    /// Issuer peer of the grant.
    #[serde(with = "crate::wire::peer_b58")]
    pub issuer: memvault_core::PeerId,
    /// Issuing cluster.
    #[serde(with = "crate::wire::hex_id")]
    pub issuing_cluster: ClusterId,
    /// Who the grant is addressed to.
    pub audience: memvault_auth::GrantAudience,
    /// Granted actions.
    pub actions: Vec<memvault_auth::Action>,
    pub not_before_ns: u64,
    pub not_after_ns: u64,
}

/// Summary of a cross-cluster share proposal.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShareProposalInfo {
    /// Proposal envelope CID (canonical CID string on the wire).
    #[serde(with = "crate::wire::cid_str")]
    pub cid: Vec<u8>,
    #[serde(with = "crate::wire::hex_array16")]
    pub proposal_id: [u8; 16],
    #[serde(with = "crate::wire::hex_id")]
    pub from_cluster: ClusterId,
    #[serde(with = "crate::wire::hex_id")]
    pub from_bucket: BucketId,
    #[serde(with = "crate::wire::peer_b58")]
    pub from_admin: memvault_core::PeerId,
    #[serde(with = "crate::wire::hex_id")]
    pub to_cluster: ClusterId,
    pub to_recipient: memvault_auth::ShareRecipient,
    pub proposed_actions: Vec<memvault_auth::Action>,
    pub purpose: String,
    pub not_after_ns: u64,
}

// ─── Extraction / media pipeline ──────────────────────────────────────────────

/// Status of a background extraction op for a file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MediaJobStatus {
    /// Work is queued or running (locally or expected from a peer).
    Pending,
    /// A cached result annotation exists.
    Done,
    /// A cached failure annotation exists.
    Failed,
    /// The capability is disabled/unconfigured on this node.
    Unavailable,
    /// No extractor claims this MIME type for the op.
    Unsupported,
}

/// A timed transcript segment (wire form — carries its text, unlike the
/// ABI form which spans into the full transcript).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TranscriptSegmentInfo {
    pub start_ms: u64,
    pub end_ms: u64,
    pub text: String,
}

/// Unified extraction state for a file: plain text, OCR text, or audio
/// transcript, plus job status.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ExtractionInfo {
    pub status: MediaJobStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    /// Timed segments, present for audio transcripts.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub segments: Option<Vec<TranscriptSegmentInfo>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// Extractor identifier (e.g. "memvault-whisper@0.1.0").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extractor: Option<String>,
}

/// Pixel dimensions of one pre-rendered page.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PageDims {
    /// 1-based page number.
    pub page_no: u32,
    pub width: u32,
    pub height: u32,
}

/// Page-render manifest for a file: dims only, no image bytes or text
/// layers (those are fetched per page).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PageRenderInfo {
    pub status: MediaJobStatus,
    pub page_count: u32,
    #[serde(default)]
    pub pages: Vec<PageDims>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// A positioned word in image pixel coordinates (origin top-left).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PageWord {
    pub text: String,
    pub x: f32,
    pub y: f32,
    pub w: f32,
    pub h: f32,
}

/// Selectable text layer for one rendered page.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PageTextLayer {
    /// 1-based page number.
    pub page_no: u32,
    /// Image pixel dims the word coords are relative to.
    pub width: u32,
    pub height: u32,
    pub words: Vec<PageWord>,
}

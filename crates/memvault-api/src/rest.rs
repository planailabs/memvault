//! Request and response bodies of the REST API (`memvault-web`'s `/api/v1`),
//! shared by the server handlers and [`crate::HttpApiClient`].
//!
//! One type per body, serialized by the server and deserialized by the
//! client (or the other way round for requests) — see
//! `standards/wire-dtos.md`. Domain types that already have a wire shape
//! (`BucketInfo`, `DocSummary`, `NodeSummary`, `View`, `TraversalHit`, …) are
//! transmitted as they are; these are the bodies that have no domain type.
//! IDs follow `standards/api-wire-conventions.md` §1: node references are
//! `"type:hex"` labels, opaque ids bare hex, CIDs CID strings.

use std::collections::BTreeMap;

use memvault_core::{
    BucketId, ClusterId, DetailLevel, EdgeId, NodeKind, QueryScope, RetractionMode,
};
use serde::{Deserialize, Serialize};

use crate::wire::GrantAudienceWire;

// ── Query scope as query parameters ─────────────────────────────────

/// A [`QueryScope`] as query parameters, for the scope-aware reads
/// (`GET /nodes`, `/nodes/count`, `/search`, `/docs/{id}`, `/labels/{id}`).
///
/// The server never widens a scope from these: it checks every bucket named
/// (an unreadable one answers 404), falls back to the caller's agent bucket
/// when none is named, and admits retracted nodes only to callers who may see
/// them (`standards/query-scope.md`).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ScopeParams {
    /// Comma-separated bucket ids (hex).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bucket: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub view: Option<String>,
    /// `doc` | `file` | `entity`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    /// An entity kind (e.g. `person`), entities only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub entity_kind: Option<String>,
    /// `active` | `include` | `only`. Absent: the caller's default (retracted
    /// nodes included for those who may see them).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retraction: Option<String>,
    /// `summary` | `full`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub exclude_reserved: bool,
}

impl ScopeParams {
    /// The parameters for `scope`.
    pub fn from_scope(scope: &QueryScope) -> Self {
        Self {
            bucket: scope.buckets.explicit().map(|bs| {
                bs.iter()
                    .map(|b| hex::encode(b.0))
                    .collect::<Vec<_>>()
                    .join(",")
            }),
            view: scope.view.clone(),
            kind: scope.kind.map(|k| k.node_types()[0].to_string()),
            entity_kind: scope.entity_kind.clone(),
            retraction: Some(
                match scope.retraction {
                    RetractionMode::ActiveOnly => "active",
                    RetractionMode::IncludeRetracted => "include",
                    RetractionMode::RetractedOnly => "only",
                }
                .to_string(),
            ),
            detail: match scope.detail {
                DetailLevel::Summary => None,
                DetailLevel::Full => Some("full".to_string()),
            },
            exclude_reserved: scope.exclude_reserved,
        }
    }

    /// The buckets named (an empty list when none is).
    pub fn buckets(&self) -> Result<Vec<BucketId>, String> {
        self.bucket
            .as_deref()
            .unwrap_or("")
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(|h| BucketId::from_hex(h).map_err(|_| "invalid bucket hex".to_string()))
            .collect()
    }

    /// The retraction mode asked for, if any.
    pub fn retraction(&self) -> Result<Option<RetractionMode>, String> {
        match self.retraction.as_deref() {
            None | Some("") => Ok(None),
            Some("active") => Ok(Some(RetractionMode::ActiveOnly)),
            Some("include") => Ok(Some(RetractionMode::IncludeRetracted)),
            Some("only") => Ok(Some(RetractionMode::RetractedOnly)),
            Some(other) => Err(format!("unknown retraction mode: {other}")),
        }
    }

    /// The scope's view, kind, entity kind, detail and reserved-kind filter
    /// (buckets and retraction are the server's to decide).
    pub fn base_scope(&self) -> Result<QueryScope, String> {
        let kind = match self.kind.as_deref() {
            None | Some("") => None,
            Some(k) => {
                Some(NodeKind::from_node_type(k).ok_or_else(|| format!("unknown node kind: {k}"))?)
            }
        };
        let detail = match self.detail.as_deref() {
            None | Some("") | Some("summary") => DetailLevel::Summary,
            Some("full") => DetailLevel::Full,
            Some(other) => return Err(format!("unknown detail level: {other}")),
        };
        let mut scope = QueryScope::all()
            .with_view(self.view.clone().filter(|v| !v.is_empty()))
            .with_kind(kind)
            .with_entity_kind(self.entity_kind.clone().filter(|k| !k.is_empty()))
            .with_detail(detail);
        if self.exclude_reserved {
            scope = scope.without_reserved();
        }
        Ok(scope)
    }
}

/// `?limit=` alone.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LimitParams {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<usize>,
}

/// `?reason=` for a retraction or revocation.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ReasonParams {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// A body carrying only a reason (archive, grant revocation, token
/// revocation).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReasonRequest {
    pub reason: String,
}

// ── Nodes ───────────────────────────────────────────────────────────

/// The answer to creating a node: its `"type:hex"` label.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeCreated {
    pub node_id: String,
}

/// The answer to creating an edge.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EdgeCreated {
    #[serde(with = "crate::wire::hex_id")]
    pub edge_id: EdgeId,
}

/// The answer to a write that produced a block: its CID.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CidReceipt {
    #[serde(with = "crate::wire::cid_str")]
    pub cid: Vec<u8>,
}

/// `GET /labels/{node_id}`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeLabel {
    pub node_id: String,
    pub label: Option<String>,
}

/// `GET /nodes/{node_id}/bucket`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeBucket {
    #[serde(default, with = "crate::wire::hex_id_opt")]
    pub bucket_id: Option<BucketId>,
}

/// `PUT`/`DELETE /tags/{node_id}`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TagsRequest {
    pub tags: Vec<(String, String)>,
}

/// `GET /nodes/{node_id}`: any node, tagged by `node_type`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "node_type", rename_all = "snake_case")]
pub enum NodeWire {
    Entity {
        #[serde(flatten)]
        entity: crate::wire::EntityWire,
        tags: Vec<(String, String)>,
    },
    Doc(DocWire),
    File {
        node_id: String,
        manifest: Option<crate::types::FileManifestInfo>,
        tags: Vec<(String, String)>,
    },
}

// ── Documents ───────────────────────────────────────────────────────

/// A document: `POST /docs` (201) and `GET /docs/{id}`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DocWire {
    /// `"doc:<hex>"`.
    pub node_id: String,
    /// The envelope written, on a create.
    #[serde(
        default,
        with = "crate::wire::cid_str_opt",
        skip_serializing_if = "Option::is_none"
    )]
    pub cid: Option<Vec<u8>>,
    pub body: String,
    #[serde(default)]
    pub frontmatter: BTreeMap<String, serde_json::Value>,
    #[serde(default)]
    pub tags: Vec<(String, String)>,
}

/// `POST /docs`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CreateDocRequest {
    pub body: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub frontmatter: Option<BTreeMap<String, serde_json::Value>>,
    #[serde(default)]
    pub tags: Vec<(String, String)>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub visibility: Option<String>,
    /// A VFS path to place the new document at.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vfs_path: Option<String>,
    /// Bucket id (hex); the caller's agent bucket when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bucket: Option<String>,
    /// A document id (hex) chosen by the client, so the id it hands out is
    /// the stored one. Refused if taken.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
}

/// `GET /docs` query.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ListDocsParams {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tag_ns: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tag_val: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bucket: Option<String>,
    /// Retracted documents too — honoured only for callers who may see them.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub include_retracted: Option<bool>,
}

// ── Entities, links, traversal ──────────────────────────────────────

/// `POST /entities`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateEntityRequest {
    pub kind: String,
    #[serde(default)]
    pub props: BTreeMap<String, serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub visibility: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vfs_path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bucket: Option<String>,
}

/// `GET /entities` query.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ListEntitiesParams {
    /// An entity kind to keep.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bucket: Option<String>,
    /// Retracted entities too — honoured only for callers who may see them.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub include_retracted: Option<bool>,
}

/// `POST /links`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateLinkRequest {
    /// Source node label.
    pub source: String,
    /// Target node label.
    pub target: String,
    pub relation: String,
    #[serde(default)]
    pub weight: Option<f32>,
    #[serde(default)]
    pub props: BTreeMap<String, serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub visibility: Option<String>,
}

// ── Files ───────────────────────────────────────────────────────────

/// The `meta` part of a `POST /files` upload (JSON): what the multipart
/// file part can't carry.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct UploadMeta {
    #[serde(default)]
    pub tags: Vec<(String, String)>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub visibility: Option<String>,
}

/// The answer to `POST /files` (201).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileUploaded {
    /// The manifest's CID.
    #[serde(with = "crate::wire::cid_str")]
    pub cid: Vec<u8>,
    /// `"file:<hex>"`.
    pub node_id: String,
    pub name: String,
}

/// A pinned file (`GET /pins`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PinInfo {
    #[serde(with = "crate::wire::cid_str")]
    pub cid: Vec<u8>,
    pub name: String,
}

/// `GET /files/{cid}/extracted-text`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtractedText {
    pub text: Option<String>,
}

// ── Search ──────────────────────────────────────────────────────────

/// `GET /search` query (with [`ScopeParams`] alongside).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SearchParams {
    pub q: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<usize>,
}

// ── Tokens ──────────────────────────────────────────────────────────

/// `POST /admin/tokens`. Exactly one of `agent_role` / `node_role`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IssueTokenRequest {
    /// `agenthost` | `auditor` | `service` | `admin`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_role: Option<String>,
    /// `node` | `admin`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node_role: Option<String>,
    pub ttl_secs: u64,
    pub max_uses: u32,
    #[serde(default)]
    pub label: Option<String>,
    /// Dialable multiaddrs of the issuing node to embed in the token.
    #[serde(default)]
    pub issuer_addrs: Vec<String>,
}

impl IssueTokenRequest {
    /// The role fields for `role`.
    pub fn role_fields(role: memvault_auth::TokenRole) -> (Option<String>, Option<String>) {
        use memvault_auth::{AgentRole, NodeRole, TokenRole};
        match role {
            TokenRole::Agent(r) => (
                Some(
                    match r {
                        AgentRole::AgentHost => "agenthost",
                        AgentRole::Auditor => "auditor",
                        AgentRole::Service => "service",
                        AgentRole::Admin => "admin",
                    }
                    .to_string(),
                ),
                None,
            ),
            TokenRole::Node(r) => (
                None,
                Some(
                    match r {
                        NodeRole::Node => "node",
                        NodeRole::Admin => "admin",
                    }
                    .to_string(),
                ),
            ),
        }
    }
}

/// The answer to `POST /admin/tokens` (201).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenIssued {
    pub token: String,
}

// ── Buckets ─────────────────────────────────────────────────────────

/// `POST /buckets`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateBucketRequest {
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
    /// Defaults to `Internal`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_visibility: Option<memvault_core::Visibility>,
    /// Defaults to `Internal`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_classification: Option<memvault_core::classification::Classification>,
    /// Only `standard` buckets are created over the API (the default).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role: Option<memvault_core::BucketRole>,
}

/// The answer to `POST /buckets` (201) and `POST /buckets/agent`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BucketCreated {
    #[serde(with = "crate::wire::hex_id")]
    pub bucket_id: BucketId,
}

/// `POST /buckets/agent`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnsureAgentBucketRequest {
    /// The agent's display name (its identity is the token's key).
    pub agent_id: String,
}

/// `PATCH /buckets/{id}`, `PATCH /skills/{id}`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RenameRequest {
    pub name: String,
}

/// `PATCH /agents/{pubkey}`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentLabelRequest {
    pub label: String,
}

/// `POST /buckets/merge`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MergeBucketsRequest {
    #[serde(with = "crate::wire::hex_id_vec")]
    pub sources: Vec<BucketId>,
    #[serde(with = "crate::wire::hex_id")]
    pub canonical: BucketId,
}

/// `POST /buckets/unmerge`, and one edge of `GET /buckets/merges`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BucketMerge {
    #[serde(with = "crate::wire::hex_id")]
    pub source: BucketId,
    #[serde(with = "crate::wire::hex_id")]
    pub canonical: BucketId,
}

/// `POST /buckets/{id}/bind`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BindBucketRequest {
    #[serde(with = "crate::wire::hex_id")]
    pub cluster_id: ClusterId,
}

/// `POST /buckets/{id}/issue-grant`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IssueGrantRequest {
    pub audience: GrantAudienceWire,
    pub actions: Vec<memvault_auth::Action>,
    pub ttl_secs: u64,
}

/// The answer to issuing or submitting a grant (201).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GrantIssued {
    #[serde(with = "crate::wire::cid_str")]
    pub grant_cid: Vec<u8>,
}

/// The answer to `POST /grants/{cid}/revoke` (201).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GrantRevoked {
    #[serde(with = "crate::wire::cid_str")]
    pub revocation_cid: Vec<u8>,
}

/// `POST /buckets/{id}/grants`: an agent-signed grant, built client-side.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubmitGrantRequest {
    /// The DAG-CBOR-encoded `Grant`, hex.
    pub grant_cbor_hex: String,
}

// ── Admin keys ──────────────────────────────────────────────────────

/// The answer to `POST /admin/keys` (201).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminKeyAdmitted {
    #[serde(with = "crate::wire::cid_str")]
    pub admission_cid: Vec<u8>,
}

/// The answer to `POST /admin/keys/retire`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminKeyRetired {
    #[serde(with = "crate::wire::cid_str")]
    pub retirement_cid: Vec<u8>,
}

// ── Sharing ─────────────────────────────────────────────────────────

/// `POST /share/proposals/{cid}/decide`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShareDecideRequest {
    pub approve: bool,
    #[serde(default)]
    pub reason: Option<String>,
}

// ── Skills ──────────────────────────────────────────────────────────

/// `POST /skills`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublishSkillRequest {
    #[serde(flatten)]
    pub spec: crate::types::SkillSpec,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub visibility: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bucket: Option<String>,
}

/// `POST /skills/{id}/resources`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LinkResourceRequest {
    /// Target node label.
    pub node: String,
    pub relation: String,
    #[serde(default)]
    pub path: Option<String>,
    #[serde(default)]
    pub executable: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub visibility: Option<String>,
}

// ── VFS ─────────────────────────────────────────────────────────────

/// `POST /vfs/mkdir`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VfsMkdirRequest {
    pub path: String,
    #[serde(with = "crate::wire::hex_id")]
    pub bucket: BucketId,
}

/// `POST /vfs/link`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VfsLinkRequest {
    pub path: String,
    /// Target node label.
    pub target: String,
    #[serde(with = "crate::wire::hex_id")]
    pub bucket: BucketId,
}

/// `POST /vfs/mv`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VfsMvRequest {
    pub from: String,
    pub to: String,
    #[serde(with = "crate::wire::hex_id")]
    pub bucket: BucketId,
}

/// `GET /vfs/resolve`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VfsResolved {
    pub path: String,
    pub node_id: String,
    pub node_type: String,
    /// The edge from the parent directory (none for the root).
    #[serde(default, with = "crate::wire::hex_id_opt")]
    pub edge_id: Option<EdgeId>,
}

/// `GET /vfs/tree`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VfsTree {
    pub path: String,
    pub tree: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scope_params_round_trip() {
        let b = BucketId([3; 32]);
        let scope = QueryScope::all()
            .with_buckets(vec![b.clone(), BucketId([4; 32])])
            .with_view(Some("v".into()))
            .with_kind(Some(NodeKind::GraphEntity))
            .with_entity_kind(Some("person".into()))
            .with_retraction(RetractionMode::RetractedOnly)
            .with_detail(DetailLevel::Full)
            .without_reserved();
        let p = ScopeParams::from_scope(&scope);
        let q = serde_urlencoded::to_string(&p).unwrap();
        let back: ScopeParams = serde_urlencoded::from_str(&q).unwrap();
        assert_eq!(back.buckets().unwrap(), vec![b, BucketId([4; 32])]);
        assert_eq!(
            back.retraction().unwrap(),
            Some(RetractionMode::RetractedOnly)
        );
        let base = back.base_scope().unwrap();
        assert_eq!(base.view.as_deref(), Some("v"));
        assert_eq!(base.kind, Some(NodeKind::GraphEntity));
        assert_eq!(base.entity_kind.as_deref(), Some("person"));
        assert_eq!(base.detail, DetailLevel::Full);
        assert!(base.exclude_reserved);
    }
}

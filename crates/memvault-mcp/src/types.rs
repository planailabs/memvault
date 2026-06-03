use std::collections::HashMap;

use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::Value;

// -- memvault_put --

#[derive(Deserialize, JsonSchema)]
pub struct PutParams {
    /// The document text to store.
    pub text: String,
    /// Optional title for the document.
    #[serde(default)]
    pub title: Option<String>,
    /// Tags in "scope:label" format.
    #[serde(default)]
    pub tags: Vec<String>,
    /// Visibility level: "internal", "cluster", or "public". Defaults to "internal".
    #[serde(default)]
    pub visibility: Option<String>,
    /// Optional VFS path to place the new document at (e.g. "/notes/my-doc").
    #[serde(default)]
    pub vfs_path: Option<String>,
    /// Optional bucket ID (hex) to scope this operation to. Defaults to the agent bucket.
    #[serde(default)]
    pub bucket: Option<String>,
}

// -- memvault_get --

#[derive(Deserialize, JsonSchema)]
pub struct GetParams {
    /// Hex-encoded CID of the document.
    pub cid: String,
}

// -- memvault_search --

#[derive(Deserialize, JsonSchema)]
pub struct SearchParams {
    /// Search query text.
    pub query: String,
    /// Maximum number of results (default: 10).
    #[serde(default)]
    pub limit: Option<usize>,
    /// Optional tag filter in "scope:label" format.
    #[serde(default)]
    pub tag_filter: Option<String>,
    /// Optional bucket ID (hex). When omitted, searches all accessible buckets.
    #[serde(default)]
    pub bucket: Option<String>,
}

// -- memvault_list --

#[derive(Deserialize, JsonSchema)]
pub struct ListParams {
    /// Maximum number of results (default: 20).
    #[serde(default)]
    pub limit: Option<usize>,
    /// Filter by tag scope.
    #[serde(default)]
    pub tag_scope: Option<String>,
    /// Filter by tag label.
    #[serde(default)]
    pub tag_label: Option<String>,
    /// Optional bucket ID (hex). When omitted, lists across all accessible buckets.
    #[serde(default)]
    pub bucket: Option<String>,
}

// -- memvault_upload_file --

#[derive(Deserialize, JsonSchema)]
pub struct UploadFileParams {
    /// Absolute path to the file on the local filesystem.
    pub path: String,
    /// MIME content type. If omitted, guessed from the file extension.
    #[serde(default)]
    pub content_type: Option<String>,
    /// Tags in "scope:label" format.
    #[serde(default)]
    pub tags: Option<Vec<String>>,
    /// Visibility level: "internal", "federated", or "public". Defaults to "internal".
    #[serde(default)]
    pub visibility: Option<String>,
    /// Optional VFS path to place the new file at (e.g. "/assets/logo.png").
    #[serde(default)]
    pub vfs_path: Option<String>,
    /// Optional bucket ID (hex). Defaults to the agent bucket.
    #[serde(default)]
    pub bucket: Option<String>,
}

// -- memvault_read_range --

#[derive(Deserialize, JsonSchema)]
pub struct ReadRangeParams {
    /// Hex-encoded manifest CID.
    pub manifest_cid: String,
    /// Start byte offset (inclusive).
    pub start: u64,
    /// End byte offset (exclusive).
    pub end: u64,
}

// -- memvault_pin --

#[derive(Deserialize, JsonSchema)]
pub struct PinParams {
    /// Hex-encoded manifest CID of the file to pin.
    pub manifest_cid: String,
}

// -- memvault_unpin --

#[derive(Deserialize, JsonSchema)]
pub struct UnpinParams {
    /// Hex-encoded manifest CID of the file to unpin.
    pub manifest_cid: String,
}

// -- memvault_extract_text --

#[derive(Deserialize, JsonSchema)]
pub struct ExtractTextParams {
    /// Hex-encoded manifest CID of the file to extract text from.
    pub manifest_cid: String,
}

// -- memvault_file_info --

#[derive(Deserialize, JsonSchema)]
pub struct FileInfoParams {
    /// Hex-encoded manifest CID of the file.
    pub manifest_cid: String,
}

// -- memvault_graph_add --

#[derive(Deserialize, JsonSchema)]
pub struct GraphAddParams {
    /// Entity kind/type (e.g. "person", "project", "concept").
    pub kind: String,
    /// Key-value properties for the entity.
    #[serde(default)]
    pub props: HashMap<String, String>,
    /// Visibility level. Defaults to "internal".
    #[serde(default)]
    pub visibility: Option<String>,
    /// Optional VFS path to place the new entity at (e.g. "/projects/acme").
    #[serde(default)]
    pub vfs_path: Option<String>,
    /// Optional bucket ID (hex). Defaults to the agent bucket.
    #[serde(default)]
    pub bucket: Option<String>,
}

// -- memvault_graph_link --

#[derive(Deserialize, JsonSchema)]
pub struct GraphLinkParams {
    /// Hex-encoded source entity ID.
    pub source_id: String,
    /// Hex-encoded target entity ID.
    pub target_id: String,
    /// Relation type (e.g. "knows", "depends_on", "part_of").
    pub relation: String,
    /// Optional edge weight (0.0 to 1.0).
    #[serde(default)]
    pub weight: Option<f32>,
    /// Optional edge properties (key-value map).
    #[serde(default)]
    pub props: HashMap<String, Value>,
    /// Optional bucket ID (hex). Defaults to the agent bucket.
    #[serde(default)]
    pub bucket: Option<String>,
}

// -- memvault_graph_query --

#[derive(Deserialize, JsonSchema)]
pub struct GraphQueryParams {
    /// Hex-encoded entity ID to start traversal from.
    pub from_id: String,
    /// Optional relation filter.
    #[serde(default)]
    pub relation: Option<String>,
    /// Maximum traversal depth (default: 2).
    #[serde(default)]
    pub max_depth: Option<usize>,
}

// -- memvault_link --

#[derive(Deserialize, JsonSchema)]
pub struct LinkParams {
    /// Source node as "entity:<hex>", "doc:<hex>", or "file:<hex>".
    pub source: String,
    /// Target node as "entity:<hex>", "doc:<hex>", or "file:<hex>".
    pub target: String,
    /// Relation type (e.g. "references", "evidence_for", "related_to").
    pub relation: String,
    /// Optional edge weight (0.0 to 1.0).
    #[serde(default)]
    pub weight: Option<f32>,
    /// Optional edge properties (key-value map).
    #[serde(default)]
    pub props: HashMap<String, Value>,
    /// Optional bucket ID (hex). Defaults to the agent bucket.
    #[serde(default)]
    pub bucket: Option<String>,
}

// -- memvault_edges --

#[derive(Deserialize, JsonSchema)]
pub struct EdgesOfParams {
    /// Node to query — "entity:<hex>", "doc:<hex>", or "file:<hex>".
    pub node: String,
}

// -- memvault_unlink --

#[derive(Deserialize, JsonSchema)]
pub struct UnlinkParams {
    /// Hex-encoded edge ID to remove.
    pub edge_id: String,
    /// Source node — "entity:<hex>", "doc:<hex>", or "file:<hex>".
    pub source: String,
}

// -- memvault_list_all --

#[derive(Deserialize, JsonSchema)]
pub struct ListAllParams {
    /// Maximum number of results (default: 100).
    #[serde(default)]
    pub limit: Option<usize>,
    /// Optional view name to filter by.
    #[serde(default)]
    pub view: Option<String>,
    /// Optional bucket ID (hex). When omitted, lists across all accessible buckets.
    #[serde(default)]
    pub bucket: Option<String>,
}

// -- memvault_tag --

#[derive(Deserialize, JsonSchema)]
pub struct TagParams {
    /// Node to tag — "entity:<hex>", "doc:<hex>", or "file:<hex>".
    pub node: String,
    /// Tags to add in "scope:label" format.
    pub tags: Vec<String>,
    /// Optional bucket ID (hex). Defaults to the agent bucket.
    #[serde(default)]
    pub bucket: Option<String>,
}

// -- memvault_untag --

#[derive(Deserialize, JsonSchema)]
pub struct UntagParams {
    /// Node to untag — "entity:<hex>", "doc:<hex>", or "file:<hex>".
    pub node: String,
    /// Tags to remove in "scope:label" format.
    pub tags: Vec<String>,
    /// Optional bucket ID (hex). Defaults to the agent bucket.
    #[serde(default)]
    pub bucket: Option<String>,
}

// -- memvault_get_tags --

#[derive(Deserialize, JsonSchema)]
pub struct GetTagsParams {
    /// Node — "entity:<hex>", "doc:<hex>", or "file:<hex>".
    pub node: String,
}

// -- memvault_view_list --
// (no params)

// -- memvault_view_create --

#[derive(Deserialize, JsonSchema)]
pub struct ViewCreateParams {
    /// Name of the view.
    pub name: String,
    /// Required tags in "scope:label" format. Items must have ALL of these to appear.
    pub tags: Vec<String>,
}

// -- memvault_view_update --

#[derive(Deserialize, JsonSchema)]
pub struct ViewUpdateParams {
    /// Name of the view to update.
    pub name: String,
    /// New set of required tags in "scope:label" format.
    pub tags: Vec<String>,
}

// -- memvault_view_delete --

#[derive(Deserialize, JsonSchema)]
pub struct ViewDeleteParams {
    /// Name of the view to delete.
    pub name: String,
}

// -- Bucket tools --

#[derive(Deserialize, JsonSchema)]
pub struct BucketListParams {}

#[derive(Deserialize, JsonSchema)]
pub struct BucketCreateParams {
    /// Name for the new bucket.
    pub name: String,
    /// Optional description.
    #[serde(default)]
    pub description: Option<String>,
}

#[derive(Deserialize, JsonSchema)]
pub struct BucketGetParams {
    /// Hex-encoded bucket ID.
    pub id: String,
}

#[derive(Deserialize, JsonSchema)]
pub struct BucketRenameParams {
    /// Hex-encoded bucket ID.
    pub id: String,
    /// New name for the bucket.
    pub name: String,
}

#[derive(Deserialize, JsonSchema)]
pub struct AgentRenameParams {
    /// Hex-encoded agent ed25519 pubkey (the canonical agent identity).
    pub agent_pubkey: String,
    /// New display label. Display-only — does not affect access.
    pub label: String,
}

#[derive(Deserialize, JsonSchema)]
pub struct BucketArchiveParams {
    /// Hex-encoded bucket ID.
    pub id: String,
    /// Reason for archiving.
    pub reason: String,
}

#[derive(Deserialize, JsonSchema)]
pub struct BucketGrantsListParams {
    /// Optional hex-encoded bucket ID. When omitted, aggregates across every
    /// bucket the agent can currently list.
    #[serde(default)]
    pub bucket: Option<String>,
}

#[derive(Deserialize, JsonSchema, Default)]
pub struct ShareInboxParams {}

#[derive(Deserialize, JsonSchema, Default)]
pub struct ShareOutboxParams {}

#[derive(Deserialize, JsonSchema)]
pub struct ShareDecideParams {
    /// Hex-encoded share proposal CID.
    pub proposal_cid: String,
    /// `true` to approve, `false` to reject.
    pub approve: bool,
    /// Optional reason (typically provided when rejecting).
    #[serde(default)]
    pub reason: Option<String>,
    /// Must be set to `true` on the second call to actually commit the decision.
    /// First call (default `false`) returns the proposal preview without writing.
    #[serde(default)]
    pub confirm: bool,
}

// -- memvault_get_entity --

#[derive(Deserialize, JsonSchema)]
pub struct GetEntityParams {
    /// Hex-encoded entity ID.
    pub id: String,
}

// -- memvault_list_entities --

#[derive(Deserialize, JsonSchema)]
pub struct ListEntitiesParams {
    /// Maximum number of results (default: 50).
    #[serde(default)]
    pub limit: Option<usize>,
    /// Optional bucket ID (hex). When omitted, lists across all accessible buckets.
    #[serde(default)]
    pub bucket: Option<String>,
}

// -- memvault_traverse --

#[derive(Deserialize, JsonSchema)]
pub struct TraverseParams {
    /// Starting node — "entity:<hex>", "doc:<hex>", or "file:<hex>".
    pub from: String,
    /// Optional relation filter.
    #[serde(default)]
    pub relation: Option<String>,
    /// Maximum traversal depth (default: 2).
    #[serde(default)]
    pub max_depth: Option<usize>,
}

// -- memvault_audit --

#[derive(Deserialize, JsonSchema)]
pub struct AuditParams {
    /// Maximum number of results (default: 50).
    #[serde(default)]
    pub limit: Option<usize>,
    /// Filter by operation kind (e.g. "DocCreate", "EntityCreate", "AttachFile").
    #[serde(default)]
    pub op_kind: Option<String>,
    /// Optional bucket ID (hex). When omitted, audits across all accessible buckets.
    #[serde(default)]
    pub bucket: Option<String>,
}

// -- memvault_doc_history --

#[derive(Deserialize, JsonSchema)]
pub struct DocHistoryParams {
    /// Hex-encoded document ID.
    pub doc_id: String,
}

// -- memvault_retract --

#[derive(Deserialize, JsonSchema)]
pub struct RetractParams {
    /// Node to retract — "doc:<hex>", "entity:<hex>", or "file:<hex>".
    pub node: String,
    /// Reason for retraction.
    pub reason: String,
}

// ── VFS tools ───────────────────────────────────────────────────────

#[derive(Deserialize, JsonSchema)]
pub struct VfsLsParams {
    /// Absolute VFS path to list (e.g. "/", "/projects").
    pub path: String,
    /// If true, list recursively. Defaults to false.
    #[serde(default)]
    pub recursive: Option<bool>,
    /// Optional bucket ID (hex). Defaults to the agent bucket. VFS is
    /// per-bucket — a path resolves differently in each bucket.
    #[serde(default)]
    pub bucket: Option<String>,
}

#[derive(Deserialize, JsonSchema)]
pub struct VfsResolveParams {
    /// Absolute VFS path to resolve (e.g. "/projects/acme/spec.md").
    pub path: String,
    /// Optional bucket ID (hex). Defaults to the agent bucket.
    #[serde(default)]
    pub bucket: Option<String>,
}

#[derive(Deserialize, JsonSchema)]
pub struct VfsMkdirParams {
    /// Absolute VFS path for the new directory (e.g. "/projects/acme"). Intermediate directories are created automatically.
    pub path: String,
    /// Optional bucket ID (hex). Defaults to the agent bucket.
    #[serde(default)]
    pub bucket: Option<String>,
}

#[derive(Deserialize, JsonSchema)]
pub struct VfsLinkParams {
    /// Absolute VFS path where the node should appear (e.g. "/projects/acme/spec.md").
    pub path: String,
    /// Target node to place at the path — "doc:<hex>", "entity:<hex>", or "file:<hex>".
    pub target: String,
    /// Optional bucket ID (hex). Defaults to the agent bucket.
    #[serde(default)]
    pub bucket: Option<String>,
}

#[derive(Deserialize, JsonSchema)]
pub struct VfsUnlinkParams {
    /// Absolute VFS path to remove (e.g. "/projects/old-spec.md"). The underlying node is NOT deleted.
    pub path: String,
    /// Optional bucket ID (hex). Defaults to the agent bucket.
    #[serde(default)]
    pub bucket: Option<String>,
}

#[derive(Deserialize, JsonSchema)]
pub struct VfsMvParams {
    /// Source VFS path.
    pub from: String,
    /// Destination VFS path.
    pub to: String,
    /// Optional bucket ID (hex). Defaults to the agent bucket.
    #[serde(default)]
    pub bucket: Option<String>,
}

#[derive(Deserialize, JsonSchema)]
pub struct VfsTreeParams {
    /// Root path for the tree (defaults to "/").
    #[serde(default)]
    pub path: Option<String>,
    /// Maximum depth to display (defaults to 5).
    #[serde(default)]
    pub max_depth: Option<usize>,
    /// Optional bucket ID (hex). Defaults to the agent bucket.
    #[serde(default)]
    pub bucket: Option<String>,
}

#[derive(Deserialize, JsonSchema)]
pub struct VfsFindParams {
    /// Node ID to search for — "doc:<hex>", "entity:<hex>", or "file:<hex>".
    pub node: String,
    /// Optional bucket ID (hex). Defaults to the agent bucket.
    #[serde(default)]
    pub bucket: Option<String>,
}

// -- Export tools --

#[derive(Deserialize, JsonSchema)]
pub struct ExportNodeParams {
    /// Node ID to export — "doc:<hex>", "entity:<hex>", or "file:<hex>".
    pub node_id: String,
    /// Include historical versions (applies to documents).
    #[serde(default)]
    pub history: Option<bool>,
    // bucket: intentionally absent — `memvault_export::export_node` does
    // not yet take a bucket filter, so exposing one here would be
    // misleading. Add when the export crate gains the parameter.
}

#[derive(Deserialize, JsonSchema)]
pub struct ExportVaultParams {
    /// Output directory or tar file path.
    pub output_path: String,
    /// Include historical versions of documents.
    #[serde(default)]
    pub history: Option<bool>,
    /// Export as tar archive.
    #[serde(default)]
    pub tar: Option<bool>,
    /// Filter by tag (scope:label format).
    #[serde(default)]
    pub tag: Option<String>,
    /// Filter by view name.
    #[serde(default)]
    pub view: Option<String>,
    // bucket: intentionally absent — `ExportOptions` doesn't carry a
    // bucket filter today. See ExportNodeParams for the same note.
}

// -- memvault_skill_publish --

#[derive(Deserialize, JsonSchema)]
pub struct SkillPublishParams {
    /// Human-readable skill name.
    pub name: String,
    /// One-line description (used for discovery/search).
    #[serde(default)]
    pub description: Option<String>,
    /// When the skill should be used (trigger text).
    #[serde(default)]
    pub trigger: Option<String>,
    /// Optional inline instruction prose (the SKILL.md body). When set, a
    /// document is created and linked as the skill's primary instruction.
    #[serde(default)]
    pub instruction_body: Option<String>,
    /// Visibility level. Defaults to "internal".
    #[serde(default)]
    pub visibility: Option<String>,
    /// Optional bucket ID (hex). Defaults to the agent bucket.
    #[serde(default)]
    pub bucket: Option<String>,
}

// -- memvault_skill_list --

#[derive(Deserialize, JsonSchema)]
pub struct SkillListParams {
    /// Maximum number of skills to return.
    #[serde(default)]
    pub limit: Option<usize>,
    /// Optional bucket ID (hex) to scope the listing.
    #[serde(default)]
    pub bucket: Option<String>,
}

// -- memvault_skill_get --

#[derive(Deserialize, JsonSchema)]
pub struct SkillGetParams {
    /// Skill entity ID (hex or "entity:<hex>").
    pub id: String,
}

// -- memvault_skill_rename --

#[derive(Deserialize, JsonSchema)]
pub struct SkillRenameParams {
    /// Skill entity ID (hex or "entity:<hex>").
    pub id: String,
    /// New display name.
    pub name: String,
}

// -- memvault_skill_delete --

#[derive(Deserialize, JsonSchema)]
pub struct SkillDeleteParams {
    /// Skill entity ID (hex or "entity:<hex>").
    pub id: String,
    /// Optional retraction reason.
    #[serde(default)]
    pub reason: Option<String>,
}

// -- memvault_skill_link_resource --

#[derive(Deserialize, JsonSchema)]
pub struct SkillLinkResourceParams {
    /// Skill entity ID (hex or "entity:<hex>").
    pub skill_id: String,
    /// Node to link — "doc:<hex>", "file:<hex>", or "entity:<hex>".
    pub node: String,
    /// Edge relation: "skill:instruction", "skill:resource" (default), or
    /// "skill:requires".
    #[serde(default)]
    pub relation: Option<String>,
    /// Relative path within the hydrated bundle (e.g. "scripts/run.sh").
    #[serde(default)]
    pub path: Option<String>,
    /// Set the executable bit when the bundle is materialized to disk.
    #[serde(default)]
    pub executable: bool,
    /// Visibility level. Defaults to "internal".
    #[serde(default)]
    pub visibility: Option<String>,
}

// -- memvault_skill_unlink_resource --

#[derive(Deserialize, JsonSchema)]
pub struct SkillUnlinkResourceParams {
    /// Skill entity ID (hex or "entity:<hex>").
    pub skill_id: String,
    /// Hex-encoded edge ID to remove.
    pub edge_id: String,
}

// -- memvault_skill_hydrate --

#[derive(Deserialize, JsonSchema)]
pub struct SkillHydrateParams {
    /// Skill entity ID (hex or "entity:<hex>").
    pub id: String,
    /// Destination directory to materialize the bundle into (created if absent).
    pub dest: String,
    /// Set the executable bit on resources flagged executable. Defaults to
    /// false — only enable for skills whose author you trust, since this
    /// writes directly-runnable code to disk.
    #[serde(default)]
    pub executable: bool,
}

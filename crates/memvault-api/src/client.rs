//! The MemvaultClient trait — the full API surface.

use async_trait::async_trait;
use memvault_auth::TokenRole;
use memvault_core::classification::Classification;
use memvault_core::{
    BucketId, ClusterId, DocId, EdgeId, EntityId, NodeRef, QueryScope, Visibility,
};
use memvault_doc::{Document, Edge, Entity, TextPatch};
use memvault_query::{AuditQuery, AuditRecord, SearchHit, UnifiedHit};

use crate::error::Result;
use crate::types::{
    BucketInfo, DocSummary, GrantInfo, NodeStatus, NodeSummary, RotationInfo, ScopeCount,
    ShareProposalInfo, SkillBundle, SkillInfo, SkillSpec, TokenStatus, TraversalHit,
};

/// The complete memvault API surface.
///
/// All write and list operations accept an optional `bucket` parameter.
/// When `None`, implementations query all accessible buckets (read) or
/// require an explicit bucket (write).
#[async_trait]
pub trait MemvaultClient: Send + Sync {
    // -- Documents --
    async fn put_doc(
        &self,
        doc: Document,
        tags: Vec<(String, String)>,
        vis: Visibility,
        bucket: Option<&BucketId>,
    ) -> Result<Vec<u8>>;
    async fn get_doc(&self, id: &DocId) -> Result<Option<Document>>;
    async fn edit_doc(&self, id: &DocId, patch: TextPatch) -> Result<Vec<u8>>;
    async fn list_docs(
        &self,
        tag_filter: Option<(String, String)>,
        limit: usize,
        bucket: Option<&BucketId>,
    ) -> Result<Vec<DocSummary>>;

    // -- Files --
    async fn upload_file(
        &self,
        data: &[u8],
        filename: Option<&str>,
        mime_type: &str,
        tags: Vec<(String, String)>,
        visibility: &str,
        bucket: Option<&BucketId>,
    ) -> Result<Vec<u8>>;
    async fn read_file(&self, manifest_cid: &[u8]) -> Result<Vec<u8>>;
    async fn read_file_range(&self, manifest_cid: &[u8], start: u64, end: u64) -> Result<Vec<u8>>;
    async fn read_extracted_text(&self, manifest_cid: &[u8]) -> Result<Option<String>>;
    async fn pin_file(&self, manifest_cid: &[u8]) -> Result<()>;
    async fn unpin_file(&self, manifest_cid: &[u8]) -> Result<()>;
    async fn list_pinned(&self) -> Result<Vec<(Vec<u8>, String)>>; // (cid, reason)
    async fn get_file_manifest(&self, manifest_cid: &[u8]) -> Result<Option<Vec<u8>>>; // returns JSON

    // -- Graph --
    //
    // `add_entity_internal` is the raw, *unvalidated* create — the required op
    // each client implements. It is crate-internal by convention (the
    // `_internal` name): only trusted callers that legitimately create reserved
    // kinds (VFS mkdir, skill_publish) call it directly. Everything else calls
    // the validated `add_entity` below. (It can't be `pub(crate)`: trait items
    // take the trait's visibility, and the op must stay trait-dispatched so the
    // default methods and the `&dyn` VFS helpers can reach it.)
    async fn add_entity_internal(
        &self,
        entity: Entity,
        vis: Visibility,
        bucket: Option<&BucketId>,
    ) -> Result<EntityId>;
    async fn get_entity(&self, id: &EntityId) -> Result<Option<Entity>>;
    async fn list_entities(&self, limit: usize, bucket: Option<&BucketId>) -> Result<Vec<Entity>>;
    async fn entity_history(&self, id: &EntityId) -> Result<Vec<AuditRecord>>;
    /// The bucket a node currently lives in, if resolvable. Default `None`;
    /// `LocalClient` resolves it from the store. Used e.g. to keep a skill's
    /// uploaded resources in the skill's own bucket.
    async fn node_bucket(&self, node: &NodeRef) -> Result<Option<BucketId>> {
        let _ = node;
        Ok(None)
    }

    // -- Links (cross-type edges) --
    /// Create a directed edge from any node to any node.
    async fn add_link(&self, source: &NodeRef, edge: Edge, vis: Visibility) -> Result<EdgeId>;
    /// Remove an edge by source and edge ID.
    async fn remove_link_from(&self, source: &NodeRef, edge_id: &EdgeId) -> Result<()>;
    /// List all edges (incoming + outgoing) touching a node.
    async fn edges_of(&self, node: &NodeRef) -> Result<Vec<(NodeRef, Edge)>>;
    /// Traverse the graph from any node, following edges across types.
    async fn traverse_from(
        &self,
        from: &NodeRef,
        relation: Option<&str>,
        max_depth: usize,
    ) -> Result<Vec<TraversalHit>>;

    // -- Validated node API (the default everyone should call) --
    //
    // These wrap the raw `*_internal` ops with a reserved-kind guard, so the
    // managed aggregates (skill, vfs:dir) can only be created/retracted through
    // their dedicated APIs. The guard lives here once rather than at every
    // entry point; user-facing surfaces (HTTP, MCP, CLI) call these.

    /// Create an entity, rejecting reserved/managed kinds (skill, vfs:dir).
    async fn add_entity(
        &self,
        entity: Entity,
        vis: Visibility,
        bucket: Option<&BucketId>,
    ) -> Result<EntityId> {
        if memvault_core::is_reserved_entity_kind(&entity.kind) {
            return Err(crate::error::ApiError::Invalid(format!(
                "'{}' is a managed kind — use the dedicated skill/VFS API, not the generic entity API",
                entity.kind
            )));
        }
        self.add_entity_internal(entity, vis, bucket).await
    }

    /// Retract a node by id, refusing reserved/managed entities (skill,
    /// vfs:dir) — those must be removed via their dedicated API.
    async fn retract_node(&self, node_id: &str, reason: &str) -> Result<()> {
        if let Some(NodeRef::Entity(eid)) = NodeRef::from_tag_label(node_id) {
            if let Some(e) = self.get_entity(&eid).await? {
                if memvault_core::is_reserved_entity_kind(&e.kind) {
                    return Err(crate::error::ApiError::Invalid(format!(
                        "'{}' is a managed kind — use the dedicated skill/VFS API, not the generic node API",
                        e.kind
                    )));
                }
            }
        }
        self.retract_node_internal(node_id, reason).await
    }

    // -- VFS (first-class, like skills) --
    //
    // The per-bucket virtual filesystem is a managed aggregate (vfs:dir entities
    // + vfs:child edges). These are the dispatch points: `LocalClient` runs the
    // `crate::vfs::*` logic in-process (creating dirs via the raw internal node
    // op, which is why VFS never touches the guarded generic entity API); the
    // HTTP client overrides them to hit the dedicated `/vfs/*` endpoints in one
    // round trip. Callers (MCP tools, web UI, CLI) use these, not the free fns.

    /// `mkdir -p`; returns the leaf directory's EntityId.
    async fn vfs_mkdir(&self, bucket: &BucketId, path: &str) -> Result<EntityId> {
        crate::vfs::mkdir(self, bucket, path).await
    }

    /// List a directory's entries (optionally recursive).
    async fn vfs_ls(
        &self,
        bucket: &BucketId,
        path: &str,
        recursive: bool,
    ) -> Result<Vec<crate::vfs::VfsEntry>> {
        crate::vfs::ls(self, bucket, path, recursive).await
    }

    /// Resolve a path to its `(node, parent-edge)`, or `None` if absent.
    async fn vfs_resolve(
        &self,
        bucket: &BucketId,
        path: &str,
    ) -> Result<Option<(NodeRef, Option<EdgeId>)>> {
        crate::vfs::resolve_path(self, bucket, path).await
    }

    /// Link an existing node at a path (creating parent dirs as needed).
    async fn vfs_link(&self, bucket: &BucketId, path: &str, target: &NodeRef) -> Result<EdgeId> {
        crate::vfs::link_at_path(self, bucket, path, target).await
    }

    /// Remove an entry from a path (the underlying node is not deleted).
    async fn vfs_unlink(&self, bucket: &BucketId, path: &str) -> Result<()> {
        crate::vfs::unlink_path(self, bucket, path).await
    }

    /// Move/rename a path.
    async fn vfs_mv(&self, bucket: &BucketId, from: &str, to: &str) -> Result<()> {
        crate::vfs::mv_path(self, bucket, from, to).await
    }

    /// Render an ASCII tree under a path.
    async fn vfs_tree(&self, bucket: &BucketId, path: &str, max_depth: usize) -> Result<String> {
        crate::vfs::tree(self, bucket, path, max_depth).await
    }

    /// Find all paths that lead to a target node.
    async fn vfs_find(&self, bucket: &BucketId, target: &NodeRef) -> Result<Vec<String>> {
        crate::vfs::find_paths(self, bucket, target).await
    }

    // -- Tags --
    /// Add tags to an existing item (doc, entity, or file).
    async fn add_tags(&self, node_id: &str, tags: Vec<(String, String)>) -> Result<()>;
    /// Remove tags from an existing item.
    async fn remove_tags(&self, node_id: &str, tags: Vec<(String, String)>) -> Result<()>;
    /// Get the effective tags for a node (original + added - removed).
    async fn get_tags(&self, node_id: &str) -> Result<Vec<(String, String)>>;

    // -- Views (saved tag filter sets) --
    async fn list_views(&self) -> Result<Vec<crate::types::View>>;
    async fn create_view(&self, view: crate::types::View) -> Result<()>;
    async fn delete_view(&self, name: &str) -> Result<()>;
    async fn get_view(&self, name: &str) -> Result<Option<crate::types::View>>;
    async fn update_view(&self, view: crate::types::View) -> Result<()>;

    // -- Search --
    async fn search(&self, query: &str, limit: usize) -> Result<Vec<SearchHit>>;
    /// Unified search across all node types (docs, entities, files).
    async fn search_unified(
        &self,
        query: &str,
        limit: usize,
    ) -> Result<Vec<memvault_query::UnifiedHit>>;
    /// List all nodes, optionally filtered by a view name. Returns (node_id, node_type, label, tags).
    async fn list_all(
        &self,
        view_name: Option<&str>,
        limit: usize,
        bucket: Option<&BucketId>,
    ) -> Result<Vec<(String, String, String, Vec<(String, String)>)>>;
    /// Return node_ids of all items matching a view's required tags.
    async fn view_members(&self, view_name: &str) -> Result<Vec<String>>;
    /// Resolve a node_id (tag_label like "entity:<hex>") to a human-readable label.
    async fn resolve_label(&self, node_id: &str) -> Result<Option<String>>;

    // -- Retraction-aware reads (auditor/admin "see retracted" view) --
    //
    // Each mirrors a read method above but takes `include_retracted`. When
    // false they are identical to the base method. When true, retracted
    // entries are NOT filtered out — the caller (an HTTP handler resolving the
    // requester's role, or the web UI's "show retracted" toggle) decides.
    // Default impls ignore the flag (= filtered behaviour); `LocalClient` and
    // the HTTP client override them to honour it.
    async fn list_docs_ex(
        &self,
        tag_filter: Option<(String, String)>,
        limit: usize,
        bucket: Option<&BucketId>,
        include_retracted: bool,
    ) -> Result<Vec<DocSummary>> {
        let _ = include_retracted;
        self.list_docs(tag_filter, limit, bucket).await
    }
    async fn list_entities_ex(
        &self,
        limit: usize,
        bucket: Option<&BucketId>,
        include_retracted: bool,
    ) -> Result<Vec<Entity>> {
        let _ = include_retracted;
        self.list_entities(limit, bucket).await
    }

    // -- Scoped reads (the (view, buckets, retracted) triplet) --
    //
    // These supersede the per-method `bucket` parameter + `*_ex` flag with a
    // single `QueryScope`, and — unlike the legacy methods — can span a *set*
    // of buckets in one call (an agent's accessible set). The default impls
    // honour view + retraction via the legacy methods (single-/all-bucket);
    // `LocalClient` overrides them with true multi-bucket member-set-backed
    // behaviour. Handlers must intersect the scope's buckets with the caller's
    // accessible set before calling — scope never widens visibility.

    /// List nodes matching the scope. Returns node summaries (with retracted flag).
    async fn list_scoped(&self, scope: &QueryScope, limit: usize) -> Result<Vec<NodeSummary>> {
        // Thread the scope's (first explicit) bucket through (see
        // standards/query-scope.md). LocalClient overrides this with a fully
        // scope-aware impl; this default backs the HTTP client.
        let bucket = scope.buckets.explicit().and_then(|v| v.first());
        let rows = self.list_all(scope.view.as_deref(), limit, bucket).await?;
        Ok(rows
            .into_iter()
            .map(|(node_id, node_type, label, tags)| NodeSummary {
                node_id,
                node_type,
                label,
                tags,
                retracted: false,
                detail: None,
            })
            .collect())
    }

    /// Unified search constrained to the scope.
    async fn search_scoped(
        &self,
        _scope: &QueryScope,
        query: &str,
        limit: usize,
    ) -> Result<Vec<UnifiedHit>> {
        self.search_unified(query, limit).await
    }

    /// Active/retracted counts for the scope.
    async fn count_scoped(&self, scope: &QueryScope) -> Result<ScopeCount> {
        let rows = self.list_scoped(scope, usize::MAX).await?;
        let retracted = rows.iter().filter(|r| r.retracted).count() as u64;
        Ok(ScopeCount {
            active: rows.len() as u64 - retracted,
            retracted,
        })
    }

    /// Fetch a document by id, verifying it satisfies the scope (retraction +
    /// bucket + view). Returns `Ok(None)` if absent or out of scope. Supersedes
    /// the `*_ex` by-id getters. Default impl honours only retraction.
    async fn get_doc_scoped(
        &self,
        id: &DocId,
        scope: &QueryScope,
    ) -> Result<Option<Document>> {
        self.get_doc(id).await.map(|d| {
            d.filter(|_| scope.retraction.includes_active())
        })
    }

    /// Fetch an entity by id, verifying it satisfies the scope.
    async fn get_entity_scoped(
        &self,
        id: &EntityId,
        scope: &QueryScope,
    ) -> Result<Option<Entity>> {
        self.get_entity(id).await.map(|e| {
            e.filter(|_| scope.retraction.includes_active())
        })
    }

    /// Resolve a node's label, verifying it satisfies the scope.
    async fn resolve_label_scoped(
        &self,
        node_id: &str,
        scope: &QueryScope,
    ) -> Result<Option<String>> {
        let _ = scope;
        self.resolve_label(node_id).await
    }

    /// Resolve the legacy bucket (used only for adoption of pre-bucket data).
    /// Errors if no `BucketRole::Legacy` bucket is configured.
    async fn legacy_bucket_id(&self) -> Result<BucketId>;

    // -- History & Audit --
    async fn history_of(&self, doc_id: &DocId) -> Result<Vec<AuditRecord>>;
    async fn audit(&self, query: AuditQuery) -> Result<Vec<AuditRecord>>;
    async fn retract(&self, target_cid: &[u8], reason: &str) -> Result<Vec<u8>>;
    /// Retract a node by its tag_label (e.g. "entity:<hex>", "doc:<hex>", "file:<hex>").
    /// Removes it from the search index and marks it as retracted. Raw, unvalidated
    /// op (the `_internal` convention) — call the validated `retract_node` instead
    /// unless you are a trusted caller removing a reserved kind (e.g. skill_delete).
    async fn retract_node_internal(&self, node_id: &str, reason: &str) -> Result<()>;

    // -- Tokens --
    /// Issue a join token. A `TokenRole::Node(NodeRole::Admin)` token also
    /// permits admin-key admission at join (the joiner must present a valid
    /// POP for the admission to mint).
    async fn issue_token_ex(
        &self,
        role: TokenRole,
        ttl_secs: u64,
        max_uses: u32,
        label: Option<String>,
        issuer_addrs: Vec<String>,
    ) -> Result<String>;
    /// Convenience: issue a join token with no embedded issuer addresses.
    async fn issue_token(
        &self,
        role: TokenRole,
        ttl_secs: u64,
        max_uses: u32,
        label: Option<String>,
    ) -> Result<String> {
        self.issue_token_ex(role, ttl_secs, max_uses, label, vec![])
            .await
    }
    async fn list_tokens(&self) -> Result<Vec<TokenStatus>>;
    async fn revoke_token(&self, token_cid: &[u8], reason: &str) -> Result<()>;

    // -- Rotation --
    async fn list_rotations(&self) -> Result<Vec<RotationInfo>>;

    // -- Buckets --
    /// Create a new bucket. Does NOT require a cluster — creates a standalone bucket.
    async fn bucket_create(
        &self,
        name: &str,
        description: Option<&str>,
        default_visibility: Visibility,
        default_classification: Classification,
        role: memvault_doc::BucketRole,
    ) -> Result<BucketId>;

    /// List all buckets in the store.
    async fn bucket_list(&self) -> Result<Vec<BucketInfo>>;

    /// Get a single bucket's info by ID.
    async fn bucket_get(&self, id: &BucketId) -> Result<Option<BucketInfo>>;

    /// Rename a bucket (writes a BucketRename op, LWW by lamport).
    async fn bucket_rename(&self, id: &BucketId, new_name: &str) -> Result<()>;

    /// Set an agent's mutable display label (writes an AgentRename op, latest
    /// wins by wall_ns). Display-only — never affects access control, which
    /// keys on the agent's ed25519 pubkey. `agent_pubkey` is the 32-byte key.
    async fn agent_rename(&self, agent_pubkey: &[u8; 32], new_label: &str) -> Result<()>;

    /// Bind a bucket to a cluster.
    async fn bucket_bind(
        &self,
        bucket_id: &BucketId,
        cluster_id: &ClusterId,
    ) -> Result<()>;

    /// Attach a private bucket to the cluster (flips private_to_peer to None, triggers gossip).
    async fn bucket_attach(&self, id: &BucketId) -> Result<()>;

    /// Archive a bucket (soft-remove: new writes are refused, reads continue, data preserved).
    async fn bucket_archive(&self, id: &BucketId, reason: &str) -> Result<()>;

    /// Find or create the agent's data bucket, keyed by its ed25519 pubkey
    /// (`deterministic_agent_bucket_id(cluster_id, pubkey)` — cryptographically
    /// unique across nodes). `name_hint` is only a display label on the
    /// BucketDecl.
    ///
    /// Over HTTP the server is authoritative: it derives the pubkey from the
    /// caller's verified JWT and ignores the passed bytes, so a client can only
    /// ever ensure *its own* bucket. `LocalClient` uses the passed pubkey
    /// directly. (The former name-string `ensure_agent_bucket(agent_id)` and
    /// the HTTP-only `ensure_agent_bucket_for_pubkey` are folded into this.)
    async fn ensure_agent_bucket(
        &self,
        agent_pubkey: &[u8],
        name_hint: &str,
    ) -> Result<BucketId>;

    /// List capability grants scoped to a bucket.
    async fn bucket_grants_list(&self, bucket_id: &BucketId) -> Result<Vec<GrantInfo>>;

    /// Issue (sign + publish) a capability grant on a bucket. Returns the
    /// stored grant block CID.
    ///
    /// The implementation picks the best signing authority the local node
    /// holds for the bucket (admin key, owner-agent key, or node key) —
    /// callers do not pass a signer. HTTP clients route this through the
    /// `POST /api/v1/buckets/{id}/issue-grant` endpoint, which signs
    /// server-side using the daemon's own keys.
    async fn bucket_grant(
        &self,
        bucket_id: &BucketId,
        audience: memvault_auth::GrantAudience,
        actions: Vec<memvault_auth::Action>,
        ttl_secs: u64,
    ) -> Result<Vec<u8>>;

    /// Revoke a previously-issued grant by its CID. Returns the
    /// revocation block CID. Signed with the same authority that signed
    /// the original grant (admin / owner-agent / node).
    async fn revoke_grant(
        &self,
        grant_cid: &[u8],
        reason: &str,
    ) -> Result<Vec<u8>>;

    // -- Sharing --

    /// List share proposals received by this cluster.
    async fn share_inbox(&self) -> Result<Vec<Vec<u8>>>;

    /// List share proposals sent by this cluster.
    async fn share_outbox(&self) -> Result<Vec<Vec<u8>>>;

    /// Fetch the contents of a share proposal by CID.
    async fn share_get_proposal(&self, proposal_cid: &[u8]) -> Result<Option<ShareProposalInfo>>;

    /// Decide a share proposal (approve or reject).
    async fn share_decide(
        &self,
        proposal_cid: &[u8],
        approve: bool,
        reason: Option<&str>,
    ) -> Result<()>;

    // -- Skills (first-class, like VFS) --
    //
    // A skill is a graph entity (`kind == SKILL_KIND`) that aggregates its
    // component nodes by typed edges. The composition logic lives in
    // `crate::skills` (free functions over the client), mirroring `crate::vfs`;
    // these defaults delegate there. `LocalClient` runs them in-process; the
    // HTTP client overrides them to thread through the `/skills` endpoints.
    // `skill_rename` is the exception — it needs an in-place `EntityUpdate`
    // with no composable primitive, so it stays per-client.

    /// Publish a new skill (manifest + optional inline instruction doc).
    async fn skill_publish(
        &self,
        spec: SkillSpec,
        vis: Visibility,
        bucket: Option<&BucketId>,
    ) -> Result<EntityId> {
        crate::skills::publish(self, spec, vis, bucket).await
    }

    /// List skills (manifest summaries only).
    async fn skill_list(&self, limit: usize, bucket: Option<&BucketId>) -> Result<Vec<SkillInfo>> {
        crate::skills::list(self, limit, bucket).await
    }

    /// Assemble a skill bundle: the manifest plus its linked components.
    async fn skill_get(&self, id: &EntityId) -> Result<Option<SkillBundle>> {
        crate::skills::get(self, id).await
    }

    /// Rename a skill (sets the `name` prop via `EntityUpdate`). Required: no
    /// composable primitive exists for an in-place entity prop update.
    async fn skill_rename(&self, id: &EntityId, new_name: &str) -> Result<()>;

    /// Retract a skill entity (linked component docs/files are left intact).
    async fn skill_delete(&self, id: &EntityId, reason: &str) -> Result<()> {
        crate::skills::delete(self, id, reason).await
    }

    /// Link an existing node (doc/file/entity) to a skill under `relation`.
    async fn skill_link_resource(
        &self,
        skill_id: &EntityId,
        target: &NodeRef,
        relation: &str,
        path: Option<&str>,
        executable: bool,
        vis: Visibility,
    ) -> Result<EdgeId> {
        crate::skills::link_resource(self, skill_id, target, relation, path, executable, vis).await
    }

    /// Remove a resource/instruction/requires edge from a skill.
    async fn skill_unlink_resource(&self, skill_id: &EntityId, edge_id: &EdgeId) -> Result<()> {
        crate::skills::unlink_resource(self, skill_id, edge_id).await
    }

    // -- Status --
    async fn status(&self) -> Result<NodeStatus>;
}

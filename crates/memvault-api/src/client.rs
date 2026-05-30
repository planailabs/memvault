//! The MemvaultClient trait — the full API surface.

use async_trait::async_trait;
use memvault_auth::TokenRole;
use memvault_core::classification::Classification;
use memvault_core::{BucketId, ClusterId, DocId, EdgeId, EntityId, NodeRef, QueryScope, Visibility};
use memvault_doc::{Document, Edge, Entity, TextPatch};
use memvault_query::{AuditQuery, AuditRecord, SearchHit, UnifiedHit};

use crate::error::Result;
use crate::types::{
    BucketInfo, DocSummary, GrantInfo, NodeStatus, NodeSummary, RotationInfo, ScopeCount,
    ShareProposalInfo, TokenStatus, TraversalHit,
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
    async fn add_entity(
        &self,
        entity: Entity,
        vis: Visibility,
        bucket: Option<&BucketId>,
    ) -> Result<EntityId>;
    async fn get_entity(&self, id: &EntityId) -> Result<Option<Entity>>;
    async fn list_entities(&self, limit: usize, bucket: Option<&BucketId>) -> Result<Vec<Entity>>;
    async fn entity_history(&self, id: &EntityId) -> Result<Vec<AuditRecord>>;

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
        let rows = self.list_all(scope.view.as_deref(), limit).await?;
        Ok(rows
            .into_iter()
            .map(|(node_id, node_type, label, tags)| NodeSummary {
                node_id,
                node_type,
                label,
                tags,
                retracted: false,
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
    /// Removes it from the search index and marks it as retracted.
    async fn retract_node(&self, node_id: &str, reason: &str) -> Result<()>;

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

    /// Find or create the agent bucket for the given agent ID.
    /// Used by per-agent MCP servers as the default bucket for writes.
    async fn ensure_agent_bucket(&self, agent_id: &str) -> Result<BucketId>;

    /// Find or create the agent bucket keyed by the agent's ed25519 pubkey.
    /// The bucket id is `deterministic_agent_bucket_id(cluster_id, pubkey)` —
    /// cryptographically unique. `name_hint` is only used as a display
    /// label on the BucketDecl. Prefer this over `ensure_agent_bucket`
    /// when the caller already holds the pubkey (e.g. an HTTP handler
    /// resolving it from a verified JWT) — it skips the name → sigchain
    /// attestation lookup that the name-based path performs.
    async fn ensure_agent_bucket_for_pubkey(
        &self,
        agent_pubkey: &[u8],
        name_hint: &str,
    ) -> Result<BucketId>;

    /// List capability grants scoped to a bucket.
    async fn bucket_grants_list(&self, bucket_id: &BucketId) -> Result<Vec<GrantInfo>>;

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

    // -- Status --
    async fn status(&self) -> Result<NodeStatus>;
}

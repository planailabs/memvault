//! The MemvaultClient trait — the full API surface.

use async_trait::async_trait;
use memvault_auth::TokenRole;
use memvault_core::classification::Classification;
use memvault_core::{
    BucketId, ClusterId, DetailLevel, DocId, EdgeId, EntityId, NodeRef, QueryScope, Visibility,
};
use memvault_doc::{Document, Edge, Entity, TextPatch};
use memvault_query::{AuditQuery, AuditRecord, SearchHit, UnifiedHit};

use crate::error::Result;
use crate::types::{
    BucketInfo, DocSummary, GrantInfo, NodeDetail, NodeStatus, NodeSummary, RotationInfo,
    ScopeCount, ShareProposalInfo, SkillBundle, SkillInfo, SkillResource, SkillSpec, TokenStatus,
    TraversalHit,
};

/// Parse an `"entity:<hex>"` node id into an [`EntityId`].
fn parse_entity_node_id(node_id: &str) -> Option<EntityId> {
    let hex_str = node_id.strip_prefix("entity:")?;
    let bytes = hex::decode(hex_str).ok()?;
    let arr: [u8; 32] = bytes.try_into().ok()?;
    Some(EntityId(arr))
}

/// Build a [`SkillResource`] from an outgoing skill edge.
fn skill_resource_from_edge(edge: &Edge) -> SkillResource {
    SkillResource {
        edge_id: edge.id.clone(),
        node: edge.target.tag_label(),
        relation: edge.relation.clone(),
        path: edge
            .props
            .get(memvault_core::SKILL_PATH_PROP)
            .and_then(|v| v.as_str())
            .map(str::to_string),
        executable: edge
            .props
            .get(memvault_core::SKILL_EXECUTABLE_PROP)
            .and_then(|v| v.as_bool())
            .unwrap_or(false),
        order: edge
            .props
            .get(memvault_core::SKILL_ORDER_PROP)
            .and_then(|v| v.as_i64()),
        label: None,
    }
}

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

    // -- Skills --
    //
    // A skill is a graph entity (`kind == SKILL_KIND`) that aggregates its
    // component nodes by typed edges. These default impls express the logic in
    // terms of the graph/doc/search primitives above, so it lives once, behind
    // the MCP/HTTP/UI layers. `LocalClient` runs them directly against the
    // store; the HTTP client overrides them to thread through dedicated
    // `/skills` endpoints (one round trip → the server's `LocalClient`).

    /// Publish a new skill: create the manifest entity and, if an inline body
    /// is given, a Document linked as the primary instruction. Returns the
    /// skill entity id.
    async fn skill_publish(
        &self,
        spec: SkillSpec,
        vis: Visibility,
        bucket: Option<&BucketId>,
    ) -> Result<EntityId> {
        let mut props: std::collections::BTreeMap<String, serde_json::Value> =
            std::collections::BTreeMap::new();
        props.insert(
            memvault_core::SKILL_NAME_PROP.to_string(),
            serde_json::Value::String(spec.name.clone()),
        );
        if let Some(d) = &spec.description {
            props.insert(
                memvault_core::SKILL_DESCRIPTION_PROP.to_string(),
                serde_json::Value::String(d.clone()),
            );
        }
        if let Some(t) = &spec.trigger {
            props.insert(
                memvault_core::SKILL_TRIGGER_PROP.to_string(),
                serde_json::Value::String(t.clone()),
            );
        }
        let entity = Entity {
            id: EntityId::random(),
            kind: memvault_core::SKILL_KIND.to_string(),
            props,
            edges_out: vec![],
        };
        let skill_id = self.add_entity_internal(entity, vis, bucket).await?;

        if let Some(body) = spec.instruction_body {
            let doc = Document::new(DocId::random(), body, std::collections::BTreeMap::new());
            let doc_id = doc.id.clone();
            self.put_doc(doc, vec![], vis, bucket).await?;
            let mut eprops: std::collections::BTreeMap<String, serde_json::Value> =
                std::collections::BTreeMap::new();
            eprops.insert(
                memvault_core::SKILL_ORDER_PROP.to_string(),
                serde_json::Value::from(0),
            );
            let edge = Edge {
                id: EdgeId::random(),
                relation: memvault_core::SKILL_INSTRUCTION_REL.to_string(),
                target: NodeRef::Doc(doc_id),
                weight: None,
                props: eprops,
                provenance: None,
            };
            self.add_link(&NodeRef::Entity(skill_id.clone()), edge, vis)
                .await?;
        }
        Ok(skill_id)
    }

    /// List skills (manifest summaries only). Narrows to `kind == SKILL_KIND`
    /// via the scoped query's `entity_kind` filter.
    async fn skill_list(&self, limit: usize, bucket: Option<&BucketId>) -> Result<Vec<SkillInfo>> {
        let mut scope = QueryScope::all()
            .with_entity_kind(Some(memvault_core::SKILL_KIND.to_string()))
            .with_detail(DetailLevel::Full);
        if let Some(b) = bucket {
            scope = scope.with_bucket(Some(b.clone()));
        }
        let rows = self.list_scoped(&scope, limit).await?;
        let mut out = Vec::new();
        for n in rows {
            let Some(id) = parse_entity_node_id(&n.node_id) else {
                continue;
            };
            let (name, description, trigger) = match &n.detail {
                Some(NodeDetail::Entity { props, .. }) => (
                    props
                        .get(memvault_core::SKILL_NAME_PROP)
                        .and_then(|v| v.as_str())
                        .unwrap_or(&n.label)
                        .to_string(),
                    props
                        .get(memvault_core::SKILL_DESCRIPTION_PROP)
                        .and_then(|v| v.as_str())
                        .map(str::to_string),
                    props
                        .get(memvault_core::SKILL_TRIGGER_PROP)
                        .and_then(|v| v.as_str())
                        .map(str::to_string),
                ),
                _ => (n.label.clone(), None, None),
            };
            out.push(SkillInfo {
                id,
                name,
                description,
                trigger,
                retracted: n.retracted,
            });
        }
        Ok(out)
    }

    /// Assemble a skill bundle: the manifest plus its outgoing component edges,
    /// grouped by relation. Returns `None` if the id is not a skill entity.
    async fn skill_get(&self, id: &EntityId) -> Result<Option<SkillBundle>> {
        let Some(entity) = self.get_entity(id).await? else {
            return Ok(None);
        };
        if entity.kind != memvault_core::SKILL_KIND {
            return Ok(None);
        }
        let info = SkillInfo {
            id: id.clone(),
            name: entity
                .props
                .get(memvault_core::SKILL_NAME_PROP)
                .and_then(|v| v.as_str())
                .unwrap_or(&entity.kind)
                .to_string(),
            description: entity
                .props
                .get(memvault_core::SKILL_DESCRIPTION_PROP)
                .and_then(|v| v.as_str())
                .map(str::to_string),
            trigger: entity
                .props
                .get(memvault_core::SKILL_TRIGGER_PROP)
                .and_then(|v| v.as_str())
                .map(str::to_string),
            retracted: false,
        };
        let skill_ref = NodeRef::Entity(id.clone());
        let edges = self.edges_of(&skill_ref).await?;
        let mut instructions = Vec::new();
        let mut resources = Vec::new();
        let mut requires = Vec::new();
        for (source, edge) in edges {
            // Outgoing edges only (skill → component).
            if source != skill_ref {
                continue;
            }
            let res = skill_resource_from_edge(&edge);
            match edge.relation.as_str() {
                memvault_core::SKILL_INSTRUCTION_REL => instructions.push(res),
                memvault_core::SKILL_RESOURCE_REL => resources.push(res),
                memvault_core::SKILL_REQUIRES_REL => requires.push(res),
                _ => {}
            }
        }
        instructions.sort_by_key(|r| r.order.unwrap_or(0));
        Ok(Some(SkillBundle {
            info,
            instructions,
            resources,
            requires,
        }))
    }

    /// Rename a skill (sets the `name` prop via `EntityUpdate`). Required: no
    /// composable primitive exists for an in-place entity prop update.
    async fn skill_rename(&self, id: &EntityId, new_name: &str) -> Result<()>;

    /// Retract a skill entity. The linked component docs/files are left intact
    /// (they may be shared by other skills).
    async fn skill_delete(&self, id: &EntityId, reason: &str) -> Result<()> {
        let node_id = format!("entity:{}", hex::encode(id.0));
        self.retract_node_internal(&node_id, reason).await
    }

    /// Link an existing node (doc/file/entity) to a skill under `relation`,
    /// carrying an optional bundle `path` and executable bit. Returns edge id.
    async fn skill_link_resource(
        &self,
        skill_id: &EntityId,
        target: &NodeRef,
        relation: &str,
        path: Option<&str>,
        executable: bool,
        vis: Visibility,
    ) -> Result<EdgeId> {
        let mut props: std::collections::BTreeMap<String, serde_json::Value> =
            std::collections::BTreeMap::new();
        if let Some(p) = path {
            props.insert(
                memvault_core::SKILL_PATH_PROP.to_string(),
                serde_json::Value::String(p.to_string()),
            );
        }
        if executable {
            props.insert(
                memvault_core::SKILL_EXECUTABLE_PROP.to_string(),
                serde_json::Value::Bool(true),
            );
        }
        let edge = Edge {
            id: EdgeId::random(),
            relation: relation.to_string(),
            target: target.clone(),
            weight: None,
            props,
            provenance: None,
        };
        self.add_link(&NodeRef::Entity(skill_id.clone()), edge, vis)
            .await
    }

    /// Remove a resource/instruction/requires edge from a skill.
    async fn skill_unlink_resource(&self, skill_id: &EntityId, edge_id: &EdgeId) -> Result<()> {
        self.remove_link_from(&NodeRef::Entity(skill_id.clone()), edge_id)
            .await
    }

    // -- Status --
    async fn status(&self) -> Result<NodeStatus>;
}

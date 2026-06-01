use std::collections::BTreeMap;
use std::sync::Arc;

use anyhow::Result;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::*;
use rmcp::{ServerHandler, tool, tool_handler, tool_router};

use memvault_api::docs::{create_doc, parse_tags, parse_visibility};
use memvault_api::files::{detect_mime, upload_file};
use memvault_api::vfs as api_vfs;
use memvault_api::MemvaultClient;
use memvault_core::{BucketId, DocId, EdgeId, EntityId, NodeRef, Visibility};
use memvault_doc::{Edge, Entity};
use memvault_query::AuditQuery;

use crate::types::*;

// ── Helpers ────────────────────────────────────────────────────────

fn ensure_entity_label(id: &str) -> String {
    if let Some(rest) = id.strip_prefix("entity:") {
        format!("entity:{rest}")
    } else {
        format!("entity:{id}")
    }
}

#[derive(Clone)]
pub struct MemvaultServer {
    client: Arc<dyn MemvaultClient>,
    default_tags: Vec<String>,
    default_visibility: String,
    /// The agent's default bucket — used when a tool call omits `bucket`.
    agent_bucket: Option<BucketId>,
    tool_router: rmcp::handler::server::tool::ToolRouter<Self>,
}

impl MemvaultServer {
    pub fn new(
        client: Arc<dyn MemvaultClient>,
        default_tags: Vec<String>,
        default_visibility: String,
        agent_bucket: Option<BucketId>,
    ) -> Self {
        Self {
            client,
            default_tags,
            default_visibility,
            agent_bucket,
            tool_router: Self::tool_router(),
        }
    }

    /// Resolve a per-call bucket for **write** operations: explicit override
    /// if provided, else the startup-resolved agent bucket. Errors when
    /// neither is available — every write must target a specific bucket, so
    /// failing here keeps the bad request from reaching the daemon.
    fn resolve_bucket(&self, explicit: Option<&str>) -> Result<BucketId> {
        if let Some(s) = explicit.filter(|s| !s.is_empty()) {
            return BucketId::from_hex(s).map_err(Into::into);
        }
        self.agent_bucket.clone().ok_or_else(|| {
            anyhow::anyhow!(
                "no bucket available — pass `bucket` in the tool call or start with --agent-id"
            )
        })
    }

    /// Resolve bucket for query-style operations. None is fine — reads
    /// degrade to "all accessible buckets".
    fn resolve_bucket_query(&self, explicit: Option<&str>) -> Result<Option<BucketId>> {
        if let Some(s) = explicit.filter(|s| !s.is_empty()) {
            return BucketId::from_hex(s).map(Some).map_err(Into::into);
        }
        Ok(None)
    }

    /// Bucket used for VFS operations. VFS is per-bucket — every call needs
    /// either an explicit bucket from the tool params or the startup-resolved
    /// agent bucket. Errors when neither is available.
    fn vfs_bucket(&self, explicit: Option<&str>) -> Result<BucketId> {
        self.resolve_bucket(explicit)
    }
}

#[tool_handler]
impl ServerHandler for MemvaultServer {
    fn get_info(&self) -> ServerInfo {
        ServerInfo {
            instructions: Some(
                "Memvault MCP server — store, retrieve, search, and link memories in a \
                 local-first p2p knowledge base. Use memvault_put to store documents, \
                 memvault_search to find them, the graph tools to build a knowledge graph, \
                 and the VFS tools (memvault_vfs_*) to organise nodes into a virtual \
                 filesystem hierarchy with directories, paths, and tree views."
                    .into(),
            ),
            capabilities: ServerCapabilities::builder().enable_tools().build(),
            ..Default::default()
        }
    }
}

#[tool_router]
impl MemvaultServer {
    // ── Documents ──────────────────────────────────────────────────

    #[tool(
        name = "memvault_put",
        description = "Store a memory (document with optional title and tags). Returns the hex-encoded doc ID and CID."
    )]
    async fn put(&self, Parameters(params): Parameters<PutParams>) -> String {
        let bucket = match self.resolve_bucket(params.bucket.as_deref()) {
            Ok(b) => b,
            Err(e) => return format!("error: {e}"),
        };
        let tags_input = if params.tags.is_empty() {
            &self.default_tags
        } else {
            &params.tags
        };
        let tags = parse_tags(tags_input);
        let vis = parse_visibility(
            params
                .visibility
                .as_deref()
                .or(Some(self.default_visibility.as_str())),
        );
        match create_doc(
            &*self.client,
            &params.text,
            params.title.as_deref(),
            None,
            tags,
            vis,
            params.vfs_path.as_deref(),
            Some(&bucket),
        )
        .await
        {
            Ok(res) => {
                let mut result = serde_json::json!({
                    "node_id": res.node_id,
                    "doc_id": hex::encode(res.doc_id.0),
                    "cid": hex::encode(&res.cid),
                    "status": "stored",
                });
                if let Some(path) = &params.vfs_path {
                    result["vfs_path"] = serde_json::json!(path);
                }
                result.to_string()
            }
            Err(e) => format!("error: {e}"),
        }
    }

    #[tool(
        name = "memvault_get",
        description = "Retrieve a memory by its hex-encoded doc ID."
    )]
    async fn get(&self, Parameters(params): Parameters<GetParams>) -> String {
        let id = match DocId::from_hex(&params.cid) {
            Ok(id) => id,
            Err(e) => return format!("error: {e}"),
        };
        match self.client.get_doc(&id).await {
            Ok(Some(doc)) => serde_json::json!({
                "doc_id": params.cid,
                "title": doc.frontmatter.get("title").and_then(|v| v.as_str()),
                "body": doc.body,
            })
            .to_string(),
            Ok(None) => format!("error: document not found for id {}", params.cid),
            Err(e) => format!("error: {e}"),
        }
    }

    #[tool(
        name = "memvault_search",
        description = "Search memories by text query. Optionally filter by tag (scope:label format)."
    )]
    async fn search(&self, Parameters(params): Parameters<SearchParams>) -> String {
        let limit = params.limit.unwrap_or(10);
        match self.client.search(&params.query, limit).await {
            Ok(hits) => serde_json::json!(hits
                .iter()
                .map(|h| serde_json::json!({
                    "doc_id": hex::encode(h.doc_id.0),
                    "score": h.score,
                    "snippet": h.snippet,
                }))
                .collect::<Vec<_>>())
            .to_string(),
            Err(e) => format!("error: {e}"),
        }
    }

    #[tool(
        name = "memvault_list",
        description = "List recent documents. Optionally filter by tag scope and label."
    )]
    async fn list(&self, Parameters(params): Parameters<ListParams>) -> String {
        let limit = params.limit.unwrap_or(20);
        let bucket = match self.resolve_bucket_query(params.bucket.as_deref()) {
            Ok(b) => b,
            Err(e) => return format!("error: {e}"),
        };
        let tag_filter = match (params.tag_scope, params.tag_label) {
            (Some(s), Some(l)) => Some((s, l)),
            _ => None,
        };
        match self.client.list_docs(tag_filter, limit, bucket.as_ref()).await {
            Ok(docs) => serde_json::json!(docs
                .iter()
                .map(|d| serde_json::json!({
                    "id": hex::encode(d.id.0),
                    "title": d.title,
                    "updated_ns": d.updated_ns,
                }))
                .collect::<Vec<_>>())
            .to_string(),
            Err(e) => format!("error: {e}"),
        }
    }

    #[tool(
        name = "memvault_doc_history",
        description = "View the operation history for a document by its hex-encoded ID."
    )]
    async fn doc_history(&self, Parameters(params): Parameters<DocHistoryParams>) -> String {
        let id = match DocId::from_hex(&params.doc_id) {
            Ok(id) => id,
            Err(e) => return format!("error: {e}"),
        };
        match self.client.history_of(&id).await {
            Ok(records) => serde_json::json!(records
                .iter()
                .map(|r| serde_json::json!({
                    "cid": hex::encode(&r.cid),
                    "op_kind": format!("{:?}", r.op_kind),
                    "wall_ns": r.wall_ns,
                }))
                .collect::<Vec<_>>())
            .to_string(),
            Err(e) => format!("error: {e}"),
        }
    }

    // ── Files ──────────────────────────────────────────────────────

    #[tool(
        name = "memvault_upload_file",
        description = "Upload a local file to memvault by its absolute path. Returns the manifest CID."
    )]
    async fn upload_file(&self, Parameters(params): Parameters<UploadFileParams>) -> String {
        let bucket = match self.resolve_bucket(params.bucket.as_deref()) {
            Ok(b) => b,
            Err(e) => return format!("error: {e}"),
        };
        let path = std::path::Path::new(&params.path);
        let data = match std::fs::read(path) {
            Ok(d) => d,
            Err(e) => return format!("error: cannot read {}: {e}", params.path),
        };
        let filename = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("unnamed");
        let mime_type = params
            .content_type
            .as_deref()
            .unwrap_or_else(|| detect_mime(path));
        let tags_input = params.tags.unwrap_or_else(|| self.default_tags.clone());
        let tags = parse_tags(&tags_input);
        let visibility = params
            .visibility
            .as_deref()
            .unwrap_or(self.default_visibility.as_str());
        match upload_file(
            &*self.client,
            &data,
            Some(filename),
            mime_type,
            tags,
            visibility,
            params.vfs_path.as_deref(),
            Some(&bucket),
        )
        .await
        {
            Ok((cid, node_id)) => {
                let mut result = serde_json::json!({
                    "node_id": node_id,
                    "cid": hex::encode(&cid),
                    "filename": filename,
                    "size": data.len(),
                    "mime_type": mime_type,
                    "status": "uploaded",
                });
                if let Some(path) = &params.vfs_path {
                    result["vfs_path"] = serde_json::json!(path);
                }
                result.to_string()
            }
            Err(e) => format!("error: {e}"),
        }
    }

    #[tool(
        name = "memvault_read_range",
        description = "Read a byte range [start, end) from a file. Returns base64-encoded bytes."
    )]
    async fn read_range(&self, Parameters(params): Parameters<ReadRangeParams>) -> String {
        let cid = match hex::decode(&params.manifest_cid) {
            Ok(b) => b,
            Err(e) => return format!("error: invalid hex: {e}"),
        };
        match self.client.read_file_range(&cid, params.start, params.end).await {
            Ok(data) => {
                use base64::Engine;
                serde_json::json!({
                    "data_base64": base64::engine::general_purpose::STANDARD.encode(&data),
                    "size": data.len(),
                })
                .to_string()
            }
            Err(e) => format!("error: {e}"),
        }
    }

    #[tool(
        name = "memvault_pin",
        description = "Pin a file to prevent garbage collection."
    )]
    async fn pin(&self, Parameters(params): Parameters<PinParams>) -> String {
        let cid = match hex::decode(&params.manifest_cid) {
            Ok(b) => b,
            Err(e) => return format!("error: invalid hex: {e}"),
        };
        match self.client.pin_file(&cid).await {
            Ok(()) => serde_json::json!({
                "manifest_cid": params.manifest_cid,
                "status": "pinned"
            })
            .to_string(),
            Err(e) => format!("error: {e}"),
        }
    }

    #[tool(
        name = "memvault_unpin",
        description = "Unpin a file, allowing garbage collection."
    )]
    async fn unpin(&self, Parameters(params): Parameters<UnpinParams>) -> String {
        let cid = match hex::decode(&params.manifest_cid) {
            Ok(b) => b,
            Err(e) => return format!("error: invalid hex: {e}"),
        };
        match self.client.unpin_file(&cid).await {
            Ok(()) => serde_json::json!({
                "manifest_cid": params.manifest_cid,
                "status": "unpinned"
            })
            .to_string(),
            Err(e) => format!("error: {e}"),
        }
    }

    #[tool(
        name = "memvault_extract_text",
        description = "Extract text from a file (PDF, DOCX, HTML, Markdown, plain text)."
    )]
    async fn extract_text(&self, Parameters(params): Parameters<ExtractTextParams>) -> String {
        let cid = match hex::decode(&params.manifest_cid) {
            Ok(b) => b,
            Err(e) => return format!("error: invalid hex: {e}"),
        };
        match self.client.read_extracted_text(&cid).await {
            Ok(Some(text)) => {
                serde_json::json!({ "manifest_cid": params.manifest_cid, "text": text })
                    .to_string()
            }
            Ok(None) => serde_json::json!({
                "manifest_cid": params.manifest_cid,
                "text": null,
                "note": "unsupported or failed"
            })
            .to_string(),
            Err(e) => format!("error: {e}"),
        }
    }

    #[tool(
        name = "memvault_file_info",
        description = "Get manifest metadata for a file."
    )]
    async fn file_info(&self, Parameters(params): Parameters<FileInfoParams>) -> String {
        let cid = match hex::decode(&params.manifest_cid) {
            Ok(b) => b,
            Err(e) => return format!("error: invalid hex: {e}"),
        };
        match self.client.get_file_manifest(&cid).await {
            Ok(Some(bytes)) => match serde_json::from_slice::<serde_json::Value>(&bytes) {
                Ok(v) => v.to_string(),
                Err(e) => format!("error: corrupt manifest json: {e}"),
            },
            Ok(None) => format!("error: manifest not found for cid {}", params.manifest_cid),
            Err(e) => format!("error: {e}"),
        }
    }

    // ── Graph ──────────────────────────────────────────────────────

    #[tool(
        name = "memvault_graph_add",
        description = "Add an entity to the knowledge graph. Returns the hex-encoded entity ID."
    )]
    async fn graph_add(&self, Parameters(params): Parameters<GraphAddParams>) -> String {
        let bucket = match self.resolve_bucket(params.bucket.as_deref()) {
            Ok(b) => b,
            Err(e) => return format!("error: {e}"),
        };
        let vis = parse_visibility(
            params
                .visibility
                .as_deref()
                .or(Some(self.default_visibility.as_str())),
        );
        let props_map: BTreeMap<String, serde_json::Value> = params
            .props
            .into_iter()
            .map(|(k, v)| (k, serde_json::Value::String(v)))
            .collect();
        let entity = Entity {
            id: EntityId::random(),
            kind: params.kind,
            props: props_map,
            edges_out: vec![],
        };
        match self.client.add_entity(entity, vis, Some(&bucket)).await {
            Ok(id) => {
                let node_id = format!("entity:{}", hex::encode(id.0));
                let mut result =
                    serde_json::json!({ "node_id": node_id, "status": "created" });
                if let Some(vfs_path) = &params.vfs_path {
                    if let Err(e) =
                        api_vfs::link_node_at_path(&*self.client, &bucket, vfs_path, &node_id)
                            .await
                    {
                        result["vfs_error"] = serde_json::json!(e.to_string());
                    } else {
                        result["vfs_path"] = serde_json::json!(vfs_path);
                    }
                }
                result.to_string()
            }
            Err(e) => format!("error: {e}"),
        }
    }

    #[tool(
        name = "memvault_get_entity",
        description = "Get a single entity by hex ID. Returns kind, properties, and edges."
    )]
    async fn get_entity(&self, Parameters(params): Parameters<GetEntityParams>) -> String {
        let id = match EntityId::from_hex(&params.id) {
            Ok(id) => id,
            Err(e) => return format!("error: {e}"),
        };
        match self.client.get_entity(&id).await {
            Ok(Some(e)) => serde_json::json!({
                "id": hex::encode(e.id.0),
                "kind": e.kind,
                "props": e.props,
                "edges": e.edges_out.iter().map(|edge| serde_json::json!({
                    "edge_id": hex::encode(edge.id.0),
                    "relation": edge.relation,
                    "target": edge.target.tag_label(),
                    "weight": edge.weight,
                    "props": edge.props,
                })).collect::<Vec<_>>(),
            })
            .to_string(),
            Ok(None) => format!("error: entity not found: {}", params.id),
            Err(e) => format!("error: {e}"),
        }
    }

    #[tool(
        name = "memvault_list_entities",
        description = "List knowledge graph entities."
    )]
    async fn list_entities(&self, Parameters(params): Parameters<ListEntitiesParams>) -> String {
        let bucket = match self.resolve_bucket_query(params.bucket.as_deref()) {
            Ok(b) => b,
            Err(e) => return format!("error: {e}"),
        };
        match self
            .client
            .list_entities(params.limit.unwrap_or(50), bucket.as_ref())
            .await
        {
            Ok(entities) => serde_json::json!(
                entities.iter().map(|e| serde_json::json!({
                    "id": hex::encode(e.id.0),
                    "kind": e.kind,
                    "label": e.props.get("name").or_else(|| e.props.get("title"))
                        .and_then(|v| v.as_str()).unwrap_or(&e.kind),
                    "edge_count": e.edges_out.len(),
                })).collect::<Vec<_>>()
            )
            .to_string(),
            Err(e) => format!("error: {e}"),
        }
    }

    #[tool(
        name = "memvault_traverse",
        description = "Traverse the graph from any node (type:hex). Returns connected nodes up to max_depth."
    )]
    async fn traverse(&self, Parameters(params): Parameters<TraverseParams>) -> String {
        let node = match NodeRef::from_tag_label(&params.from) {
            Some(n) => n,
            None => return format!("error: invalid node: {}", params.from),
        };
        match self
            .client
            .traverse_from(&node, params.relation.as_deref(), params.max_depth.unwrap_or(2))
            .await
        {
            Ok(hits) => serde_json::json!(
                hits.iter().map(|h| serde_json::json!({
                    "node": h.node.tag_label(),
                    "depth": h.depth,
                    "path": h.path.iter().map(|(eid, rel)| serde_json::json!({
                        "edge_id": hex::encode(eid.0),
                        "relation": rel,
                    })).collect::<Vec<_>>(),
                })).collect::<Vec<_>>()
            )
            .to_string(),
            Err(e) => format!("error: {e}"),
        }
    }

    #[tool(
        name = "memvault_graph_link",
        description = "Link two entities by hex ID. Use memvault_link for cross-type linking."
    )]
    async fn graph_link(&self, Parameters(params): Parameters<GraphLinkParams>) -> String {
        let source_label = ensure_entity_label(&params.source_id);
        let target_label = ensure_entity_label(&params.target_id);
        self.add_link_impl(
            &source_label,
            &target_label,
            &params.relation,
            params.weight,
            params.props.into_iter().collect(),
        )
        .await
    }

    #[tool(
        name = "memvault_graph_query",
        description = "List all edges for an entity."
    )]
    async fn graph_query(&self, Parameters(params): Parameters<GraphQueryParams>) -> String {
        let node_label = ensure_entity_label(&params.from_id);
        self.edges_of_impl(&node_label).await
    }

    // ── Links (cross-type) ─────────────────────────────────────────

    #[tool(
        name = "memvault_link",
        description = "Link any two nodes (type:hex format). Returns the edge ID."
    )]
    async fn link(&self, Parameters(params): Parameters<LinkParams>) -> String {
        self.add_link_impl(
            &params.source,
            &params.target,
            &params.relation,
            params.weight,
            params.props.into_iter().collect(),
        )
        .await
    }

    #[tool(
        name = "memvault_edges",
        description = "List all edges for any node (type:hex)."
    )]
    async fn edges(&self, Parameters(params): Parameters<EdgesOfParams>) -> String {
        self.edges_of_impl(&params.node).await
    }

    #[tool(
        name = "memvault_unlink",
        description = "Remove an edge. Requires edge_id and source node (type:hex)."
    )]
    async fn unlink(&self, Parameters(params): Parameters<UnlinkParams>) -> String {
        let source = match NodeRef::from_tag_label(&params.source) {
            Some(n) => n,
            None => return format!("error: invalid source: {}", params.source),
        };
        let edge_id = match EdgeId::from_hex(&params.edge_id) {
            Ok(id) => id,
            Err(e) => return format!("error: {e}"),
        };
        match self.client.remove_link_from(&source, &edge_id).await {
            Ok(()) => serde_json::json!({
                "edge_id": params.edge_id,
                "status": "removed"
            })
            .to_string(),
            Err(e) => format!("error: {e}"),
        }
    }

    // ── Nodes (universal) ──────────────────────────────────────────

    #[tool(
        name = "memvault_list_all",
        description = "List all nodes (docs, entities, files). Optionally filter by view name."
    )]
    async fn list_all(&self, Parameters(params): Parameters<ListAllParams>) -> String {
        let _ = self.resolve_bucket_query(params.bucket.as_deref());
        match self
            .client
            .list_all(params.view.as_deref(), params.limit.unwrap_or(100))
            .await
        {
            Ok(items) => serde_json::json!(items
                .iter()
                .map(|(id, nt, label, tags)| serde_json::json!({
                    "node_id": id,
                    "node_type": nt,
                    "label": label,
                    "tags": tags,
                }))
                .collect::<Vec<_>>())
            .to_string(),
            Err(e) => format!("error: {e}"),
        }
    }

    #[tool(
        name = "memvault_retract",
        description = "Retract (soft-delete) any node. Node must be in type:hex format: doc:<hex>, entity:<hex>, or file:<hex>."
    )]
    async fn retract(&self, Parameters(params): Parameters<RetractParams>) -> String {
        match self.client.retract_node(&params.node, &params.reason).await {
            Ok(()) => serde_json::json!({
                "node_id": params.node,
                "status": "retracted",
            })
            .to_string(),
            Err(e) => format!("error: {e}"),
        }
    }

    // ── Tags ───────────────────────────────────────────────────────

    #[tool(
        name = "memvault_tag",
        description = "Add tags to an item (type:hex node ID). Tags in scope:label format."
    )]
    async fn tag(&self, Parameters(params): Parameters<TagParams>) -> String {
        match self
            .client
            .add_tags(&params.node, parse_tags(&params.tags))
            .await
        {
            Ok(()) => serde_json::json!({
                "node_id": params.node,
                "status": "tags_added",
            })
            .to_string(),
            Err(e) => format!("error: {e}"),
        }
    }

    #[tool(
        name = "memvault_untag",
        description = "Remove tags from an item. Tags in scope:label format."
    )]
    async fn untag(&self, Parameters(params): Parameters<UntagParams>) -> String {
        match self
            .client
            .remove_tags(&params.node, parse_tags(&params.tags))
            .await
        {
            Ok(()) => serde_json::json!({
                "node_id": params.node,
                "status": "tags_removed",
            })
            .to_string(),
            Err(e) => format!("error: {e}"),
        }
    }

    #[tool(
        name = "memvault_get_tags",
        description = "Get effective tags for an item."
    )]
    async fn get_tags(&self, Parameters(params): Parameters<GetTagsParams>) -> String {
        match self.client.get_tags(&params.node).await {
            Ok(tags) => serde_json::json!({ "node_id": params.node, "tags": tags }).to_string(),
            Err(e) => format!("error: {e}"),
        }
    }

    // ── Views ──────────────────────────────────────────────────────

    #[tool(name = "memvault_view_list", description = "List all saved views.")]
    async fn view_list(&self) -> String {
        match self.client.list_views().await {
            Ok(views) => serde_json::json!(views).to_string(),
            Err(e) => format!("error: {e}"),
        }
    }

    #[tool(
        name = "memvault_view_create",
        description = "Create a view. Tags in scope:label format."
    )]
    async fn view_create(&self, Parameters(params): Parameters<ViewCreateParams>) -> String {
        let view = memvault_api::View {
            name: params.name.clone(),
            tags: parse_tags(&params.tags),
            created_ns: memvault_core::wall_ns(),
            cid: String::new(),
            bucket_id: None,
        };
        match self.client.create_view(view).await {
            Ok(()) => serde_json::json!({ "name": params.name, "status": "created" }).to_string(),
            Err(e) => format!("error: {e}"),
        }
    }

    #[tool(name = "memvault_view_update", description = "Update a view's tags.")]
    async fn view_update(&self, Parameters(params): Parameters<ViewUpdateParams>) -> String {
        let view = memvault_api::View {
            name: params.name.clone(),
            tags: parse_tags(&params.tags),
            created_ns: memvault_core::wall_ns(),
            cid: String::new(),
            bucket_id: None,
        };
        match self.client.update_view(view).await {
            Ok(()) => serde_json::json!({ "name": params.name, "status": "updated" }).to_string(),
            Err(e) => format!("error: {e}"),
        }
    }

    #[tool(name = "memvault_view_delete", description = "Delete a view.")]
    async fn view_delete(&self, Parameters(params): Parameters<ViewDeleteParams>) -> String {
        match self.client.delete_view(&params.name).await {
            Ok(()) => serde_json::json!({ "name": params.name, "status": "deleted" }).to_string(),
            Err(e) => format!("error: {e}"),
        }
    }

    // ── Buckets ────────────────────────────────────────────────────

    #[tool(
        name = "memvault_bucket_list",
        description = "List all buckets with status, name, and item count."
    )]
    async fn bucket_list(&self) -> String {
        match self.client.bucket_list().await {
            Ok(buckets) => serde_json::json!(buckets
                .iter()
                .map(|b| serde_json::json!({
                    "id": hex::encode(b.id.0),
                    "name": b.name,
                    "description": b.description,
                    "owner_agent": b.owner_agent.as_ref().map(|a| &a.0),
                    "is_attached": b.is_attached,
                    "envelope_count": b.envelope_count,
                    "created_ns": b.created_ns,
                }))
                .collect::<Vec<_>>())
            .to_string(),
            Err(e) => format!("error: {e}"),
        }
    }

    #[tool(
        name = "memvault_bucket_create",
        description = "Create a new bucket. Returns the bucket ID."
    )]
    async fn bucket_create(&self, Parameters(params): Parameters<BucketCreateParams>) -> String {
        match self
            .client
            .bucket_create(
                &params.name,
                params.description.as_deref(),
                Visibility::Internal,
                memvault_core::classification::Classification::Internal,
                memvault_doc::BucketRole::Standard,
            )
            .await
        {
            Ok(id) => {
                serde_json::json!({ "bucket_id": hex::encode(id.0), "name": params.name })
                    .to_string()
            }
            Err(e) => format!("error: {e}"),
        }
    }

    #[tool(
        name = "memvault_bucket_get",
        description = "Get details of a bucket by hex ID."
    )]
    async fn bucket_get(&self, Parameters(params): Parameters<BucketGetParams>) -> String {
        let bid = match BucketId::from_hex(&params.id) {
            Ok(b) => b,
            Err(e) => return format!("error: {e}"),
        };
        match self.client.bucket_get(&bid).await {
            Ok(Some(b)) => serde_json::json!({
                "id": hex::encode(b.id.0),
                "name": b.name,
                "description": b.description,
                "owner_agent": b.owner_agent.as_ref().map(|a| &a.0),
                "is_attached": b.is_attached,
                "envelope_count": b.envelope_count,
            })
            .to_string(),
            Ok(None) => "not found".to_string(),
            Err(e) => format!("error: {e}"),
        }
    }

    #[tool(name = "memvault_bucket_rename", description = "Rename a bucket.")]
    async fn bucket_rename(&self, Parameters(params): Parameters<BucketRenameParams>) -> String {
        let bid = match BucketId::from_hex(&params.id) {
            Ok(b) => b,
            Err(e) => return format!("error: {e}"),
        };
        match self.client.bucket_rename(&bid, &params.name).await {
            Ok(()) => serde_json::json!({ "status": "renamed" }).to_string(),
            Err(e) => format!("error: {e}"),
        }
    }

    #[tool(
        name = "memvault_bucket_archive",
        description = "Archive a bucket (soft-remove, data preserved)."
    )]
    async fn bucket_archive(&self, Parameters(params): Parameters<BucketArchiveParams>) -> String {
        let bid = match BucketId::from_hex(&params.id) {
            Ok(b) => b,
            Err(e) => return format!("error: {e}"),
        };
        match self.client.bucket_archive(&bid, &params.reason).await {
            Ok(()) => serde_json::json!({ "status": "archived" }).to_string(),
            Err(e) => format!("error: {e}"),
        }
    }

    #[tool(
        name = "memvault_bucket_grants_list",
        description = "List capability grants for one bucket (when `bucket` is set) or aggregated across every bucket the agent can see. Read-only."
    )]
    async fn bucket_grants_list(
        &self,
        Parameters(params): Parameters<BucketGrantsListParams>,
    ) -> String {
        let buckets: Vec<BucketId> = match params.bucket.as_deref().filter(|s| !s.is_empty()) {
            Some(hex) => match BucketId::from_hex(hex) {
                Ok(b) => vec![b],
                Err(e) => return format!("error: {e}"),
            },
            None => match self.client.bucket_list().await {
                Ok(list) => list.into_iter().map(|b| b.id).collect(),
                Err(e) => return format!("error: {e}"),
            },
        };

        let mut all = Vec::new();
        for bid in &buckets {
            match self.client.bucket_grants_list(bid).await {
                Ok(grants) => {
                    for g in grants {
                        all.push(serde_json::json!({
                            "cid": hex::encode(&g.cid),
                            "bucket_id": hex::encode(g.bucket_id.0),
                            "issuer": hex::encode(&g.issuer.0),
                            "issuing_cluster": hex::encode(g.issuing_cluster.0),
                            "audience": g.audience,
                            "actions": g.actions,
                            "not_before_ns": g.not_before_ns,
                            "not_after_ns": g.not_after_ns,
                        }));
                    }
                }
                Err(e) => return format!("error: {e}"),
            }
        }
        serde_json::json!({ "grants": all }).to_string()
    }

    // ── Sharing ────────────────────────────────────────────────────

    #[tool(
        name = "memvault_share_inbox",
        description = "List cross-cluster share proposals received by this cluster. Returns hex CIDs; call memvault_share_decide for proposal contents."
    )]
    async fn share_inbox(&self, Parameters(_params): Parameters<ShareInboxParams>) -> String {
        match self.client.share_inbox().await {
            Ok(cids) => serde_json::json!({
                "proposals": cids.iter().map(hex::encode).collect::<Vec<_>>(),
            })
            .to_string(),
            Err(e) => format!("error: {e}"),
        }
    }

    #[tool(
        name = "memvault_share_outbox",
        description = "List cross-cluster share proposals sent by this cluster. Returns hex CIDs."
    )]
    async fn share_outbox(&self, Parameters(_params): Parameters<ShareOutboxParams>) -> String {
        match self.client.share_outbox().await {
            Ok(cids) => serde_json::json!({
                "proposals": cids.iter().map(hex::encode).collect::<Vec<_>>(),
            })
            .to_string(),
            Err(e) => format!("error: {e}"),
        }
    }

    #[tool(
        name = "memvault_share_decide",
        description = "Approve or reject a cross-cluster share proposal. Two-step: call first with `confirm: false` (default) to preview the proposal contents, then call again with `confirm: true` to commit the decision."
    )]
    async fn share_decide(&self, Parameters(params): Parameters<ShareDecideParams>) -> String {
        let cid = match hex::decode(&params.proposal_cid) {
            Ok(c) => c,
            Err(e) => return format!("error: invalid hex cid: {e}"),
        };

        let preview = match self.client.share_get_proposal(&cid).await {
            Ok(Some(p)) => serde_json::json!({
                "cid": hex::encode(&p.cid),
                "proposal_id": hex::encode(p.proposal_id),
                "from_cluster": hex::encode(p.from_cluster.0),
                "from_bucket": hex::encode(p.from_bucket.0),
                "from_admin": hex::encode(&p.from_admin.0),
                "to_cluster": hex::encode(p.to_cluster.0),
                "to_recipient": p.to_recipient,
                "proposed_actions": p.proposed_actions,
                "purpose": p.purpose,
                "not_after_ns": p.not_after_ns,
            }),
            Ok(None) => serde_json::json!({
                "cid": params.proposal_cid,
                "note": "proposal contents not available locally",
            }),
            Err(e) => return format!("error: {e}"),
        };

        if !params.confirm {
            return serde_json::json!({
                "status": "preview",
                "proposal": preview,
                "intended_decision": if params.approve { "approve" } else { "reject" },
                "reason": params.reason,
                "next": "call again with confirm=true to commit",
            })
            .to_string();
        }

        match self
            .client
            .share_decide(&cid, params.approve, params.reason.as_deref())
            .await
        {
            Ok(()) => serde_json::json!({
                "status": if params.approve { "approved" } else { "rejected" },
                "proposal": preview,
                "reason": params.reason,
            })
            .to_string(),
            Err(e) => format!("error: {e}"),
        }
    }

    // ── Audit ──────────────────────────────────────────────────────

    #[tool(
        name = "memvault_audit",
        description = "Query audit log. Optionally filter by op_kind (DocCreate, EntityCreate, AttachFile, EdgeAdd, Retract)."
    )]
    async fn audit(&self, Parameters(params): Parameters<AuditParams>) -> String {
        let _ = self.resolve_bucket_query(params.bucket.as_deref());
        let query = AuditQuery {
            op_kind: params.op_kind.as_deref().map(|k| match k {
                "DocCreate" => memvault_query::OpKind::DocCreate,
                "DocEdit" => memvault_query::OpKind::DocEdit,
                "AttachFile" => memvault_query::OpKind::AttachFile,
                "EntityCreate" => memvault_query::OpKind::EntityCreate,
                "EdgeAdd" => memvault_query::OpKind::EdgeAdd,
                "Retract" => memvault_query::OpKind::Retract,
                other => memvault_query::OpKind::Other(other.to_string()),
            }),
            limit: Some(params.limit.unwrap_or(50)),
            ..Default::default()
        };
        match self.client.audit(query).await {
            Ok(records) => serde_json::json!(records
                .iter()
                .map(|r| serde_json::json!({
                    "cid": hex::encode(&r.cid),
                    "op_kind": format!("{:?}", r.op_kind),
                    "author": hex::encode(&r.author),
                    "wall_ns": r.wall_ns,
                    "tags": r.tags,
                }))
                .collect::<Vec<_>>())
            .to_string(),
            Err(e) => format!("error: {e}"),
        }
    }

    // ── Status ─────────────────────────────────────────────────────

    #[tool(
        name = "memvault_status",
        description = "Get node status (block count, doc count, peer count, uptime)."
    )]
    async fn status(&self) -> String {
        match self.client.status().await {
            Ok(s) => serde_json::json!({
                "peer_id": hex::encode(&s.peer_id),
                "cluster_id": hex::encode(&s.cluster_id),
                "block_count": s.block_count,
                "doc_count": s.doc_count,
                "peer_count": s.peer_count,
                "uptime_secs": s.uptime_secs,
            })
            .to_string(),
            Err(e) => format!("error: {e}"),
        }
    }

    // ── VFS ────────────────────────────────────────────────────────

    #[tool(
        name = "memvault_vfs_ls",
        description = "List directory contents at a VFS path. Shows name, type, and node ID for each entry."
    )]
    async fn vfs_ls(&self, Parameters(params): Parameters<VfsLsParams>) -> String {
        let bucket = match self.vfs_bucket(params.bucket.as_deref()) {
            Ok(b) => b,
            Err(e) => return format!("error: {e}"),
        };
        let recursive = params.recursive.unwrap_or(false);
        match api_vfs::ls(&*self.client, &bucket, &params.path, recursive).await {
            Ok(entries) => serde_json::json!({
                "path": params.path,
                "entries": entries,
            })
            .to_string(),
            Err(e) => format!("error: {e}"),
        }
    }

    #[tool(
        name = "memvault_vfs_resolve",
        description = "Resolve a VFS path to its target node ID (type:hex format)."
    )]
    async fn vfs_resolve(&self, Parameters(params): Parameters<VfsResolveParams>) -> String {
        let bucket = match self.vfs_bucket(params.bucket.as_deref()) {
            Ok(b) => b,
            Err(e) => return format!("error: {e}"),
        };
        match api_vfs::resolve_path(&*self.client, &bucket, &params.path).await {
            Ok(Some((node, edge_id))) => serde_json::json!({
                "path": params.path,
                "node_id": node.tag_label(),
                "edge_id": edge_id.map(|e| hex::encode(e.0)),
            })
            .to_string(),
            Ok(None) => {
                serde_json::json!({ "path": params.path, "error": "not found" }).to_string()
            }
            Err(e) => format!("error: {e}"),
        }
    }

    #[tool(
        name = "memvault_vfs_mkdir",
        description = "Create a directory at a VFS path. Intermediate directories are created automatically (like mkdir -p)."
    )]
    async fn vfs_mkdir(&self, Parameters(params): Parameters<VfsMkdirParams>) -> String {
        let bucket = match self.vfs_bucket(params.bucket.as_deref()) {
            Ok(b) => b,
            Err(e) => return format!("error: {e}"),
        };
        match api_vfs::mkdir(&*self.client, &bucket, &params.path).await {
            Ok(id) => serde_json::json!({
                "path": params.path,
                "entity_id": hex::encode(id.0),
                "status": "created",
            })
            .to_string(),
            Err(e) => format!("error: {e}"),
        }
    }

    #[tool(
        name = "memvault_vfs_link",
        description = "Place a node at a VFS path. Intermediate directories are created automatically. A node can appear at multiple paths."
    )]
    async fn vfs_link(&self, Parameters(params): Parameters<VfsLinkParams>) -> String {
        let bucket = match self.vfs_bucket(params.bucket.as_deref()) {
            Ok(b) => b,
            Err(e) => return format!("error: {e}"),
        };
        let target_ref = match NodeRef::from_tag_label(&params.target) {
            Some(n) => n,
            None => return format!("error: invalid target: {}", params.target),
        };
        match api_vfs::link_at_path(&*self.client, &bucket, &params.path, &target_ref).await {
            Ok(edge_id) => serde_json::json!({
                "path": params.path,
                "target": params.target,
                "edge_id": hex::encode(edge_id.0),
                "status": "linked",
            })
            .to_string(),
            Err(e) => format!("error: {e}"),
        }
    }

    #[tool(
        name = "memvault_vfs_unlink",
        description = "Remove an entry from a VFS path. The underlying node is NOT deleted — only the VFS link is removed."
    )]
    async fn vfs_unlink(&self, Parameters(params): Parameters<VfsUnlinkParams>) -> String {
        let bucket = match self.vfs_bucket(params.bucket.as_deref()) {
            Ok(b) => b,
            Err(e) => return format!("error: {e}"),
        };
        match api_vfs::unlink_path(&*self.client, &bucket, &params.path).await {
            Ok(()) => serde_json::json!({
                "path": params.path,
                "status": "unlinked",
            })
            .to_string(),
            Err(e) => format!("error: {e}"),
        }
    }

    #[tool(
        name = "memvault_vfs_mv",
        description = "Move or rename a VFS entry from one path to another."
    )]
    async fn vfs_mv(&self, Parameters(params): Parameters<VfsMvParams>) -> String {
        let bucket = match self.vfs_bucket(params.bucket.as_deref()) {
            Ok(b) => b,
            Err(e) => return format!("error: {e}"),
        };
        match api_vfs::mv_path(&*self.client, &bucket, &params.from, &params.to).await {
            Ok(()) => serde_json::json!({
                "from": params.from,
                "to": params.to,
                "status": "moved",
            })
            .to_string(),
            Err(e) => format!("error: {e}"),
        }
    }

    #[tool(
        name = "memvault_vfs_tree",
        description = "Display an ASCII tree view of the VFS hierarchy from a given path."
    )]
    async fn vfs_tree(&self, Parameters(params): Parameters<VfsTreeParams>) -> String {
        let bucket = match self.vfs_bucket(params.bucket.as_deref()) {
            Ok(b) => b,
            Err(e) => return format!("error: {e}"),
        };
        let path = params.path.as_deref().unwrap_or("/");
        let max_depth = params.max_depth.unwrap_or(5);
        match api_vfs::tree(&*self.client, &bucket, path, max_depth).await {
            Ok(t) => t,
            Err(e) => format!("error: {e}"),
        }
    }

    #[tool(
        name = "memvault_vfs_find",
        description = "Find all VFS paths that link to a given node. Useful for discovering where a node is mounted."
    )]
    async fn vfs_find(&self, Parameters(params): Parameters<VfsFindParams>) -> String {
        let bucket = match self.vfs_bucket(params.bucket.as_deref()) {
            Ok(b) => b,
            Err(e) => return format!("error: {e}"),
        };
        let target_ref = match NodeRef::from_tag_label(&params.node) {
            Some(n) => n,
            None => return format!("error: invalid node: {}", params.node),
        };
        match api_vfs::find_paths(&*self.client, &bucket, &target_ref).await {
            Ok(paths) => serde_json::json!({
                "node": params.node,
                "paths": paths,
            })
            .to_string(),
            Err(e) => format!("error: {e}"),
        }
    }

    // ── Export ─────────────────────────────────────────────────────

    #[tool(
        name = "memvault_export",
        description = "Export a single node (document, file, or entity) to a temp file. \
                       Pass node_id as 'doc:<hex>', 'entity:<hex>', or 'file:<hex>'. \
                       Returns the file path. For documents, optionally includes history."
    )]
    async fn export_node(&self, Parameters(params): Parameters<ExportNodeParams>) -> String {
        let out_dir = std::env::temp_dir().join("memvault-export");
        let history = params.history.unwrap_or(false);
        match memvault_export::export_node(&*self.client, &params.node_id, &out_dir, history).await
        {
            Ok(result) => serde_json::to_string(&result).unwrap_or_else(|e| format!("error: {e}")),
            Err(e) => format!("error: {e}"),
        }
    }

    #[tool(
        name = "memvault_export_vault",
        description = "Export the entire vault (or a filtered subset) to a directory or tar archive on disk."
    )]
    async fn export_vault(&self, Parameters(params): Parameters<ExportVaultParams>) -> String {
        let tag_filter = params
            .tag
            .as_deref()
            .and_then(memvault_api::docs::parse_tag_filter);
        let opts = memvault_export::ExportOptions {
            history: params.history.unwrap_or(false),
            include_vfs: true,
            tag_filter,
            view_filter: params.view,
        };
        let output = std::path::PathBuf::from(&params.output_path);
        let force_tar = params.tar.unwrap_or(false);
        let gzip = output
            .to_str()
            .is_some_and(|s| s.ends_with(".gz") || s.ends_with(".tgz"));
        let sink = match memvault_export::create_sink(&output, force_tar, gzip) {
            Ok(s) => s,
            Err(e) => return format!("error creating output: {e}"),
        };
        match memvault_export::run_export(&*self.client, sink, opts).await {
            Ok(stats) => format!(
                "Exported {} documents, {} files, {} entities ({} history versions) to {}",
                stats.documents,
                stats.files,
                stats.entities,
                stats.history_versions,
                params.output_path,
            ),
            Err(e) => format!("error: {e}"),
        }
    }
}

// ── Shared implementations ─────────────────────────────────────────

impl MemvaultServer {
    async fn add_link_impl(
        &self,
        source: &str,
        target: &str,
        relation: &str,
        weight: Option<f32>,
        props: BTreeMap<String, serde_json::Value>,
    ) -> String {
        let source_ref = match NodeRef::from_tag_label(source) {
            Some(n) => n,
            None => return format!("error: invalid source: {source}"),
        };
        let target_ref = match NodeRef::from_tag_label(target) {
            Some(n) => n,
            None => return format!("error: invalid target: {target}"),
        };
        let edge = Edge {
            id: EdgeId::random(),
            relation: relation.to_string(),
            target: target_ref,
            weight,
            props,
            provenance: None,
        };
        match self.client.add_link(&source_ref, edge, Visibility::Internal).await {
            Ok(edge_id) => serde_json::json!({
                "edge_id": hex::encode(edge_id.0),
                "status": "linked",
            })
            .to_string(),
            Err(e) => format!("error: {e}"),
        }
    }

    async fn edges_of_impl(&self, node: &str) -> String {
        let node_ref = match NodeRef::from_tag_label(node) {
            Some(n) => n,
            None => return format!("error: invalid node: {node}"),
        };
        match self.client.edges_of(&node_ref).await {
            Ok(edges) => serde_json::json!(edges
                .iter()
                .map(|(src, edge)| serde_json::json!({
                    "edge_id": hex::encode(edge.id.0),
                    "source": src.tag_label(),
                    "target": edge.target.tag_label(),
                    "relation": edge.relation,
                    "weight": edge.weight,
                    "props": edge.props,
                }))
                .collect::<Vec<_>>())
            .to_string(),
            Err(e) => format!("error: {e}"),
        }
    }
}

#[cfg(test)]
mod tool_tests {
    //! Thin in-crate tests that drive the rmcp `MemvaultServer` tool methods
    //! directly, backed by an enrolled-agent in-process `LocalClient` (no HTTP).
    //! Complements the HTTP-transport coverage in
    //! `memvault-web/tests/mcp_http_e2e.rs`.

    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};

    use ed25519_dalek::SigningKey;
    use tokio::sync::RwLock;

    static COUNTER: AtomicU64 = AtomicU64::new(0);

    /// Build a `MemvaultServer` over a freshly enrolled-agent `LocalClient`.
    async fn test_server() -> MemvaultServer {
        let admin = SigningKey::from_bytes(&[0x51u8; 32]);
        let node = SigningKey::from_bytes(&[0x52u8; 32]);
        let cluster = memvault_core::ClusterId([0x33u8; 32]);

        let dir = std::env::temp_dir().join(format!(
            "mv-mcp-tools-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::SeqCst)
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let store =
            Arc::new(memvault_store::MemvaultStore::open(dir.join("blocks.redb")).unwrap());
        let client = memvault_api::LocalClient::new(
            store,
            Arc::new(RwLock::new(memvault_query::QuotaManager::new(Default::default()))),
            Arc::new(memvault_api::EventBus::new(16)),
            node.verifying_key().to_bytes().to_vec(),
            cluster.0.to_vec(),
        );
        let genesis = memvault_auth::sign_admin_genesis(&admin, cluster.clone(), 1).unwrap();
        client.set_admin_signing_key(admin);
        client.set_pinned_admin_genesis(genesis);
        client.set_node_signing_key(node);
        let identity = memvault_api::agent_identity::enroll_local_agent(
            &client,
            "mcp-tools",
            &dir.join("agent"),
            memvault_auth::AgentRole::AgentHost,
            u64::MAX,
        )
        .expect("enroll_local_agent");
        client.set_agent_identity(identity);

        let client: Arc<dyn MemvaultClient> = Arc::new(client);
        let bucket = client
            .ensure_agent_bucket("mcp-tools")
            .await
            .expect("ensure_agent_bucket");
        MemvaultServer::new(client, vec![], "internal".to_string(), Some(bucket))
    }

    /// Tool methods return either a JSON string or `"error: …"`.
    fn assert_ok(s: &str) {
        assert!(!s.starts_with("error"), "tool returned an error: {s}");
    }

    #[tokio::test]
    async fn put_search_via_tools() {
        let srv = test_server().await;
        let put = srv
            .put(Parameters(crate::types::PutParams {
                text: "the platypus index rose sharply this quarter".to_string(),
                title: Some("Platypus".to_string()),
                tags: vec![],
                visibility: None,
                vfs_path: None,
                bucket: None,
            }))
            .await;
        assert_ok(&put);
        assert!(put.contains("node_id"), "put must return a node_id: {put}");

        let hits = srv
            .search(Parameters(crate::types::SearchParams {
                query: "platypus".to_string(),
                limit: Some(10),
                tag_filter: None,
                bucket: None,
            }))
            .await;
        assert_ok(&hits);
        assert!(hits.contains("doc_id"), "search must find the doc: {hits}");
    }

    #[tokio::test]
    async fn graph_and_vfs_via_tools() {
        let srv = test_server().await;
        assert_ok(
            &srv.graph_add(Parameters(crate::types::GraphAddParams {
                kind: "project".to_string(),
                props: Default::default(),
                visibility: None,
                vfs_path: None,
                bucket: None,
            }))
            .await,
        );

        let mkdir = srv
            .vfs_mkdir(Parameters(crate::types::VfsMkdirParams {
                path: "/projects/acme".to_string(),
                bucket: None,
            }))
            .await;
        assert_ok(&mkdir);
        // The regression guard: a real entity id, never entity:000…000.
        assert!(
            !mkdir.contains(&"0".repeat(64)),
            "vfs_mkdir must not return a zero entity id: {mkdir}"
        );

        assert_ok(
            &srv.vfs_resolve(Parameters(crate::types::VfsResolveParams {
                path: "/projects/acme".to_string(),
                bucket: None,
            }))
            .await,
        );

        let ls = srv
            .vfs_ls(Parameters(crate::types::VfsLsParams {
                path: "/".to_string(),
                recursive: Some(false),
                bucket: None,
            }))
            .await;
        assert_ok(&ls);
        assert!(ls.contains("projects"), "vfs_ls / must list 'projects': {ls}");
    }

    #[tokio::test]
    async fn bucket_status_list_via_tools() {
        let srv = test_server().await;
        assert_ok(&srv.bucket_list().await);
        assert_ok(&srv.status().await);
        assert_ok(
            &srv.list_all(Parameters(crate::types::ListAllParams {
                limit: Some(50),
                view: None,
                bucket: None,
            }))
            .await,
        );
    }
}

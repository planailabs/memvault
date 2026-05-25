//! LocalClient — implements MemvaultClient directly against the store.

use std::collections::VecDeque;
use std::sync::Arc;

use async_trait::async_trait;
use tokio::sync::RwLock;

use memvault_core::{cid_from_bytes, BucketId, DocId, EdgeId, EntityId, NodeRef, Visibility};
use memvault_doc::{
    Document, Edge, Entity, Op, TextPatch,
};
use memvault_attach::{self, AttachmentManifest};
use memvault_query::{
    query_audit, AuditQuery, AuditRecord, QuotaManager, SearchHit, TextIndex,
};
use memvault_auth::Role;
use memvault_store::{EnvelopeMeta, MemvaultStore};

use crate::client::MemvaultClient;
use crate::error::{ApiError, Result};
use crate::subscription::{EventBus, MemvaultEvent};
use crate::types::{DocSummary, NodeStatus, RotationInfo, TokenStatus, TraversalHit};

/// Extract the target node's tag label from an EdgeAdd op.
/// Extract text from file content, catching panics from buggy extractors (e.g. pdf-extract).
/// Result of text extraction — either the text or an error message to cache.
enum ExtractionResult {
    Ok(String),
    Failed(String),
    Unsupported,
}

fn safe_extract_text(data: &[u8], mime_type: &str) -> ExtractionResult {
    let registry = memvault_extract::ExtractionRegistry::with_defaults();
    if !registry.can_extract(mime_type) {
        return ExtractionResult::Unsupported;
    }
    let data = data.to_vec();
    let mime = mime_type.to_string();
    match std::panic::catch_unwind(move || {
        let registry = memvault_extract::ExtractionRegistry::with_defaults();
        registry.extract(&data, &mime, &memvault_extract::ExtractionHints::default())
    }) {
        Ok(Ok(extracted)) => ExtractionResult::Ok(extracted.text),
        Ok(Err(e)) => {
            tracing::warn!("text extraction failed for {mime_type}: {e}");
            ExtractionResult::Failed(format!("{e}"))
        }
        Err(_) => {
            tracing::warn!("text extraction panicked for {mime_type}");
            ExtractionResult::Failed("extractor panicked".to_string())
        }
    }
}

fn op_edge_target_label(op: &Op) -> Option<String> {
    match op {
        Op::EdgeAdd { edge, .. } => Some(edge.target.tag_label()),
        _ => None,
    }
}

/// LocalClient implements MemvaultClient by calling directly into the store.
pub struct LocalClient {
    store: Arc<MemvaultStore>,
    index: Arc<RwLock<TextIndex>>,
    quotas: Arc<RwLock<QuotaManager>>,
    event_bus: Arc<EventBus>,
    peer_id: Vec<u8>,
    cluster_id: Vec<u8>,
    /// Optional admin signing key for token issuance and agent enrollment.
    admin_signing_key: Option<ed25519_dalek::SigningKey>,
    /// Optional agent identity for agent-scoped operations.
    agent_identity: Option<crate::agent_identity::AgentIdentity>,
    start_time: std::time::Instant,
}

impl LocalClient {
    pub fn new(
        store: Arc<MemvaultStore>,
        index: Arc<RwLock<TextIndex>>,
        quotas: Arc<RwLock<QuotaManager>>,
        event_bus: Arc<EventBus>,
        peer_id: Vec<u8>,
        cluster_id: Vec<u8>,
    ) -> Self {
        let client = Self {
            store,
            index,
            quotas,
            event_bus,
            peer_id,
            cluster_id,
            admin_signing_key: None,
            agent_identity: None,
            start_time: std::time::Instant::now(),
        };

        // Auto-bind any unbound buckets to the cluster (handles the case where
        // buckets were created before genesis/cluster-join, and the store is
        // now re-opened with a cluster_id).
        if client.cluster_id.iter().any(|&b| b != 0) {
            let _ = client.store.bind_unbound_buckets(&client.cluster_id);
        }

        client
    }

    /// Set the admin signing key (enables real token issuance).
    pub fn set_admin_signing_key(&mut self, key: ed25519_dalek::SigningKey) {
        self.admin_signing_key = Some(key);
    }

    /// Set the agent identity (enables agent-scoped operations).
    pub fn set_agent_identity(&mut self, identity: crate::agent_identity::AgentIdentity) {
        self.agent_identity = Some(identity);
    }

    /// Get the agent ID if set.
    pub fn agent_id(&self) -> Option<&memvault_core::AgentId> {
        self.agent_identity.as_ref().map(|i| &i.agent_id)
    }

    /// The effective author identity for write operations.
    /// Uses the agent's peer ID (derived from its public key) if an agent
    /// identity is set, otherwise falls back to the raw peer_id.
    fn effective_author(&self) -> Vec<u8> {
        if let Some(ref identity) = self.agent_identity {
            identity.verifying_key.as_bytes().to_vec()
        } else {
            self.peer_id.clone()
        }
    }

    /// Build a BucketInfo from a bucket_id and its decl CID.
    fn build_bucket_info(
        &self,
        bucket_id_bytes: &[u8],
        decl_cid: &[u8],
    ) -> Result<Option<crate::types::BucketInfo>> {
        let block = match self.store.get_block(decl_cid)? {
            Some(b) => b,
            None => return Ok(None),
        };

        let decl: memvault_doc::BucketDecl = match serde_json::from_slice(&block) {
            Ok(d) => d,
            Err(_) => return Ok(None),
        };

        let cluster_bytes = self.store.get_bucket_cluster(bucket_id_bytes)?;
        let cluster_id = cluster_bytes.and_then(|b| {
            let arr: [u8; 32] = b.try_into().ok()?;
            Some(memvault_core::ClusterId(arr))
        });

        let is_default = if let Some(ref cid) = cluster_id {
            self.store.get_default_bucket(&cid.0)?
                .map(|b| b == bucket_id_bytes)
                .unwrap_or(false)
        } else {
            false
        };

        let envelope_count = self.store.query_by_bucket(bucket_id_bytes, 0, usize::MAX)?
            .len() as u64;

        Ok(Some(crate::types::BucketInfo {
            id: decl.bucket_id,
            name: decl.name,
            description: decl.description,
            owner_agent: decl.owner_agent,
            cluster_id,
            is_default,
            is_attached: decl.private_to_peer.is_none(),
            default_visibility: decl.default_visibility,
            default_classification: decl.default_classification,
            created_ns: decl.created_ns,
            envelope_count,
        }))
    }

    /// Load the TextIndex from a cache file, or rebuild from the blockstore if
    /// the cache is missing/stale. Saves the rebuilt index afterward.
    /// Call this after construction to make search work for pre-existing data.
    pub async fn load_or_rebuild_index(&self, cache_path: &std::path::Path) -> Result<(usize, usize, usize)> {
        if let Some(loaded) = TextIndex::load(cache_path) {
            let mut idx = self.index.write().await;
            *idx = loaded;
            let count = idx.len();
            tracing::info!("loaded text index from cache ({count} entries)");
            return Ok((count, 0, 0));
        }
        tracing::info!("text index cache missing or stale, rebuilding from blockstore...");
        let counts = self.populate_index().await?;
        let idx = self.index.read().await;
        if let Err(e) = idx.save(cache_path) {
            tracing::warn!("failed to save text index cache: {e}");
        } else {
            tracing::info!("saved text index cache to {}", cache_path.display());
        }
        Ok(counts)
    }

    /// Populate the in-memory TextIndex from the blockstore.
    pub async fn populate_index(&self) -> Result<(usize, usize, usize)> {
        tracing::info!("populating text index from blockstore...");
        let mut doc_count = 0usize;
        let mut entity_count = 0usize;
        let mut attachment_count = 0usize;

        // Index documents
        let doc_labels = self.store.query_unique_labels("doc", usize::MAX)
            .map_err(|e| ApiError::Serialization(e.to_string()))?;
        for label in &doc_labels {
            let id_bytes = hex::decode(label).unwrap_or_default();
            if id_bytes.len() != 32 { continue; }
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&id_bytes);
            let doc_id = DocId(arr);
            if let Ok(Some(doc)) = self.get_doc(&doc_id).await {
                let title = doc.frontmatter.get("title").and_then(|v| v.as_str());
                // Recover creation-time tags from the envelope metadata.
                let creation_tags = self.extract_creation_tags("doc", label);
                let mut idx = self.index.write().await;
                idx.index_doc(doc_id, &doc.body, title, creation_tags);
                doc_count += 1;
            }
        }

        // Index entities
        let entity_labels = self.store.query_unique_labels("entity", usize::MAX)
            .map_err(|e| ApiError::Serialization(e.to_string()))?;
        for label in &entity_labels {
            let id_bytes = hex::decode(label).unwrap_or_default();
            if id_bytes.len() != 32 { continue; }
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&id_bytes);
            let eid = EntityId(arr);
            if let Ok(Some(entity)) = self.get_entity(&eid).await {
                let creation_tags = self.extract_creation_tags("entity", label);
                let mut idx = self.index.write().await;
                idx.index_entity(&eid, &entity.kind, &entity.props, creation_tags);
                entity_count += 1;
            }
        }

        // Index attachments
        let blocks = self.store.iter_blocks()
            .map_err(|e| ApiError::Serialization(e.to_string()))?;
        for (_, data) in &blocks {
            if let Ok(val) = serde_json::from_slice::<serde_json::Value>(data) {
                if val.get("kind").and_then(|v| v.as_str()) == Some("attachment") {
                    let manifest_cid = val.get("manifest_cid")
                        .and_then(|v| serde_json::from_value::<Vec<u8>>(v.clone()).ok());
                    let filename = val.get("filename").and_then(|v| v.as_str());
                    let mime_type = val.get("mime_type").and_then(|v| v.as_str())
                        .unwrap_or("application/octet-stream");
                    if let Some(mcid) = manifest_cid {
                        let text = if let Ok(content) = self.read_file(&mcid).await {
                            self.extract_and_cache(&mcid, &content, mime_type)
                        } else {
                            None
                        };
                        let att_tags: Vec<(String, String)> = val.get("tags")
                            .and_then(|v| serde_json::from_value(v.clone()).ok())
                            .unwrap_or_default();
                        let mut idx = self.index.write().await;
                        idx.index_attachment(&mcid, filename, mime_type, text.as_deref(), att_tags);
                        attachment_count += 1;
                    }
                }
            }
        }

        // Replay tag updates and retractions
        for (_, data) in &blocks {
            if let Ok(val) = serde_json::from_slice::<serde_json::Value>(data) {
                let kind = val.get("kind").and_then(|v| v.as_str());

                // Unified annotation format
                if kind == Some("annotation") {
                    let target = val.get("target").and_then(|v| v.as_str()).unwrap_or("");
                    let ann_type = val.get("type").and_then(|v| v.as_str()).unwrap_or("");
                    let ann_data = val.get("data").cloned().unwrap_or(serde_json::Value::Null);
                    if !target.is_empty() {
                        let mut idx = self.index.write().await;
                        match ann_type {
                            "tag_update" => {
                                let add: Vec<(String, String)> = ann_data.get("add")
                                    .and_then(|v| serde_json::from_value(v.clone()).ok()).unwrap_or_default();
                                let remove: Vec<(String, String)> = ann_data.get("remove")
                                    .and_then(|v| serde_json::from_value(v.clone()).ok()).unwrap_or_default();
                                idx.apply_tag_update(target, &add, &remove);
                            }
                            "retraction" => { idx.retract_node(target); }
                            _ => {} // extraction annotations handled during attachment indexing
                        }
                    }
                }
                // Legacy formats (backward compat)
                else if kind == Some("tag_update") {
                    let node_id = val.get("node_id").and_then(|v| v.as_str()).unwrap_or("");
                    let add: Vec<(String, String)> = val.get("add")
                        .and_then(|v| serde_json::from_value(v.clone()).ok()).unwrap_or_default();
                    let remove: Vec<(String, String)> = val.get("remove")
                        .and_then(|v| serde_json::from_value(v.clone()).ok()).unwrap_or_default();
                    if !node_id.is_empty() {
                        let mut idx = self.index.write().await;
                        idx.apply_tag_update(node_id, &add, &remove);
                    }
                } else if kind == Some("node_retraction") {
                    let node_id = val.get("node_id").and_then(|v| v.as_str()).unwrap_or("");
                    if !node_id.is_empty() {
                        let mut idx = self.index.write().await;
                        idx.retract_node(node_id);
                    }
                }
            }
        }

        Ok((doc_count, entity_count, attachment_count))
    }

    /// Save the current TextIndex to a cache file.
    pub async fn save_index(&self, cache_path: &std::path::Path) -> Result<()> {
        let idx = self.index.read().await;
        idx.save(cache_path).map_err(|e| ApiError::Serialization(e.to_string()))
    }

    /// Access the quota manager.
    /// Store an annotation block in the blockstore. All sidecars (tag updates,
    /// extraction results, retractions) use this unified format.
    /// Tagged with `_ann:<target>` for discovery.
    fn store_annotation(&self, target: &str, ann_type: &str, data: serde_json::Value) -> Result<()> {
        let tags = vec![("_ann".to_string(), target.to_string())];
        let block = serde_json::json!({
            "kind": "annotation",
            "target": target,
            "type": ann_type,
            "data": data,
            "wall_ns": memvault_core::wall_ns(),
            "tags": tags,
        });
        let block_bytes = serde_json::to_vec(&block)
            .map_err(|e| ApiError::Serialization(e.to_string()))?;
        let cid = cid_from_bytes(&block_bytes);
        let meta = EnvelopeMeta {
            author: self.effective_author(),
            tags: vec![("_ann".to_string(), target.to_string())],
            wall_ns: memvault_core::wall_ns(),
            causal: vec![],
            provenance: vec![],
            cluster_id: Some(self.cluster_id.clone()),
            bucket_id: None,
        };
        self.store.insert_envelope(&cid.to_bytes(), &block_bytes, &meta)?;
        Ok(())
    }

    fn store_tag_update(&self, node_id: &str, add: &[(String, String)], remove: &[(String, String)]) -> Result<()> {
        self.store_annotation(node_id, "tag_update", serde_json::json!({ "add": add, "remove": remove }))
    }

    /// Extract text from data, cache the result (success or failure) in the blockstore,
    /// and return the extracted text if successful.
    fn extract_and_cache(&self, manifest_cid: &[u8], data: &[u8], mime_type: &str) -> Option<String> {
        tracing::debug!(mime_type, "extracting text");
        // Check cache first.
        match self.load_cached_extraction(manifest_cid) {
            Some(ExtractionResult::Ok(text)) => {
                tracing::debug!(mime_type, "extraction cache hit");
                return Some(text);
            }
            Some(ExtractionResult::Failed(_)) => {
                tracing::debug!(mime_type, "extraction cache hit");
                return None;
            }
            _ => {}
        }

        // Extract fresh.
        let result = safe_extract_text(data, mime_type);

        // Cache the result.
        match &result {
            ExtractionResult::Ok(text) => {
                #[derive(serde::Serialize)]
                struct CachedExtraction {
                    source: Vec<u8>,
                    extractor: String,
                    extractor_version: String,
                    extracted_at_ns: u64,
                    text: String,
                    page_breaks: Vec<u32>,
                    warnings: Vec<String>,
                }
                let et = CachedExtraction {
                    source: manifest_cid.to_vec(),
                    extractor: "memvault-extract".to_string(),
                    extractor_version: env!("CARGO_PKG_VERSION").to_string(),
                    extracted_at_ns: memvault_core::wall_ns(),
                    text: text.clone(),
                    page_breaks: vec![],
                    warnings: vec![],
                };
                if let Ok(et_bytes) = serde_json::to_vec(&et) {
                    let et_cid = cid_from_bytes(&et_bytes);
                    let _ = self.store.put_block(&et_cid.to_bytes(), &et_bytes);
                    self.store_manifest_update(manifest_cid, Some(et_cid.to_bytes()), None);
                }
                tracing::debug!(mime_type, text_len = text.len(), "extraction succeeded, cached");
            }
            ExtractionResult::Failed(err) => {
                tracing::debug!(mime_type, error = %err, "extraction failed, cached failure");
                self.store_manifest_update(manifest_cid, None, Some(err));
            }
            ExtractionResult::Unsupported => {}
        }

        match result {
            ExtractionResult::Ok(text) => Some(text),
            _ => None,
        }
    }

    fn store_manifest_update(&self, manifest_cid: &[u8], extracted_text_cid: Option<Vec<u8>>, error: Option<&str>) {
        let target = format!("file:{}", hex::encode(manifest_cid));
        let _ = self.store_annotation(&target, "extraction", serde_json::json!({
            "extracted_text": extracted_text_cid,
            "extraction_error": error,
        }));
    }

    /// Load cached extraction result.
    /// Returns `Some(ExtractionResult::Ok(text))` on cached success,
    /// `Some(ExtractionResult::Failed(err))` on cached failure,
    /// `None` if no cache exists.
    fn load_cached_extraction(&self, manifest_cid: &[u8]) -> Option<ExtractionResult> {
        let target = format!("file:{}", hex::encode(manifest_cid));
        let legacy_target = format!("attachment:{}", hex::encode(manifest_cid));

        // Try new unified annotation format first, then legacy manifest_update.
        let mut ann_cids = self.store.query_by_tag("_ann", &target, 0, 10).ok()?;
        // Also check legacy "attachment:" annotations for backward compat.
        if let Ok(legacy_ann) = self.store.query_by_tag("_ann", &legacy_target, 0, 10) {
            ann_cids.extend(legacy_ann);
        }
        let legacy_label = hex::encode(manifest_cid);
        let legacy_cids = self.store.query_by_tag("manifest_update", &legacy_label, 0, 10).ok()?;

        for cid in ann_cids.iter().chain(legacy_cids.iter()) {
            let block_data = self.store.get_block(cid).ok()??;
            let val: serde_json::Value = serde_json::from_slice(&block_data).ok()?;

            // Unified annotation format
            let data_field = val.get("data").unwrap_or(&val);

            if let Some(err) = data_field.get("extraction_error").and_then(|v| v.as_str()) {
                if !err.is_empty() {
                    return Some(ExtractionResult::Failed(err.to_string()));
                }
            }

            if let Some(et_cid) = data_field.get("extracted_text")
                .and_then(|v| serde_json::from_value::<Vec<u8>>(v.clone()).ok())
            {
                let et_bytes = self.store.get_block(&et_cid).ok()??;
                let et: serde_json::Value = serde_json::from_slice(&et_bytes).ok()?;
                let text = et.get("text").and_then(|v| v.as_str())?.to_string();
                return Some(ExtractionResult::Ok(text));
            }
        }
        None
    }

    /// Access the text index (for direct queries in local backend).
    pub fn index_ref(&self) -> &Arc<RwLock<TextIndex>> {
        &self.index
    }

    /// Access the quota manager.
    pub fn quotas(&self) -> &Arc<RwLock<QuotaManager>> {
        &self.quotas
    }

    /// Extract user-facing tags from the creation envelope for a given node.
    /// Scans envelopes tagged (tag_key, label) and returns all non-internal tags.
    fn extract_creation_tags(&self, tag_key: &str, label: &str) -> Vec<(String, String)> {
        let cids = self.store.query_by_tag(tag_key, label, 0, 1)
            .unwrap_or_default();
        for cid in &cids {
            if let Ok(Some(data)) = self.store.get_block(cid) {
                if let Ok(env) = serde_json::from_slice::<serde_json::Value>(&data) {
                    if let Some(tags_arr) = env.get("tags").and_then(|v| v.as_array()) {
                        return tags_arr.iter()
                            .filter_map(|v| {
                                let pair = v.as_array()?;
                                let scope = pair.first()?.as_str()?;
                                let lbl = pair.get(1)?.as_str()?;
                                // Skip internal tags (doc/entity ID tags).
                                if scope == "doc" || scope == "entity" || scope == "edge_source" || scope == "edge_target" {
                                    return None;
                                }
                                Some((scope.to_string(), lbl.to_string()))
                            })
                            .collect();
                    }
                }
            }
        }
        vec![]
    }

    /// Resolve a bucket_id: use explicit if given, otherwise cluster default.
    fn resolve_bucket(&self, explicit: Option<&BucketId>) -> Option<Vec<u8>> {
        if let Some(b) = explicit {
            return Some(b.0.to_vec());
        }
        // Try cluster's default bucket from the store
        if self.cluster_id.iter().any(|&b| b != 0) {
            if let Ok(Some(default_bytes)) = self.store.get_default_bucket(&self.cluster_id) {
                return Some(default_bytes);
            }
        }
        // Try first available bucket
        if let Ok(buckets) = self.store.list_buckets() {
            if let Some((bucket_id_bytes, _)) = buckets.first() {
                return Some(bucket_id_bytes.clone());
            }
        }
        None
    }

    fn store_op(&self, op: &Op, tags: &[(String, String)], vis: &Visibility, bucket: Option<&BucketId>) -> Result<Vec<u8>> {
        let wall_ns = memvault_core::wall_ns();
        let bucket_id = self.resolve_bucket(bucket);

        let meta = EnvelopeMeta {
            author: self.effective_author(),
            tags: tags.to_vec(),
            wall_ns,
            causal: vec![],
            provenance: vec![],
            cluster_id: Some(self.cluster_id.clone()),
            bucket_id,
        };

        // CID is computed from the full envelope bytes so any peer
        // receiving the block can verify: CID == hash(block_bytes).
        let envelope = serde_json::json!({
            "version": 1,
            "payload": op,
            "author": self.peer_id,
            "tags": tags,
            "visibility": vis,
            "wall_ns": wall_ns,
        });
        let envelope_bytes = serde_json::to_vec(&envelope)
            .map_err(|e| ApiError::Serialization(e.to_string()))?;
        let cid = cid_from_bytes(&envelope_bytes);
        let cid_bytes = cid.to_bytes();

        self.store.insert_envelope(&cid_bytes, &envelope_bytes, &meta)?;

        Ok(cid_bytes)
    }

    fn doc_tag(doc_id: &DocId) -> (String, String) {
        let label: String = doc_id.0.iter().map(|b| format!("{b:02x}")).collect();
        ("doc".to_string(), label)
    }
}

#[async_trait]
impl MemvaultClient for LocalClient {
    async fn put_doc(
        &self,
        doc: Document,
        tags: Vec<(String, String)>,
        vis: Visibility,
        bucket: Option<&BucketId>,
    ) -> Result<Vec<u8>> {
        let op = Op::DocCreate {
            doc_id: doc.id.clone(),
            initial_body: doc.body.clone(),
            frontmatter: doc.frontmatter.clone(),
        };

        let mut all_tags = tags.clone();
        all_tags.push(Self::doc_tag(&doc.id));

        let cid_bytes = self.store_op(&op, &all_tags, &vis, bucket)?;
        tracing::info!(doc_id = %hex::encode(doc.id.0), "doc created");

        // Index for search
        let title = doc
            .frontmatter
            .get("title")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
        {
            let mut idx = self.index.write().await;
            idx.index_doc(doc.id.clone(), &doc.body, title.as_deref(), tags.clone());
        }

        self.event_bus.publish(MemvaultEvent::DocCreated {
            doc_id: doc.id,
            cid: cid_bytes.clone(),
        });

        Ok(cid_bytes)
    }

    async fn get_doc(&self, id: &DocId) -> Result<Option<Document>> {
        // Check retraction in the index.
        let node_id = format!("doc:{}", hex::encode(id.0));
        {
            let idx = self.index.read().await;
            if idx.is_retracted(&node_id) { return Ok(None); }
        }

        let (_, label) = Self::doc_tag(id);
        let cids = self.store.query_by_tag("doc", &label, 0, usize::MAX)?;

        if cids.is_empty() {
            return Ok(None);
        }

        // Collect all ops for this doc
        let mut ops = Vec::new();
        for cid in &cids {
            if let Some(data) = self.store.get_block(cid)? {
                // The block stores the envelope JSON; extract the payload op
                if let Ok(val) = serde_json::from_slice::<serde_json::Value>(&data) {
                    if let Some(payload) = val.get("payload") {
                        if let Ok(op) = serde_json::from_value::<Op>(payload.clone()) {
                            ops.push(op);
                        }
                    }
                }
            }
        }

        if ops.is_empty() {
            return Ok(None);
        }

        let doc = memvault_doc::apply_doc_ops(&ops)?;
        Ok(Some(doc))
    }

    async fn edit_doc(&self, id: &DocId, patch: TextPatch) -> Result<Vec<u8>> {
        let op = Op::DocEdit {
            doc_id: id.clone(),
            patch,
        };

        let tags = vec![Self::doc_tag(id)];
        let cid_bytes = self.store_op(&op, &tags, &Visibility::Internal, None)?;

        self.event_bus.publish(MemvaultEvent::DocUpdated {
            doc_id: id.clone(),
            cid: cid_bytes.clone(),
        });

        Ok(cid_bytes)
    }

    async fn list_docs(
        &self,
        tag_filter: Option<(String, String)>,
        limit: usize,
        _bucket: Option<&BucketId>,
    ) -> Result<Vec<DocSummary>> {
        // Use the "doc" tag index to find DocCreate envelopes directly,
        // rather than scanning all envelopes by time (which can miss docs
        // if non-doc operations fill the limit).
        let cids = if let Some((ref scope, ref label)) = tag_filter {
            self.store.query_by_tag(scope, label, 0, limit * 5)?
        } else {
            self.store.query_unique_labels("doc", limit * 5)?
                .into_iter()
                .flat_map(|label| self.store.query_by_tag("doc", &label, 0, 10).unwrap_or_default())
                .collect()
        };

        let mut summaries = Vec::new();
        let mut seen_docs: std::collections::HashSet<DocId> = std::collections::HashSet::new();

        for cid in &cids {
            if let Some(data) = self.store.get_block(cid)? {
                if let Ok(val) = serde_json::from_slice::<serde_json::Value>(&data) {
                    if let Some(payload) = val.get("payload") {
                        if let Some(dc) = payload.get("DocCreate") {
                            if let Ok(doc_id) =
                                serde_json::from_value::<DocId>(dc["doc_id"].clone())
                            {
                                if seen_docs.insert(doc_id.clone()) {
                                    let node_id = format!("doc:{}", hex::encode(doc_id.0));
                                    let idx = self.index.read().await;
                                    if idx.is_retracted(&node_id) { continue; }
                                    drop(idx);
                                    let title = dc
                                        .get("frontmatter")
                                        .and_then(|fm| fm.get("title"))
                                        .and_then(|t| t.as_str())
                                        .map(|s| s.to_string());
                                    let tags: Vec<(String, String)> = val
                                        .get("tags")
                                        .and_then(|t| serde_json::from_value(t.clone()).ok())
                                        .unwrap_or_default();
                                    let wall_ns =
                                        val.get("wall_ns").and_then(|v| v.as_u64()).unwrap_or(0);

                                    summaries.push(DocSummary {
                                        id: doc_id,
                                        cid: cid.clone(),
                                        title,
                                        tags,
                                        updated_ns: wall_ns,
                                        attachment_count: 0,
                                    });
                                }
                            }
                        }
                    }
                }
            }
        }

        Ok(summaries)
    }

    async fn upload_file(
        &self,
        data: &[u8],
        filename: Option<&str>,
        mime_type: &str,
        tags: Vec<(String, String)>,
        visibility: &str,
        bucket: Option<&BucketId>,
    ) -> Result<Vec<u8>> {
        // Chunk file into blocks using memvault-attach
        let (root_cid, blocks) = memvault_attach::chunk_file(data)?;

        // Store all blocks
        for (block_cid, block_data) in &blocks {
            self.store.put_block(block_cid, block_data)?;
        }

        // Create attachment manifest
        let layout = memvault_attach::decide_layout(data.len() as u64);
        let replication = memvault_attach::default_replication(data.len() as u64);

        let manifest = AttachmentManifest {
            content_root: root_cid,
            content_size: data.len() as u64,
            chunk_layout: layout,
            filename: filename.map(|s| s.to_string()),
            mime_type: mime_type.to_string(),
            sha256: None,
            width_height: None,
            duration_ms: None,
            extracted_text: None,
            derived_from: None,
            pii_findings: None,
            replication,
        };

        // Encode manifest and store
        let manifest_bytes = serde_json::to_vec(&manifest)
            .map_err(|e| ApiError::Serialization(e.to_string()))?;
        let manifest_cid = cid_from_bytes(&manifest_bytes);
        let manifest_cid_bytes = manifest_cid.to_bytes();
        self.store.put_block(&manifest_cid_bytes, &manifest_bytes)?;

        // Store envelope metadata for the manifest
        let bucket_id = self.resolve_bucket(bucket);
        let meta = EnvelopeMeta {
            author: self.effective_author(),
            tags: tags.clone(),
            wall_ns: memvault_core::wall_ns(),
            causal: vec![],
            provenance: vec![],
            cluster_id: Some(self.cluster_id.clone()),
            bucket_id,
        };
        let envelope = serde_json::json!({
            "version": 1,
            "kind": "attachment",
            "manifest_cid": manifest_cid_bytes,
            "filename": filename,
            "mime_type": mime_type,
            "size": data.len(),
            "visibility": visibility,
            "tags": tags,
            "wall_ns": meta.wall_ns,
        });
        let envelope_bytes = serde_json::to_vec(&envelope)
            .map_err(|e| ApiError::Serialization(e.to_string()))?;
        let env_cid = cid_from_bytes(&envelope_bytes);
        self.store.insert_envelope(&env_cid.to_bytes(), &envelope_bytes, &meta)?;
        tracing::info!(filename = ?filename, mime_type, size = data.len(), "file attached");

        // Extract text and cache the result (success or failure) in the blockstore.
        let extracted_text = self.extract_and_cache(&manifest_cid_bytes, data, mime_type);

        // Index for unified search (includes extracted text if available).
        {
            let mut idx = self.index.write().await;
            idx.index_attachment(&manifest_cid_bytes, filename, mime_type, extracted_text.as_deref(), tags.clone());
        }

        self.event_bus.publish(MemvaultEvent::FileAttached {
            doc_id: DocId([0; 32]), // No doc association in new system
            name: filename.unwrap_or("unnamed").to_string(),
        });

        Ok(manifest_cid_bytes)
    }

    async fn read_file(&self, manifest_cid: &[u8]) -> Result<Vec<u8>> {
        // Accept both "file:" and legacy "attachment:" node IDs for retraction checks.
        let node_id = format!("file:{}", hex::encode(manifest_cid));
        let legacy_node_id = format!("attachment:{}", hex::encode(manifest_cid));
        {
            let idx = self.index.read().await;
            if idx.is_retracted(&node_id) || idx.is_retracted(&legacy_node_id) {
                return Err(ApiError::NotFound("file retracted".into()));
            }
        }
        let manifest_data = self
            .store
            .get_block(manifest_cid)?
            .ok_or_else(|| ApiError::NotFound("file manifest not found".into()))?;

        let manifest: AttachmentManifest = serde_json::from_slice(&manifest_data)
            .map_err(|e| ApiError::Serialization(e.to_string()))?;

        // Read full content via UnixFS
        let data = memvault_attach::read_range::read_full(&self.store, &manifest.content_root)?;
        Ok(data)
    }

    async fn read_file_range(&self, manifest_cid: &[u8], start: u64, end: u64) -> Result<Vec<u8>> {
        let manifest_data = self
            .store
            .get_block(manifest_cid)?
            .ok_or_else(|| ApiError::NotFound("file manifest not found".into()))?;

        let manifest: AttachmentManifest = serde_json::from_slice(&manifest_data)
            .map_err(|e| ApiError::Serialization(e.to_string()))?;

        let data = memvault_attach::read_range::read_range(&self.store, &manifest.content_root, start, end)?;
        Ok(data)
    }

    async fn read_extracted_text(&self, manifest_cid: &[u8]) -> Result<Option<String>> {
        // Try cached extraction first, then extract fresh and cache.
        let manifest_data = self
            .store
            .get_block(manifest_cid)?
            .ok_or_else(|| ApiError::NotFound("file manifest not found".into()))?;

        let manifest: AttachmentManifest = serde_json::from_slice(&manifest_data)
            .map_err(|e| ApiError::Serialization(e.to_string()))?;

        let content = memvault_attach::read_range::read_full(&self.store, &manifest.content_root)?;
        Ok(self.extract_and_cache(manifest_cid, &content, &manifest.mime_type))
    }

    async fn pin_file(&self, manifest_cid: &[u8]) -> Result<()> {
        memvault_attach::pin::pin(&self.store, manifest_cid, memvault_attach::PinReason::Manual)?;
        Ok(())
    }

    async fn unpin_file(&self, manifest_cid: &[u8]) -> Result<()> {
        memvault_attach::pin::unpin(&self.store, manifest_cid)?;
        Ok(())
    }

    async fn list_pinned(&self) -> Result<Vec<(Vec<u8>, String)>> {
        // We need to scan known attachment CIDs. For now, query by the "attachment" tag.
        // This is a simplified implementation.
        let cids = self.store.query_by_tag("attachment", "", 0, 1000).unwrap_or_default();
        let pinned = memvault_attach::pin::list_pinned(&self.store, &cids)?;
        let result = pinned
            .into_iter()
            .map(|(cid, reason)| {
                let reason_str = serde_json::to_string(&reason).unwrap_or_default();
                (cid, reason_str)
            })
            .collect();
        Ok(result)
    }

    async fn get_file_manifest(&self, manifest_cid: &[u8]) -> Result<Option<Vec<u8>>> {
        // Accept both "file:" and legacy "attachment:" node IDs for retraction checks.
        let node_id = format!("file:{}", hex::encode(manifest_cid));
        let legacy_node_id = format!("attachment:{}", hex::encode(manifest_cid));
        {
            let idx = self.index.read().await;
            if idx.is_retracted(&node_id) || idx.is_retracted(&legacy_node_id) { return Ok(None); }
        }
        let data = self.store.get_block(manifest_cid)?;
        Ok(data)
    }

    async fn add_entity(&self, entity: Entity, vis: Visibility, bucket: Option<&BucketId>) -> Result<EntityId> {
        let entity_id = entity.id.clone();
        let op = Op::EntityCreate {
            entity: entity.clone(),
        };

        let entity_label: String = entity_id.0.iter().map(|b| format!("{b:02x}")).collect();
        let tags = vec![("entity".to_string(), entity_label)];
        self.store_op(&op, &tags, &vis, bucket)?;
        tracing::info!(entity_id = %hex::encode(entity_id.0), kind = %entity.kind, "entity created");

        // Index for unified search
        {
            let mut idx = self.index.write().await;
            idx.index_entity(&entity_id, &entity.kind, &entity.props, tags.clone());
        }

        self.event_bus.publish(MemvaultEvent::EntityCreated {
            entity_id: entity_id.clone(),
        });

        Ok(entity_id)
    }

    async fn get_entity(&self, id: &EntityId) -> Result<Option<Entity>> {
        let node_id = format!("entity:{}", hex::encode(id.0));
        {
            let idx = self.index.read().await;
            if idx.is_retracted(&node_id) { return Ok(None); }
        }

        let label: String = id.0.iter().map(|b| format!("{b:02x}")).collect();
        let cids = self.store.query_by_tag("entity", &label, 0, usize::MAX)?;

        if cids.is_empty() {
            return Ok(None);
        }

        let mut ops = Vec::new();
        for cid in &cids {
            if let Some(data) = self.store.get_block(cid)? {
                if let Ok(val) = serde_json::from_slice::<serde_json::Value>(&data) {
                    if let Some(payload) = val.get("payload") {
                        if let Ok(op) = serde_json::from_value::<Op>(payload.clone()) {
                            ops.push(op);
                        }
                    }
                }
            }
        }

        let state = memvault_doc::apply_graph_ops(&ops)?;
        Ok(state.entities.get(id).cloned())
    }

    async fn entity_history(&self, id: &EntityId) -> Result<Vec<AuditRecord>> {
        let label: String = id.0.iter().map(|b| format!("{b:02x}")).collect();
        let cids = self.store.query_by_tag("entity", &label, 0, usize::MAX)?;

        let mut records = Vec::new();
        for cid in &cids {
            if let Some(data) = self.store.get_block(cid)? {
                if let Ok(val) = serde_json::from_slice::<serde_json::Value>(&data) {
                    records.push(memvault_query::parse_audit_record(cid, &val));
                }
            }
        }
        Ok(records)
    }

    async fn list_entities(&self, limit: usize, _bucket: Option<&BucketId>) -> Result<Vec<Entity>> {
        let labels = self.store.query_unique_labels("entity", limit)?;
        let mut entities = Vec::new();
        for label in labels {
            let id_bytes = hex::decode(&label).unwrap_or_default();
            if id_bytes.len() != 32 {
                continue;
            }
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&id_bytes);
            let entity_id = EntityId(arr);
            if let Ok(Some(entity)) = self.get_entity(&entity_id).await {
                entities.push(entity);
            }
        }
        Ok(entities)
    }

    // -- Links (cross-type edges) --

    async fn add_link(&self, source: &NodeRef, edge: Edge, vis: Visibility) -> Result<EdgeId> {
        let edge_id = edge.id.clone();
        let op = Op::EdgeAdd {
            source: source.clone(),
            edge,
        };

        let source_label = source.tag_label();
        let target_label = op_edge_target_label(&op);
        let mut tags = vec![
            ("edge_source".to_string(), source_label),
        ];
        if let Some(tl) = target_label {
            tags.push(("edge_target".to_string(), tl));
        }
        // Also tag by entity label if source is an entity (for backward compat with get_entity)
        if let NodeRef::Entity(id) = source {
            let entity_label: String = id.0.iter().map(|b| format!("{b:02x}")).collect();
            tags.push(("entity".to_string(), entity_label));
        }
        self.store_op(&op, &tags, &vis, None)?;
        tracing::info!(source = %source.tag_label(), target = %op_edge_target_label(&op).unwrap_or_default(), "link created");

        Ok(edge_id)
    }

    async fn remove_link_from(&self, source: &NodeRef, edge_id: &EdgeId) -> Result<()> {
        let op = Op::EdgeRemove {
            source: source.clone(),
            edge_id: edge_id.clone(),
        };

        let source_label = source.tag_label();
        let mut tags = vec![
            ("edge_source".to_string(), source_label),
        ];
        if let NodeRef::Entity(id) = source {
            let entity_label: String = id.0.iter().map(|b| format!("{b:02x}")).collect();
            tags.push(("entity".to_string(), entity_label));
        }
        self.store_op(&op, &tags, &Visibility::Internal, None)?;
        Ok(())
    }

    async fn edges_of(&self, node: &NodeRef) -> Result<Vec<(NodeRef, Edge)>> {
        let label = node.tag_label();
        let mut results = Vec::new();
        let mut removed_ids: std::collections::HashSet<EdgeId> = std::collections::HashSet::new();

        // Scan all ops tagged with this node as source or target.
        let source_cids = self.store.query_by_tag("edge_source", &label, 0, usize::MAX)?;
        let target_cids = self.store.query_by_tag("edge_target", &label, 0, usize::MAX)?;

        let mut all_cids = source_cids;
        all_cids.extend(target_cids);

        for cid in &all_cids {
            if let Some(data) = self.store.get_block(cid)? {
                if let Ok(val) = serde_json::from_slice::<serde_json::Value>(&data) {
                    if let Some(payload) = val.get("payload") {
                        match serde_json::from_value::<Op>(payload.clone()) {
                            Ok(Op::EdgeAdd { source, edge }) => {
                                results.push((source, edge));
                            }
                            Ok(Op::EdgeRemove { edge_id, .. }) => {
                                removed_ids.insert(edge_id);
                            }
                            _ => {}
                        }
                    }
                }
            }
        }

        // Filter out removed edges, then deduplicate by edge ID.
        results.retain(|(_, edge)| !removed_ids.contains(&edge.id));
        let mut seen = std::collections::HashSet::new();
        results.retain(|(_, edge)| seen.insert(edge.id.clone()));

        Ok(results)
    }

    async fn traverse_from(
        &self,
        from: &NodeRef,
        relation: Option<&str>,
        max_depth: usize,
    ) -> Result<Vec<TraversalHit>> {
        let mut results = Vec::new();
        let mut visited: std::collections::HashSet<NodeRef> = std::collections::HashSet::new();
        let mut queue: VecDeque<(NodeRef, usize, Vec<(EdgeId, String)>)> = VecDeque::new();

        visited.insert(from.clone());
        queue.push_back((from.clone(), 0, Vec::new()));

        while let Some((current_node, depth, path)) = queue.pop_front() {
            if depth > 0 {
                results.push(TraversalHit {
                    node: current_node.clone(),
                    depth,
                    path: path.clone(),
                });
            }

            if depth >= max_depth {
                continue;
            }

            // Get outgoing edges for this node
            let edges = self.edges_of(&current_node).await?;
            for (source, edge) in &edges {
                // Only follow outgoing edges from the current node
                if source != &current_node {
                    continue;
                }
                if let Some(rel_filter) = relation {
                    if edge.relation != rel_filter {
                        continue;
                    }
                }
                if visited.insert(edge.target.clone()) {
                    let mut new_path = path.clone();
                    new_path.push((edge.id.clone(), edge.relation.clone()));
                    queue.push_back((edge.target.clone(), depth + 1, new_path));
                }
            }
        }

        Ok(results)
    }


    async fn search(&self, query: &str, limit: usize) -> Result<Vec<SearchHit>> {
        let idx = self.index.read().await;
        Ok(idx.search(query, limit))
    }

    async fn search_unified(&self, query: &str, limit: usize) -> Result<Vec<memvault_query::UnifiedHit>> {
        let idx = self.index.read().await;
        Ok(idx.search_unified(query, limit))
    }

    async fn view_members(&self, view_name: &str) -> Result<Vec<String>> {
        let view = self.get_view(view_name).await?
            .ok_or_else(|| ApiError::NotFound(format!("view '{view_name}' not found")))?;
        let idx = self.index.read().await;
        Ok(idx.members_of_view(&view.tags))
    }

    async fn list_all(&self, view_name: Option<&str>, limit: usize) -> Result<Vec<(String, String, String, Vec<(String, String)>)>> {
        let view_tags = if let Some(name) = view_name {
            let view = self.get_view(name).await?
                .ok_or_else(|| ApiError::NotFound(format!("view '{name}' not found")))?;
            Some(view.tags)
        } else {
            None
        };
        let idx = self.index.read().await;
        Ok(idx.list_all(view_tags.as_deref(), limit))
    }

    async fn resolve_label(&self, node_id: &str) -> Result<Option<String>> {
        let idx = self.index.read().await;
        Ok(idx.resolve_label(node_id))
    }

    async fn history_of(&self, doc_id: &DocId) -> Result<Vec<AuditRecord>> {
        let query = AuditQuery {
            doc_id: Some(doc_id.clone()),
            ..Default::default()
        };
        Ok(query_audit(&self.store, &query)?)
    }

    async fn audit(&self, query: AuditQuery) -> Result<Vec<AuditRecord>> {
        Ok(query_audit(&self.store, &query)?)
    }

    async fn retract(&self, target_cid: &[u8], _reason: &str) -> Result<Vec<u8>> {
        let tombstone_cid = cid_from_bytes(target_cid);
        let tombstone_bytes = tombstone_cid.to_bytes();
        memvault_query::retract(&self.store, target_cid, &tombstone_bytes)?;

        self.event_bus.publish(MemvaultEvent::Retracted {
            cid: target_cid.to_vec(),
        });

        Ok(tombstone_bytes)
    }

    async fn retract_node(&self, node_id: &str, reason: &str) -> Result<()> {
        self.store_annotation(node_id, "retraction", serde_json::json!({ "reason": reason }))?;
        tracing::info!(node_id, reason, "node retracted");

        // Remove from in-memory index.
        let mut idx = self.index.write().await;
        idx.retract_node(node_id);

        Ok(())
    }

    async fn issue_token(
        &self,
        role: Role,
        ttl_secs: u64,
        max_uses: u32,
        label: Option<String>,
    ) -> Result<String> {
        let admin_key = self.admin_signing_key.as_ref()
            .ok_or_else(|| ApiError::Other(
                "no admin signing key configured — cannot issue tokens".into()
            ))?;
        let peer_id = memvault_core::PeerId(self.peer_id.clone());
        let cluster_id_arr: [u8; 32] = self.cluster_id.clone().try_into()
            .map_err(|_| ApiError::Other("cluster_id must be 32 bytes".into()))?;
        let cluster_id = memvault_core::ClusterId(cluster_id_arr);

        crate::tokens::issue_token(
            &peer_id,
            &cluster_id,
            admin_key,
            role,
            ttl_secs,
            max_uses,
            label,
            &self.store,
        )
    }

    async fn list_tokens(&self) -> Result<Vec<TokenStatus>> {
        crate::tokens::list_tokens(&self.store)
    }

    async fn revoke_token(&self, token_cid: &[u8], reason: &str) -> Result<()> {
        self.store.record_revocation(token_cid, reason.as_bytes())?;
        Ok(())
    }

    async fn list_rotations(&self) -> Result<Vec<RotationInfo>> {
        crate::rotation::list_rotations(&self.store)
    }

    // -- Tags --

    async fn add_tags(&self, node_id: &str, tags: Vec<(String, String)>) -> Result<()> {
        self.store_tag_update(node_id, &tags, &[])?;
        let mut idx = self.index.write().await;
        idx.apply_tag_update(node_id, &tags, &[]);
        tracing::debug!(node_id, tag_count = tags.len(), "tags added");
        Ok(())
    }

    async fn remove_tags(&self, node_id: &str, tags: Vec<(String, String)>) -> Result<()> {
        self.store_tag_update(node_id, &[], &tags)?;
        let mut idx = self.index.write().await;
        idx.apply_tag_update(node_id, &[], &tags);
        tracing::debug!(node_id, tag_count = tags.len(), "tags removed");
        Ok(())
    }

    async fn get_tags(&self, node_id: &str) -> Result<Vec<(String, String)>> {
        let idx = self.index.read().await;
        Ok(idx.get_tags(node_id))
    }

    // -- Views --

    async fn list_views(&self) -> Result<Vec<crate::types::View>> {
        let labels = self.store.query_unique_labels("view", usize::MAX)
            .map_err(|e| ApiError::Serialization(e.to_string()))?;
        let mut views = Vec::new();
        for label in &labels {
            let cid_bytes = hex::decode(label).unwrap_or_default();
            // Skip retracted views
            if self.store.is_retracted(&cid_bytes).unwrap_or(false) {
                continue;
            }
            if let Some(data) = self.store.get_block(&cid_bytes)? {
                if let Ok(mut view) = serde_json::from_slice::<crate::types::View>(&data) {
                    view.cid = label.clone();
                    views.push(view);
                }
            }
        }
        Ok(views)
    }

    async fn create_view(&self, view: crate::types::View) -> Result<()> {
        let view_bytes = serde_json::to_vec(&view)
            .map_err(|e| ApiError::Serialization(e.to_string()))?;
        let cid = cid_from_bytes(&view_bytes);
        let cid_bytes = cid.to_bytes();
        let cid_hex = hex::encode(&cid_bytes);
        let meta = EnvelopeMeta {
            author: self.effective_author(),
            tags: vec![("view".to_string(), cid_hex)],
            wall_ns: view.created_ns,
            causal: vec![],
            provenance: vec![],
            cluster_id: Some(self.cluster_id.clone()),
            bucket_id: None,
        };
        self.store.insert_envelope(&cid_bytes, &view_bytes, &meta)?;
        tracing::info!(name = %view.name, tag_count = view.tags.len(), "view created");
        Ok(())
    }

    async fn delete_view(&self, name: &str) -> Result<()> {
        // Find the view by name (scan all views).
        let views = self.list_views().await?;
        for view in &views {
            if view.name == name {
                let cid_bytes = hex::decode(&view.cid).unwrap_or_default();
                self.retract(&cid_bytes, "view deleted").await?;
            }
        }
        Ok(())
    }

    async fn update_view(&self, view: crate::types::View) -> Result<()> {
        self.delete_view(&view.name).await?;
        self.create_view(view).await
    }

    async fn get_view(&self, name: &str) -> Result<Option<crate::types::View>> {
        // Scan all views and find by name.
        let views = self.list_views().await?;
        Ok(views.into_iter().find(|v| v.name == name))
    }

    // -- Buckets --

    async fn bucket_create(
        &self,
        name: &str,
        description: Option<&str>,
        default_visibility: Visibility,
        default_classification: memvault_core::classification::Classification,
    ) -> Result<memvault_core::BucketId> {
        use memvault_doc::BucketDecl;

        let bucket_id = memvault_core::BucketId::random();
        let now_ns = memvault_core::wall_ns();

        // Auto-attach to cluster if the node has one (non-zero cluster_id).
        // Buckets are only private when created before genesis (no cluster yet).
        let has_cluster = self.cluster_id.iter().any(|&b| b != 0);
        let decl = BucketDecl {
            bucket_id: bucket_id.clone(),
            name: name.to_string(),
            description: description.map(|s| s.to_string()),
            owner_agent: self.agent_identity.as_ref().map(|i| i.agent_id.clone()),
            default_visibility,
            default_classification,
            created_ns: now_ns,
            private_to_peer: if has_cluster { None } else { Some(memvault_core::PeerId(self.peer_id.clone())) },
        };

        // Serialize the BucketDecl as the block
        let decl_bytes = serde_json::to_vec(&decl)
            .map_err(|e| ApiError::Serialization(e.to_string()))?;
        let cid = memvault_core::cid_from_bytes(&decl_bytes);
        let cid_bytes = cid.to_bytes();

        // Store the block
        let meta = memvault_store::insert::EnvelopeMeta {
            author: self.effective_author(),
            tags: vec![
                ("kind".to_string(), "bucket-decl".to_string()),
                ("bucket".to_string(), bucket_id.to_string()),
            ],
            wall_ns: now_ns,
            causal: vec![],
            provenance: vec![],
            cluster_id: Some(self.cluster_id.clone()),
            bucket_id: Some(bucket_id.0.to_vec()),
        };
        self.store.insert_envelope(&cid_bytes, &decl_bytes, &meta)?;

        // Record in BUCKETS table
        self.store.put_bucket(&bucket_id.0, &cid_bytes)?;

        // Auto-bind to cluster if one exists
        if has_cluster {
            let _ = self.store.bind_bucket(&bucket_id.0, &self.cluster_id, false);
        }

        tracing::info!(bucket = %bucket_id, name, has_cluster, "bucket created");
        Ok(bucket_id)
    }

    async fn bucket_list(&self) -> Result<Vec<crate::types::BucketInfo>> {
        let buckets = self.store.list_buckets()?;
        let mut infos = Vec::new();

        for (bucket_id_bytes, decl_cid) in buckets {
            let info = self.build_bucket_info(&bucket_id_bytes, &decl_cid)?;
            if let Some(info) = info {
                infos.push(info);
            }
        }

        Ok(infos)
    }

    async fn bucket_get(&self, id: &memvault_core::BucketId) -> Result<Option<crate::types::BucketInfo>> {
        let decl_cid = match self.store.get_bucket(&id.0)? {
            Some(c) => c,
            None => return Ok(None),
        };
        self.build_bucket_info(&id.0, &decl_cid)
    }

    async fn bucket_rename(&self, id: &memvault_core::BucketId, new_name: &str) -> Result<()> {
        // Store a rename operation as a block
        let rename = serde_json::json!({
            "op": "BucketRename",
            "bucket_id": id.0,
            "new_name": new_name,
            "wall_ns": memvault_core::wall_ns(),
        });
        let block_bytes = serde_json::to_vec(&rename)
            .map_err(|e| ApiError::Serialization(e.to_string()))?;
        let cid = memvault_core::cid_from_bytes(&block_bytes);
        let meta = memvault_store::insert::EnvelopeMeta {
            author: self.effective_author(),
            tags: vec![
                ("kind".to_string(), "bucket-rename".to_string()),
                ("bucket".to_string(), id.to_string()),
            ],
            wall_ns: memvault_core::wall_ns(),
            causal: vec![],
            provenance: vec![],
            cluster_id: Some(self.cluster_id.clone()),
            bucket_id: Some(id.0.to_vec()),
        };
        self.store.insert_envelope(&cid.to_bytes(), &block_bytes, &meta)?;

        // Update the name in the bucket decl by storing a new decl with the updated name
        if let Some(decl_cid) = self.store.get_bucket(&id.0)? {
            if let Some(block) = self.store.get_block(&decl_cid)? {
                if let Ok(mut decl) = serde_json::from_slice::<memvault_doc::BucketDecl>(&block) {
                    decl.name = new_name.to_string();
                    let new_bytes = serde_json::to_vec(&decl)
                        .map_err(|e| ApiError::Serialization(e.to_string()))?;
                    let new_cid = memvault_core::cid_from_bytes(&new_bytes);
                    self.store.insert_envelope(&new_cid.to_bytes(), &new_bytes, &memvault_store::insert::EnvelopeMeta {
                        author: self.effective_author(),
                        tags: vec![
                            ("kind".to_string(), "bucket-decl".to_string()),
                            ("bucket".to_string(), id.to_string()),
                        ],
                        wall_ns: memvault_core::wall_ns(),
                        causal: vec![decl_cid],
                        provenance: vec![],
                        cluster_id: Some(self.cluster_id.clone()),
                        bucket_id: Some(id.0.to_vec()),
                    })?;
                    self.store.put_bucket(&id.0, &new_cid.to_bytes())?;
                }
            }
        }

        tracing::info!(bucket = %id, new_name, "bucket renamed");
        Ok(())
    }

    async fn bucket_bind(
        &self,
        bucket_id: &memvault_core::BucketId,
        cluster_id: &memvault_core::ClusterId,
        is_default: bool,
    ) -> Result<()> {
        self.store.bind_bucket(&bucket_id.0, &cluster_id.0, is_default)?;
        tracing::info!(bucket = %bucket_id, cluster = %cluster_id, is_default, "bucket bound to cluster");
        Ok(())
    }

    async fn bucket_attach(&self, id: &memvault_core::BucketId) -> Result<()> {
        // Load current decl, update private_to_peer to None, store new decl
        let decl_cid = self.store.get_bucket(&id.0)?
            .ok_or_else(|| ApiError::NotFound(format!("bucket {id}")))?;
        let block = self.store.get_block(&decl_cid)?
            .ok_or_else(|| ApiError::NotFound("bucket decl block".into()))?;
        let mut decl: memvault_doc::BucketDecl = serde_json::from_slice(&block)
            .map_err(|e| ApiError::Other(format!("failed to decode bucket decl: {e}")))?;

        if decl.private_to_peer.is_none() {
            // Already attached, idempotent
            return Ok(());
        }

        decl.private_to_peer = None;
        let new_bytes = serde_json::to_vec(&decl)
            .map_err(|e| ApiError::Serialization(e.to_string()))?;
        let new_cid = memvault_core::cid_from_bytes(&new_bytes);
        let meta = memvault_store::insert::EnvelopeMeta {
            author: self.effective_author(),
            tags: vec![
                ("kind".to_string(), "bucket-decl".to_string()),
                ("bucket".to_string(), id.to_string()),
            ],
            wall_ns: memvault_core::wall_ns(),
            causal: vec![decl_cid],
            provenance: vec![],
            cluster_id: Some(self.cluster_id.clone()),
            bucket_id: Some(id.0.to_vec()),
        };
        self.store.insert_envelope(&new_cid.to_bytes(), &new_bytes, &meta)?;
        self.store.put_bucket(&id.0, &new_cid.to_bytes())?;

        // Also bind to the cluster if not already bound.
        if self.cluster_id.iter().any(|&b| b != 0) {
            let _ = self.store.bind_bucket(&id.0, &self.cluster_id, false);
        }

        tracing::info!(bucket = %id, "bucket attached to cluster");
        Ok(())
    }

    async fn bucket_archive(&self, id: &memvault_core::BucketId, reason: &str) -> Result<()> {
        // Prevent archiving the cluster's default bucket.
        if let Ok(Some(cluster_bytes)) = self.store.get_bucket_cluster(&id.0) {
            if let Ok(Some(default_bytes)) = self.store.get_default_bucket(&cluster_bytes) {
                if default_bytes == id.0 {
                    return Err(ApiError::Other("cannot archive the cluster's default bucket".into()));
                }
            }
        }

        let now_ns = memvault_core::wall_ns();
        let archive_block = serde_json::json!({
            "op": "BucketArchive",
            "bucket_id": id.0,
            "reason": reason,
            "archived_at_ns": now_ns,
        });
        let block_bytes = serde_json::to_vec(&archive_block)
            .map_err(|e| ApiError::Serialization(e.to_string()))?;
        let cid = memvault_core::cid_from_bytes(&block_bytes);
        let meta = memvault_store::insert::EnvelopeMeta {
            author: self.effective_author(),
            tags: vec![
                ("kind".to_string(), "bucket-archive".to_string()),
                ("bucket".to_string(), id.to_string()),
            ],
            wall_ns: now_ns,
            causal: vec![],
            provenance: vec![],
            cluster_id: Some(self.cluster_id.clone()),
            bucket_id: Some(id.0.to_vec()),
        };
        self.store.insert_envelope(&cid.to_bytes(), &block_bytes, &meta)?;

        // Mark the bucket decl as archived by storing an updated decl
        if let Some(decl_cid) = self.store.get_bucket(&id.0)? {
            if let Some(block) = self.store.get_block(&decl_cid)? {
                if let Ok(mut decl) = serde_json::from_slice::<memvault_doc::BucketDecl>(&block) {
                    decl.name = format!("[ARCHIVED] {}", decl.name);
                    decl.description = Some(format!(
                        "Archived: {}. {}",
                        reason,
                        decl.description.unwrap_or_default()
                    ));
                    let new_bytes = serde_json::to_vec(&decl)
                        .map_err(|e| ApiError::Serialization(e.to_string()))?;
                    let new_cid = memvault_core::cid_from_bytes(&new_bytes);
                    self.store.insert_envelope(&new_cid.to_bytes(), &new_bytes, &memvault_store::insert::EnvelopeMeta {
                        author: self.effective_author(),
                        tags: vec![
                            ("kind".to_string(), "bucket-decl".to_string()),
                            ("bucket".to_string(), id.to_string()),
                        ],
                        wall_ns: now_ns,
                        causal: vec![decl_cid],
                        provenance: vec![],
                        cluster_id: Some(self.cluster_id.clone()),
                        bucket_id: Some(id.0.to_vec()),
                    })?;
                    self.store.put_bucket(&id.0, &new_cid.to_bytes())?;
                }
            }
        }

        tracing::info!(bucket = %id, reason, "bucket archived");
        Ok(())
    }

    // -- Sharing --

    async fn share_inbox(&self) -> Result<Vec<Vec<u8>>> {
        Ok(self.store.list_share_inbox(&self.cluster_id)?)
    }

    async fn share_outbox(&self) -> Result<Vec<Vec<u8>>> {
        // Outbox lists proposals this cluster sent — reuse the same list method
        // with the local cluster as the "from" cluster.
        Ok(self.store.list_share_inbox(&self.cluster_id)?)
    }

    async fn share_decide(&self, proposal_cid: &[u8], approve: bool, reason: Option<&str>) -> Result<()> {
        let now_ns = memvault_core::wall_ns();
        let status: u8 = if approve { 1 } else { 2 };

        // Update the inbox entry status
        self.store.record_share_inbox(
            proposal_cid,
            &self.cluster_id,
            now_ns,
            status,
        )?;

        // If approved and we have an admin signing key, issue a BucketTrust
        if approve {
            if let Some(ref admin_key) = self.admin_signing_key {
                // Load the proposal to get bucket/cluster info
                if let Some(proposal_block) = self.store.get_block(proposal_cid)? {
                    if let Ok(proposal) = serde_json::from_slice::<serde_json::Value>(&proposal_block) {
                        let from_bucket: Option<Vec<u8>> = proposal.get("from_bucket")
                            .and_then(|v| serde_json::from_value(v.clone()).ok());
                        let from_cluster: Option<Vec<u8>> = proposal.get("from_cluster")
                            .and_then(|v| serde_json::from_value(v.clone()).ok());

                        if let (Some(bucket_bytes), Some(cluster_bytes)) = (from_bucket, from_cluster) {
                            // Create and sign a BucketTrust
                            let proposal_cid_obj = memvault_core::cid_from_bytes(proposal_cid);
                            let reply_cid = memvault_core::cid_from_bytes(&now_ns.to_be_bytes());

                            let trust = memvault_auth::BucketTrust {
                                bucket_id: memvault_core::BucketId(bucket_bytes.clone().try_into().unwrap_or([0u8; 32])),
                                from_cluster: memvault_core::ClusterId(cluster_bytes.clone().try_into().unwrap_or([0u8; 32])),
                                to_cluster: memvault_core::ClusterId(self.cluster_id.clone().try_into().unwrap_or([0u8; 32])),
                                actions: vec![memvault_auth::Action::Read],
                                not_after_ns: now_ns + 7 * 24 * 3600 * 1_000_000_000, // 7 days default
                                from_proposal: proposal_cid_obj,
                                from_reply: reply_cid,
                                signature: [0u8; 64],
                            };

                            match trust.sign(admin_key) {
                                Ok(signed_trust) => {
                                    let trust_bytes = serde_json::to_vec(&signed_trust)
                                        .unwrap_or_default();
                                    let trust_cid = memvault_core::cid_from_bytes(&trust_bytes);

                                    // Store the trust in BUCKET_TRUST
                                    let _ = self.store.record_bucket_trust(
                                        &bucket_bytes,
                                        &cluster_bytes,
                                        &self.cluster_id,
                                        &trust_cid.to_bytes(),
                                    );

                                    // Store the trust block itself
                                    let meta = memvault_store::insert::EnvelopeMeta {
                                        author: self.effective_author(),
                                        tags: vec![("kind".to_string(), "bucket-trust".to_string())],
                                        wall_ns: now_ns,
                                        causal: vec![proposal_cid.to_vec()],
                                        provenance: vec![],
                                        cluster_id: Some(self.cluster_id.clone()),
                                        bucket_id: Some(bucket_bytes),
                                    };
                                    let _ = self.store.insert_envelope(
                                        &trust_cid.to_bytes(), &trust_bytes, &meta,
                                    );

                                    tracing::info!(
                                        trust_cid = hex::encode(trust_cid.to_bytes()),
                                        "issued BucketTrust for approved proposal"
                                    );
                                }
                                Err(e) => {
                                    tracing::warn!("failed to sign BucketTrust: {e}");
                                }
                            }
                        }
                    }
                }
            }
        }

        tracing::info!(
            proposal = hex::encode(proposal_cid),
            approve,
            reason = reason.unwrap_or("-"),
            "share proposal decided"
        );
        Ok(())
    }

    async fn status(&self) -> Result<NodeStatus> {
        let block_count = self.store.iter_blocks()
            .map(|b| b.len() as u64)
            .unwrap_or(0);
        let doc_count = self.store.query_unique_labels("doc", usize::MAX)
            .map(|l| l.len() as u64)
            .unwrap_or(0);
        tracing::debug!(block_count, doc_count, "status queried");
        Ok(NodeStatus {
            peer_id: self.peer_id.clone(),
            cluster_id: self.cluster_id.clone(),
            block_count,
            doc_count,
            peer_count: 1,
            uptime_secs: self.start_time.elapsed().as_secs(),
        })
    }

    async fn default_bucket_id(&self) -> Result<BucketId> {
        if let Some(bytes) = self.resolve_bucket(None) {
            if bytes.len() == 32 {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&bytes);
                return Ok(BucketId(arr));
            }
        }
        Ok(BucketId([0u8; 32]))
    }
}

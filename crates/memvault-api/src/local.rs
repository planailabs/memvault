//! LocalClient — implements MemvaultClient directly against the store.

use std::collections::VecDeque;
use std::sync::Arc;

use async_trait::async_trait;
use tokio::sync::RwLock;

use memvault_core::{cid_from_bytes, DocId, EdgeId, EntityId, NodeRef, Visibility};
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
fn safe_extract_text(data: &[u8], mime_type: &str) -> Option<String> {
    let registry = memvault_extract::ExtractionRegistry::with_defaults();
    if !registry.can_extract(mime_type) {
        return None;
    }
    let data = data.to_vec(); // owned copy for catch_unwind
    let mime = mime_type.to_string();
    match std::panic::catch_unwind(move || {
        let registry = memvault_extract::ExtractionRegistry::with_defaults();
        registry.extract(&data, &mime, &memvault_extract::ExtractionHints::default())
    }) {
        Ok(Ok(extracted)) => Some(extracted.text),
        Ok(Err(e)) => {
            tracing::warn!("text extraction failed for {mime_type}: {e}");
            None
        }
        Err(_) => {
            tracing::warn!("text extraction panicked for {mime_type} — skipping");
            None
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
        Self {
            store,
            index,
            quotas,
            event_bus,
            peer_id,
            cluster_id,
            start_time: std::time::Instant::now(),
        }
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
                let mut idx = self.index.write().await;
                idx.index_doc(doc_id, &doc.body, title, vec![]);
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
                let mut idx = self.index.write().await;
                idx.index_entity(&eid, &entity.kind, &entity.props, vec![]);
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
                        // Try cached extracted text first, then extract fresh.
                        let extracted_text = match self.load_cached_extracted_text(&mcid) {
                            Some(text) => Some(text),
                            None => {
                                if let Ok(content) = self.read_attachment(&mcid).await {
                                    safe_extract_text(&content, mime_type)
                                } else {
                                    None
                                }
                            }
                        };
                        let att_tags: Vec<(String, String)> = val.get("tags")
                            .and_then(|v| serde_json::from_value(v.clone()).ok())
                            .unwrap_or_default();
                        let mut idx = self.index.write().await;
                        idx.index_attachment(&mcid, filename, mime_type, extracted_text.as_deref(), att_tags);
                        attachment_count += 1;
                    }
                }
            }
        }

        // Replay tag updates
        for (_, data) in &blocks {
            if let Ok(val) = serde_json::from_slice::<serde_json::Value>(data) {
                if val.get("kind").and_then(|v| v.as_str()) == Some("tag_update") {
                    let node_id = val.get("node_id").and_then(|v| v.as_str()).unwrap_or("");
                    let add: Vec<(String, String)> = val.get("add")
                        .and_then(|v| serde_json::from_value(v.clone()).ok())
                        .unwrap_or_default();
                    let remove: Vec<(String, String)> = val.get("remove")
                        .and_then(|v| serde_json::from_value(v.clone()).ok())
                        .unwrap_or_default();
                    if !node_id.is_empty() {
                        let mut idx = self.index.write().await;
                        idx.apply_tag_update(node_id, &add, &remove);
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
    /// Store a tag update block in the blockstore, tagged with `tag_update:<node_id>`.
    fn store_tag_update(
        &self,
        node_id: &str,
        add: &[(String, String)],
        remove: &[(String, String)],
    ) -> Result<()> {
        let update = serde_json::json!({
            "kind": "tag_update",
            "node_id": node_id,
            "add": add,
            "remove": remove,
            "wall_ns": memvault_core::wall_ns(),
        });
        let update_bytes = serde_json::to_vec(&update)
            .map_err(|e| ApiError::Serialization(e.to_string()))?;
        let cid = cid_from_bytes(&update_bytes);
        let meta = EnvelopeMeta {
            author: self.peer_id.clone(),
            tags: vec![("tag_update".to_string(), node_id.to_string())],
            wall_ns: memvault_core::wall_ns(),
            causal: vec![],
            provenance: vec![],
            cluster_id: Some(self.cluster_id.clone()),
        };
        self.store.insert_envelope(&cid.to_bytes(), &update_bytes, &meta)?;
        Ok(())
    }

    /// Load cached extracted text by looking for a ManifestUpdate tagged with this manifest CID.
    fn load_cached_extracted_text(&self, manifest_cid: &[u8]) -> Option<String> {
        // Look for ManifestUpdate blocks tagged with this manifest.
        let label = hex::encode(manifest_cid);
        let update_cids = self.store.query_by_tag("manifest_update", &label, 0, 1).ok()?;
        for cid in &update_cids {
            let data = self.store.get_block(cid).ok()??;
            let update: serde_json::Value = serde_json::from_slice(&data).ok()?;
            if let Some(et_cid) = update.get("extracted_text")
                .and_then(|v| serde_json::from_value::<Vec<u8>>(v.clone()).ok())
            {
                let et_bytes = self.store.get_block(&et_cid).ok()??;
                let et: serde_json::Value = serde_json::from_slice(&et_bytes).ok()?;
                return et.get("text").and_then(|v| v.as_str()).map(String::from);
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

    fn store_op(&self, op: &Op, tags: &[(String, String)], vis: &Visibility) -> Result<Vec<u8>> {
        let op_bytes = serde_json::to_vec(op)
            .map_err(|e| ApiError::Serialization(e.to_string()))?;
        let cid = cid_from_bytes(&op_bytes);
        let cid_bytes = cid.to_bytes();

        let meta = EnvelopeMeta {
            author: self.peer_id.clone(),
            tags: tags.to_vec(),
            wall_ns: memvault_core::wall_ns(),
            causal: vec![],
            provenance: vec![],
            cluster_id: Some(self.cluster_id.clone()),
        };

        // Wrap op in a pseudo-envelope JSON for audit purposes
        let envelope = serde_json::json!({
            "version": 1,
            "payload": op,
            "author": self.peer_id,
            "tags": tags,
            "visibility": vis,
            "wall_ns": meta.wall_ns,
        });
        let envelope_bytes = serde_json::to_vec(&envelope)
            .map_err(|e| ApiError::Serialization(e.to_string()))?;

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
    ) -> Result<Vec<u8>> {
        let op = Op::DocCreate {
            doc_id: doc.id.clone(),
            initial_body: doc.body.clone(),
            frontmatter: doc.frontmatter.clone(),
        };

        let mut all_tags = tags.clone();
        all_tags.push(Self::doc_tag(&doc.id));

        let cid_bytes = self.store_op(&op, &all_tags, &vis)?;

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
        let cid_bytes = self.store_op(&op, &tags, &Visibility::Internal)?;

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
    ) -> Result<Vec<DocSummary>> {
        let cids = if let Some((ref scope, ref label)) = tag_filter {
            self.store.query_by_tag(scope, label, 0, limit)?
        } else {
            self.store.query_by_time(0, u64::MAX, limit)?
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

    async fn attach_file(
        &self,
        data: &[u8],
        filename: Option<&str>,
        mime_type: &str,
        tags: Vec<(String, String)>,
        visibility: &str,
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
        let meta = EnvelopeMeta {
            author: self.peer_id.clone(),
            tags: tags.clone(),
            wall_ns: memvault_core::wall_ns(),
            causal: vec![],
            provenance: vec![],
            cluster_id: Some(self.cluster_id.clone()),
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

        // Try to extract text (best-effort). Store as a separate ExtractedText block
        // and link to it via a ManifestUpdate block (can't mutate the manifest — it's
        // content-addressed). Tag the update so we can find it by manifest CID.
        let extracted_text = safe_extract_text(data, mime_type);
        if let Some(ref text) = extracted_text {
            let et = memvault_extract::ExtractedText {
                source: manifest_cid_bytes.clone(),
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

                // Store a ManifestUpdate linking the manifest to the extracted text.
                let update = memvault_attach::ManifestUpdate {
                    target_manifest: manifest_cid_bytes.clone(),
                    extracted_text: Some(et_cid.to_bytes()),
                    pii_findings: None,
                    derived_from: None,
                    updated_at_ns: memvault_core::wall_ns(),
                };
                if let Ok(upd_bytes) = serde_json::to_vec(&update) {
                    let upd_cid = cid_from_bytes(&upd_bytes);
                    let _ = self.store.put_block(&upd_cid.to_bytes(), &upd_bytes);
                    // Tag it so we can find updates by manifest CID.
                    let upd_meta = EnvelopeMeta {
                        author: self.peer_id.clone(),
                        tags: vec![
                            ("manifest_update".to_string(), hex::encode(&manifest_cid_bytes)),
                        ],
                        wall_ns: memvault_core::wall_ns(),
                        causal: vec![],
                        provenance: vec![],
                        cluster_id: Some(self.cluster_id.clone()),
                    };
                    let _ = self.store.insert_envelope(&upd_cid.to_bytes(), &upd_bytes, &upd_meta);
                }
            }
        }

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

    async fn read_attachment(&self, manifest_cid: &[u8]) -> Result<Vec<u8>> {
        // Load manifest
        let manifest_data = self
            .store
            .get_block(manifest_cid)?
            .ok_or_else(|| ApiError::NotFound("attachment manifest not found".into()))?;

        let manifest: AttachmentManifest = serde_json::from_slice(&manifest_data)
            .map_err(|e| ApiError::Serialization(e.to_string()))?;

        // Read full content via UnixFS
        let data = memvault_attach::read_range::read_full(&self.store, &manifest.content_root)?;
        Ok(data)
    }

    async fn read_attachment_range(&self, manifest_cid: &[u8], start: u64, end: u64) -> Result<Vec<u8>> {
        let manifest_data = self
            .store
            .get_block(manifest_cid)?
            .ok_or_else(|| ApiError::NotFound("attachment manifest not found".into()))?;

        let manifest: AttachmentManifest = serde_json::from_slice(&manifest_data)
            .map_err(|e| ApiError::Serialization(e.to_string()))?;

        let data = memvault_attach::read_range::read_range(&self.store, &manifest.content_root, start, end)?;
        Ok(data)
    }

    async fn read_extracted_text(&self, manifest_cid: &[u8]) -> Result<Option<String>> {
        // Try cached extracted text first.
        if let Some(text) = self.load_cached_extracted_text(manifest_cid) {
            return Ok(Some(text));
        }

        // No cache — extract from raw content (with panic protection).
        let manifest_data = self
            .store
            .get_block(manifest_cid)?
            .ok_or_else(|| ApiError::NotFound("attachment manifest not found".into()))?;

        let manifest: AttachmentManifest = serde_json::from_slice(&manifest_data)
            .map_err(|e| ApiError::Serialization(e.to_string()))?;

        let content = memvault_attach::read_range::read_full(&self.store, &manifest.content_root)?;
        Ok(safe_extract_text(&content, &manifest.mime_type))
    }

    async fn pin_attachment(&self, manifest_cid: &[u8]) -> Result<()> {
        memvault_attach::pin::pin(&self.store, manifest_cid, memvault_attach::PinReason::Manual)?;
        Ok(())
    }

    async fn unpin_attachment(&self, manifest_cid: &[u8]) -> Result<()> {
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

    async fn get_attachment_manifest(&self, manifest_cid: &[u8]) -> Result<Option<Vec<u8>>> {
        let data = self.store.get_block(manifest_cid)?;
        Ok(data)
    }

    async fn add_entity(&self, entity: Entity, vis: Visibility) -> Result<EntityId> {
        let entity_id = entity.id.clone();
        let op = Op::EntityCreate {
            entity: entity.clone(),
        };

        let entity_label: String = entity_id.0.iter().map(|b| format!("{b:02x}")).collect();
        let tags = vec![("entity".to_string(), entity_label)];
        self.store_op(&op, &tags, &vis)?;

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

    async fn list_entities(&self, limit: usize) -> Result<Vec<Entity>> {
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
        self.store_op(&op, &tags, &vis)?;

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
        self.store_op(&op, &tags, &Visibility::Internal)?;
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

    async fn issue_token(
        &self,
        role: Role,
        ttl_secs: u64,
        max_uses: u32,
        label: Option<String>,
    ) -> Result<String> {
        crate::tokens::issue_token_placeholder(role, ttl_secs, max_uses, label)
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
        Ok(())
    }

    async fn remove_tags(&self, node_id: &str, tags: Vec<(String, String)>) -> Result<()> {
        self.store_tag_update(node_id, &[], &tags)?;
        let mut idx = self.index.write().await;
        idx.apply_tag_update(node_id, &[], &tags);
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
            let cids = self.store.query_by_tag("view", label, 0, 1)
                .map_err(|e| ApiError::Serialization(e.to_string()))?;
            for cid in &cids {
                if let Some(data) = self.store.get_block(cid)? {
                    if let Ok(view) = serde_json::from_slice::<crate::types::View>(&data) {
                        views.push(view);
                    }
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
        let meta = EnvelopeMeta {
            author: self.peer_id.clone(),
            tags: vec![("view".to_string(), view.name.clone())],
            wall_ns: view.created_ns,
            causal: vec![],
            provenance: vec![],
            cluster_id: Some(self.cluster_id.clone()),
        };
        self.store.insert_envelope(&cid_bytes, &view_bytes, &meta)?;
        Ok(())
    }

    async fn delete_view(&self, name: &str) -> Result<()> {
        let cids = self.store.query_by_tag("view", name, 0, usize::MAX)
            .map_err(|e| ApiError::Serialization(e.to_string()))?;
        for cid in &cids {
            self.retract(cid, "view deleted").await?;
        }
        Ok(())
    }

    async fn update_view(&self, view: crate::types::View) -> Result<()> {
        // Delete old version, then create new.
        self.delete_view(&view.name).await?;
        self.create_view(view).await
    }

    async fn get_view(&self, name: &str) -> Result<Option<crate::types::View>> {
        let cids = self.store.query_by_tag("view", name, 0, 1)
            .map_err(|e| ApiError::Serialization(e.to_string()))?;
        for cid in &cids {
            if let Some(data) = self.store.get_block(cid)? {
                if let Ok(view) = serde_json::from_slice::<crate::types::View>(&data) {
                    return Ok(Some(view));
                }
            }
        }
        Ok(None)
    }

    async fn status(&self) -> Result<NodeStatus> {
        Ok(NodeStatus {
            peer_id: self.peer_id.clone(),
            cluster_id: self.cluster_id.clone(),
            block_count: 0, // Would need a count method on store
            doc_count: 0,
            peer_count: 1,
            uptime_secs: self.start_time.elapsed().as_secs(),
        })
    }
}

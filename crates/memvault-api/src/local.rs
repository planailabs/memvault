//! LocalClient — implements MemvaultClient directly against the store.

use std::collections::VecDeque;
use std::sync::Arc;

use async_trait::async_trait;
use tokio::sync::RwLock;

use memvault_core::{cid_from_bytes, DocId, EdgeId, EntityId, Visibility};
use memvault_doc::{
    Document, Edge, Entity, Op, TextPatch,
};
use memvault_attach::{self, AttachmentManifest};
use memvault_extract::{ExtractionHints, ExtractionRegistry};
use memvault_query::{
    query_audit, AuditQuery, AuditRecord, QuotaManager, SearchHit, TextIndex,
};
use memvault_auth::Role;
use memvault_store::{EnvelopeMeta, MemvaultStore};

use crate::client::MemvaultClient;
use crate::error::{ApiError, Result};
use crate::subscription::{EventBus, MemvaultEvent};
use crate::types::{DocSummary, NodeStatus, RotationInfo, TokenStatus, TraversalHit};

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
        // Load manifest to get content
        let manifest_data = self
            .store
            .get_block(manifest_cid)?
            .ok_or_else(|| ApiError::NotFound("attachment manifest not found".into()))?;

        let manifest: AttachmentManifest = serde_json::from_slice(&manifest_data)
            .map_err(|e| ApiError::Serialization(e.to_string()))?;

        // Check if extraction is supported for this MIME type
        let registry = ExtractionRegistry::with_defaults();
        if !registry.can_extract(&manifest.mime_type) {
            return Ok(None);
        }

        // Read the content
        let content = memvault_attach::read_range::read_full(&self.store, &manifest.content_root)?;

        // Run extraction
        match registry.extract(&content, &manifest.mime_type, &ExtractionHints::default()) {
            Ok(extracted) => Ok(Some(extracted.text)),
            Err(_) => Ok(None),
        }
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

        let entities = memvault_doc::apply_graph_ops(&ops)?;
        Ok(entities.get(id).cloned())
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

    async fn add_edge(&self, source: &EntityId, edge: Edge, vis: Visibility) -> Result<EdgeId> {
        let edge_id = edge.id.clone();
        let op = Op::EdgeAdd {
            source: source.clone(),
            edge,
        };

        let entity_label: String = source.0.iter().map(|b| format!("{b:02x}")).collect();
        let tags = vec![("entity".to_string(), entity_label)];
        self.store_op(&op, &tags, &vis)?;

        Ok(edge_id)
    }

    async fn remove_edge(&self, source: &EntityId, edge_id: &EdgeId) -> Result<()> {
        let op = Op::EdgeRemove {
            source: source.clone(),
            edge_id: edge_id.clone(),
        };

        let entity_label: String = source.0.iter().map(|b| format!("{b:02x}")).collect();
        let tags = vec![("entity".to_string(), entity_label)];
        self.store_op(&op, &tags, &Visibility::Internal)?;
        Ok(())
    }

    async fn traverse(
        &self,
        from: &EntityId,
        relation: Option<&str>,
        max_depth: usize,
    ) -> Result<Vec<TraversalHit>> {
        let mut results = Vec::new();
        let mut visited: std::collections::HashSet<EntityId> = std::collections::HashSet::new();
        let mut queue: VecDeque<(EntityId, usize, Vec<(EdgeId, String)>)> = VecDeque::new();

        visited.insert(from.clone());
        queue.push_back((from.clone(), 0, Vec::new()));

        while let Some((current_id, depth, path)) = queue.pop_front() {
            if depth > 0 {
                results.push(TraversalHit {
                    entity_id: current_id.clone(),
                    depth,
                    path: path.clone(),
                });
            }

            if depth >= max_depth {
                continue;
            }

            // Get entity to find edges
            if let Some(entity) = self.get_entity(&current_id).await? {
                for edge in &entity.edges_out {
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
        }

        Ok(results)
    }

    async fn search(&self, query: &str, limit: usize) -> Result<Vec<SearchHit>> {
        let idx = self.index.read().await;
        Ok(idx.search(query, limit))
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

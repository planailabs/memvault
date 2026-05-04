//! The MemvaultClient trait — the full API surface.

use async_trait::async_trait;
use memvault_core::{DocId, EdgeId, EntityId, NodeRef, Visibility};
use memvault_doc::{Document, Edge, Entity, TextPatch};
use memvault_query::{AuditQuery, AuditRecord, SearchHit};
use memvault_auth::Role;

use crate::error::Result;
use crate::types::{DocSummary, NodeStatus, RotationInfo, TokenStatus, TraversalHit};

/// The complete memvault API surface.
#[async_trait]
pub trait MemvaultClient: Send + Sync {
    // -- Documents --
    async fn put_doc(&self, doc: Document, tags: Vec<(String, String)>, vis: Visibility) -> Result<Vec<u8>>;
    async fn get_doc(&self, id: &DocId) -> Result<Option<Document>>;
    async fn edit_doc(&self, id: &DocId, patch: TextPatch) -> Result<Vec<u8>>;
    async fn list_docs(&self, tag_filter: Option<(String, String)>, limit: usize) -> Result<Vec<DocSummary>>;

    // -- Attachments (new system) --
    async fn attach_file(&self, data: &[u8], filename: Option<&str>, mime_type: &str,
                         tags: Vec<(String, String)>, visibility: &str) -> Result<Vec<u8>>;
    async fn read_attachment(&self, manifest_cid: &[u8]) -> Result<Vec<u8>>;
    async fn read_attachment_range(&self, manifest_cid: &[u8], start: u64, end: u64) -> Result<Vec<u8>>;
    async fn read_extracted_text(&self, manifest_cid: &[u8]) -> Result<Option<String>>;
    async fn pin_attachment(&self, manifest_cid: &[u8]) -> Result<()>;
    async fn unpin_attachment(&self, manifest_cid: &[u8]) -> Result<()>;
    async fn list_pinned(&self) -> Result<Vec<(Vec<u8>, String)>>;  // (cid, reason)
    async fn get_attachment_manifest(&self, manifest_cid: &[u8]) -> Result<Option<Vec<u8>>>;  // returns JSON

    // -- Graph --
    async fn add_entity(&self, entity: Entity, vis: Visibility) -> Result<EntityId>;
    async fn get_entity(&self, id: &EntityId) -> Result<Option<Entity>>;
    async fn list_entities(&self, limit: usize) -> Result<Vec<Entity>>;
    async fn entity_history(&self, id: &EntityId) -> Result<Vec<AuditRecord>>;

    // -- Links (cross-type edges) --
    /// Create a directed edge from any node to any node.
    async fn add_link(&self, source: &NodeRef, edge: Edge, vis: Visibility) -> Result<EdgeId>;
    /// Remove an edge by source and edge ID.
    async fn remove_link_from(&self, source: &NodeRef, edge_id: &EdgeId) -> Result<()>;
    /// List all edges (incoming + outgoing) touching a node.
    async fn edges_of(&self, node: &NodeRef) -> Result<Vec<(NodeRef, Edge)>>;
    /// Traverse the graph from any node, following edges across types.
    async fn traverse_from(&self, from: &NodeRef, relation: Option<&str>, max_depth: usize) -> Result<Vec<TraversalHit>>;


    // -- Views (saved tag filter sets) --
    async fn list_views(&self) -> Result<Vec<crate::types::View>>;
    async fn create_view(&self, view: crate::types::View) -> Result<()>;
    async fn delete_view(&self, name: &str) -> Result<()>;
    async fn get_view(&self, name: &str) -> Result<Option<crate::types::View>>;

    // -- Search --
    async fn search(&self, query: &str, limit: usize) -> Result<Vec<SearchHit>>;
    /// Unified search across all node types (docs, entities, attachments).
    async fn search_unified(&self, query: &str, limit: usize) -> Result<Vec<memvault_query::UnifiedHit>>;
    /// Resolve a node_id (tag_label like "entity:<hex>") to a human-readable label.
    async fn resolve_label(&self, node_id: &str) -> Result<Option<String>>;

    // -- History & Audit --
    async fn history_of(&self, doc_id: &DocId) -> Result<Vec<AuditRecord>>;
    async fn audit(&self, query: AuditQuery) -> Result<Vec<AuditRecord>>;
    async fn retract(&self, target_cid: &[u8], reason: &str) -> Result<Vec<u8>>;

    // -- Tokens --
    async fn issue_token(&self, role: Role, ttl_secs: u64, max_uses: u32, label: Option<String>) -> Result<String>;
    async fn list_tokens(&self) -> Result<Vec<TokenStatus>>;
    async fn revoke_token(&self, token_cid: &[u8], reason: &str) -> Result<()>;

    // -- Rotation --
    async fn list_rotations(&self) -> Result<Vec<RotationInfo>>;

    // -- Status --
    async fn status(&self) -> Result<NodeStatus>;
}

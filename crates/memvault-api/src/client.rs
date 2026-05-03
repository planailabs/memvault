//! The MemvaultClient trait — the full API surface.

use async_trait::async_trait;
use memvault_core::{DocId, EdgeId, EntityId, Visibility};
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
    async fn add_edge(&self, source: &EntityId, edge: Edge, vis: Visibility) -> Result<EdgeId>;
    async fn remove_edge(&self, source: &EntityId, edge_id: &EdgeId) -> Result<()>;
    async fn traverse(&self, from: &EntityId, relation: Option<&str>, max_depth: usize) -> Result<Vec<TraversalHit>>;

    // -- Search --
    async fn search(&self, query: &str, limit: usize) -> Result<Vec<SearchHit>>;

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

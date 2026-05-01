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

    // -- Attachments --
    async fn attach_file(&self, doc_id: &DocId, name: &str, content_type: &str, data: &[u8]) -> Result<Vec<u8>>;
    async fn detach_file(&self, doc_id: &DocId, name: &str) -> Result<()>;
    async fn get_attachment(&self, cid: &[u8]) -> Result<Vec<u8>>;

    // -- Graph --
    async fn add_entity(&self, entity: Entity, vis: Visibility) -> Result<EntityId>;
    async fn get_entity(&self, id: &EntityId) -> Result<Option<Entity>>;
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

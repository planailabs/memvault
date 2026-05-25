//! The MemvaultClient trait — the full API surface.

use async_trait::async_trait;
use memvault_core::{BucketId, ClusterId, DocId, EdgeId, EntityId, NodeRef, Visibility};
use memvault_core::classification::Classification;
use memvault_doc::{Document, Edge, Entity, TextPatch};
use memvault_query::{AuditQuery, AuditRecord, SearchHit};
use memvault_auth::Role;

use crate::error::Result;
use crate::types::{BucketInfo, DocSummary, NodeStatus, RotationInfo, TokenStatus, TraversalHit};

/// The complete memvault API surface.
#[async_trait]
pub trait MemvaultClient: Send + Sync {
    // -- Documents --
    async fn put_doc(&self, doc: Document, tags: Vec<(String, String)>, vis: Visibility) -> Result<Vec<u8>>;
    async fn get_doc(&self, id: &DocId) -> Result<Option<Document>>;
    async fn edit_doc(&self, id: &DocId, patch: TextPatch) -> Result<Vec<u8>>;
    async fn list_docs(&self, tag_filter: Option<(String, String)>, limit: usize) -> Result<Vec<DocSummary>>;

    // -- Files --
    async fn upload_file(&self, data: &[u8], filename: Option<&str>, mime_type: &str,
                         tags: Vec<(String, String)>, visibility: &str) -> Result<Vec<u8>>;
    async fn read_file(&self, manifest_cid: &[u8]) -> Result<Vec<u8>>;
    async fn read_file_range(&self, manifest_cid: &[u8], start: u64, end: u64) -> Result<Vec<u8>>;
    async fn read_extracted_text(&self, manifest_cid: &[u8]) -> Result<Option<String>>;
    async fn pin_file(&self, manifest_cid: &[u8]) -> Result<()>;
    async fn unpin_file(&self, manifest_cid: &[u8]) -> Result<()>;
    async fn list_pinned(&self) -> Result<Vec<(Vec<u8>, String)>>;  // (cid, reason)
    async fn get_file_manifest(&self, manifest_cid: &[u8]) -> Result<Option<Vec<u8>>>;  // returns JSON

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
    async fn search_unified(&self, query: &str, limit: usize) -> Result<Vec<memvault_query::UnifiedHit>>;
    /// List all nodes, optionally filtered by a view name. Returns (node_id, node_type, label, tags).
    async fn list_all(&self, view_name: Option<&str>, limit: usize) -> Result<Vec<(String, String, String, Vec<(String, String)>)>>;
    /// Return node_ids of all items matching a view's required tags.
    async fn view_members(&self, view_name: &str) -> Result<Vec<String>>;
    /// Resolve a node_id (tag_label like "entity:<hex>") to a human-readable label.
    async fn resolve_label(&self, node_id: &str) -> Result<Option<String>>;

    // -- History & Audit --
    async fn history_of(&self, doc_id: &DocId) -> Result<Vec<AuditRecord>>;
    async fn audit(&self, query: AuditQuery) -> Result<Vec<AuditRecord>>;
    async fn retract(&self, target_cid: &[u8], reason: &str) -> Result<Vec<u8>>;
    /// Retract a node by its tag_label (e.g. "entity:<hex>", "doc:<hex>", "file:<hex>").
    /// Removes it from the search index and marks it as retracted.
    async fn retract_node(&self, node_id: &str, reason: &str) -> Result<()>;

    // -- Tokens --
    async fn issue_token(&self, role: Role, ttl_secs: u64, max_uses: u32, label: Option<String>) -> Result<String>;
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
    ) -> Result<BucketId>;

    /// List all buckets in the store.
    async fn bucket_list(&self) -> Result<Vec<BucketInfo>>;

    /// Get a single bucket's info by ID.
    async fn bucket_get(&self, id: &BucketId) -> Result<Option<BucketInfo>>;

    /// Rename a bucket (writes a BucketRename op, LWW by lamport).
    async fn bucket_rename(&self, id: &BucketId, new_name: &str) -> Result<()>;

    /// Bind a bucket to a cluster. If `is_default`, set it as the cluster's default.
    async fn bucket_bind(&self, bucket_id: &BucketId, cluster_id: &ClusterId, is_default: bool) -> Result<()>;

    /// Attach a private bucket to the cluster (flips private_to_peer to None, triggers gossip).
    async fn bucket_attach(&self, id: &BucketId) -> Result<()>;

    /// Archive a bucket (soft-remove: new writes are refused, reads continue, data preserved).
    async fn bucket_archive(&self, id: &BucketId, reason: &str) -> Result<()>;

    // -- Sharing --

    /// List share proposals received by this cluster.
    async fn share_inbox(&self) -> Result<Vec<Vec<u8>>>;

    /// List share proposals sent by this cluster.
    async fn share_outbox(&self) -> Result<Vec<Vec<u8>>>;

    /// Decide a share proposal (approve or reject).
    async fn share_decide(&self, proposal_cid: &[u8], approve: bool, reason: Option<&str>) -> Result<()>;

    // -- Status --
    async fn status(&self) -> Result<NodeStatus>;
}

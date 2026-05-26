use redb::TableDefinition;

/// Primary block storage: CID bytes -> raw block bytes.
pub const BLOCKS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("blocks");

/// Index by tag: packed(scope, label, wall_ns, cid) -> ().
pub const BY_TAG: TableDefinition<&[u8], &[u8]> = TableDefinition::new("by_tag");

/// Index by author: packed(peer_id, wall_ns, cid) -> ().
pub const BY_AUTHOR: TableDefinition<&[u8], &[u8]> = TableDefinition::new("by_author");

/// Index by time: packed(wall_ns, cid) -> ().
pub const BY_TIME: TableDefinition<&[u8], &[u8]> = TableDefinition::new("by_time");

/// Causal links: packed(parent_cid, child_cid) -> ().
pub const BY_CAUSAL: TableDefinition<&[u8], &[u8]> = TableDefinition::new("by_causal");

/// Provenance links: packed(parent_cid, child_cid) -> ().
pub const BY_PROVENANCE: TableDefinition<&[u8], &[u8]> = TableDefinition::new("by_provenance");

/// Edges: packed(edge_kind, source, target, wall_ns) -> cid.
pub const EDGES: TableDefinition<&[u8], &[u8]> = TableDefinition::new("edges");

/// Heads: packed(doc_id, peer_id) -> head_cid.
pub const HEADS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("heads");

/// Revocations: target_cid -> revocation_block_bytes.
pub const REVOCATIONS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("revocations");

/// Retracted: retracted_cid -> tombstone_cid.
pub const RETRACTED: TableDefinition<&[u8], &[u8]> = TableDefinition::new("retracted");

/// Cluster origin: packed(cluster_id, wall_ns, cid) -> ().
pub const CLUSTER_ORIGIN: TableDefinition<&[u8], &[u8]> = TableDefinition::new("cluster_origin");

/// Consumed tokens: token_cid -> packed(count_u32, last_consumer_peer_id, last_consumed_at_ns).
pub const CONSUMED_TOKENS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("consumed_tokens");

/// Rotations: packed(rotation_id, wall_ns) -> rotation_block_cid.
pub const ROTATIONS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("rotations");

// ── Bucket tables (added B1) ───────────────────────────────────────────

/// Index by bucket: packed(bucket_id, wall_ns, cid) -> ().
pub const BY_BUCKET: TableDefinition<&[u8], &[u8]> = TableDefinition::new("by_bucket");

/// Bucket metadata: bucket_id -> bucket_decl_cid (most-recent BucketDecl op CID).
pub const BUCKETS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("buckets");

/// Bucket → cluster binding: bucket_id -> cluster_id.
/// A bucket with no entry here is unbound (pre-genesis or standalone).
pub const BUCKET_CLUSTER: TableDefinition<&[u8], &[u8]> = TableDefinition::new("bucket_cluster");

/// Cluster → default bucket: cluster_id -> bucket_id.
pub const CLUSTER_DEFAULT_BUCKET: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("cluster_default_bucket");

// ── Share tables (added B5) ────────────────────────────────────────

/// Share inbox: packed(to_cluster, wall_ns, proposal_cid) -> status_byte.
pub const SHARE_INBOX: TableDefinition<&[u8], &[u8]> = TableDefinition::new("share_inbox");

/// Share outbox: packed(from_cluster, wall_ns, proposal_cid) -> status_byte.
pub const SHARE_OUTBOX: TableDefinition<&[u8], &[u8]> = TableDefinition::new("share_outbox");

/// Cross-cluster bucket trust: packed(bucket_id, from_cluster, to_cluster) -> trust_cid.
pub const BUCKET_TRUST: TableDefinition<&[u8], &[u8]> = TableDefinition::new("bucket_trust");

// ── Identity tables ────────────────────────────────────────────────

/// Local node identity: fixed key "peer_id" -> peer_id bytes.
/// Written at genesis or first daemon start; verified against the swarm's PeerId.
pub const LOCAL_IDENTITY: TableDefinition<&str, &[u8]> = TableDefinition::new("local_identity");

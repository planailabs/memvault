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

// ── Scoped-index member-sets (Phase 2 of scoped-indexes) ───────────

/// Materialized scope membership: key = scope_id ‖ node_id_bytes,
/// value = packed(retracted_byte:1, wall_ns:8).
///
/// `scope_id` is an opaque, fixed-width digest derived by the caller from a
/// partition coordinate — per-bucket (`b`), per-view (`v`), or per-view×bucket
/// (`vb`). Keying by `(scope_id, node_id)` makes membership insert / remove /
/// retraction-flip O(1); ordering is applied at read time (the multi-bucket
/// merge sorts by `wall_ns` regardless), and counts come from SCOPE_REGISTRY.
pub const SCOPE_MEMBERS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("scope_members");

/// Scope partition registry: key = scope_id, value = packed registry entry
/// (kind, active_count, retracted_count, built_ns, view_cid?, bucket_id?).
/// Lets us enumerate live partitions (for ingest-time maintenance), answer
/// counts in O(1), and know which view×bucket partitions have been lazily
/// built already.
pub const SCOPE_REGISTRY: TableDefinition<&[u8], &[u8]> = TableDefinition::new("scope_registry");

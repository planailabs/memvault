//! memctl CLI — can be invoked as a standalone binary or as a daemon subcommand.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::Result;
use clap::{Parser, Subcommand};
use tokio::sync::RwLock;

use crate::{EventBus, LocalClient, MemvaultClient};
use memvault_core::{ClusterId, DocId, EntityId, Visibility};
use memvault_doc::{Edge, Entity};
use memvault_query::{QuotaManager, TextIndex};
use memvault_auth::Role;
use memvault_store::MemvaultStore;

#[derive(Parser, Debug)]
#[command(name = "memctl", about = "Memvault management CLI")]
pub struct Cli {
    /// Data directory
    #[arg(long, env = "MEMVAULT_DATA_DIR")]
    pub data_dir: Option<PathBuf>,

    /// Path to the redb database file directly (alternative to --data-dir)
    #[arg(long, env = "MEMVAULT_DB")]
    pub db: Option<PathBuf>,

    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Initialize a new memvault cluster
    Genesis {
        /// Path to admin key file (Ed25519 public key)
        #[arg(long)]
        admin_key: Option<PathBuf>,
    },
    /// Store a memory
    Put {
        /// Memory text (reads from stdin if not provided)
        text: Option<String>,
        /// Tags (scope:label format)
        #[arg(short, long)]
        tag: Vec<String>,
        /// Visibility (internal, federated, public)
        #[arg(short, long, default_value = "internal")]
        visibility: String,
        /// Title
        #[arg(long)]
        title: Option<String>,
    },
    /// Retrieve a memory by CID
    Get {
        /// Hex-encoded CID
        cid: String,
    },
    /// Search memories
    Search {
        /// Search query
        query: String,
        /// Maximum results
        #[arg(short, long, default_value = "10")]
        limit: usize,
    },
    /// List recent memories
    List {
        /// Maximum results
        #[arg(short, long, default_value = "20")]
        limit: usize,
        /// Filter by tag scope
        #[arg(long)]
        scope: Option<String>,
    },
    /// Show audit log
    Audit {
        /// Maximum results
        #[arg(short, long, default_value = "50")]
        limit: usize,
        /// Filter by operation kind
        #[arg(long)]
        kind: Option<String>,
    },
    /// View document history
    History {
        /// Hex-encoded DocId
        doc_id: String,
    },
    /// Retract a memory
    Retract {
        /// Hex-encoded CID to retract
        cid: String,
        /// Reason for retraction
        #[arg(short, long)]
        reason: String,
    },
    /// Issue a join token
    TokenIssue {
        /// Role for the token recipient
        #[arg(long, default_value = "agent-host")]
        role: String,
        /// TTL in seconds
        #[arg(long, default_value = "3600")]
        ttl: u64,
        /// Maximum uses
        #[arg(long, default_value = "1")]
        max_uses: u32,
        /// Human-readable label
        #[arg(long)]
        label: Option<String>,
    },
    /// List tokens
    TokenList,
    /// Revoke a token
    TokenRevoke {
        /// Hex-encoded token CID
        cid: String,
        /// Reason
        #[arg(short, long)]
        reason: String,
    },
    /// List key rotations
    Rotations,
    /// Show node status
    Status,
    /// Add an entity to the knowledge graph
    GraphAdd {
        /// Entity kind
        kind: String,
        /// Properties as key=value pairs
        #[arg(short, long)]
        prop: Vec<String>,
    },
    /// Link two entities
    GraphLink {
        /// Source entity ID (hex)
        source: String,
        /// Target entity ID (hex)
        target: String,
        /// Relation type
        relation: String,
        /// Edge weight
        #[arg(long)]
        weight: Option<f32>,
    },
    /// Traverse the knowledge graph
    GraphQuery {
        /// Starting entity ID (hex)
        from: String,
        /// Relation filter
        #[arg(long)]
        relation: Option<String>,
        /// Maximum depth
        #[arg(long, default_value = "3")]
        max_depth: usize,
    },
    /// Run garbage collection
    Gc {
        /// Document ID (hex)
        #[arg(long)]
        doc: Option<String>,
        /// Remove ops before this timestamp (RFC3339)
        #[arg(long)]
        before: Option<String>,
    },
    /// Show connected peers
    Peers,
    /// Rebuild all indexes from blockstore, repair VFS tree (re-link orphaned directories)
    RepairIndex,
    /// Set cluster_id on envelopes that have null/missing cluster_id
    FixClusterId,
    /// Renew attestation
    RenewAttestation {
        /// Target peer ID (hex)
        peer_id: String,
    },
    /// Import files or folders into memvault, optionally placing them in the VFS
    ImportFiles {
        /// Path to file or folder to import
        path: PathBuf,
        /// VFS folder to place imported files in (e.g. "/documents")
        #[arg(long)]
        vfs: Option<String>,
        /// Tags to apply to all imported files (scope:label format)
        #[arg(short, long)]
        tag: Vec<String>,
        /// Visibility (internal, federated, public)
        #[arg(short, long, default_value = "internal")]
        visibility: String,
    },
    /// Import text/markdown files as documents, optionally placing them in the VFS
    ImportDocs {
        /// Path to file or folder to import (reads .md, .txt, .markdown files)
        path: PathBuf,
        /// VFS folder to place imported docs in (e.g. "/notes")
        #[arg(long)]
        vfs: Option<String>,
        /// Tags to apply to all imported docs (scope:label format)
        #[arg(short, long)]
        tag: Vec<String>,
        /// Visibility (internal, federated, public)
        #[arg(short, long, default_value = "internal")]
        visibility: String,
    },
}

fn default_data_dir() -> PathBuf {
    dirs::data_local_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("memvault")
}

fn open_store_at(db_path: &Path) -> Result<Arc<MemvaultStore>> {
    if let Some(parent) = db_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let store = MemvaultStore::open(db_path)?;
    Ok(Arc::new(store))
}

fn open_store(data_dir: &Path) -> Result<Arc<MemvaultStore>> {
    std::fs::create_dir_all(data_dir)?;
    let db_path = data_dir.join("blocks.redb");
    open_store_at(&db_path)
}

fn create_client(store: Arc<MemvaultStore>) -> LocalClient {
    LocalClient::new(
        store,
        Arc::new(RwLock::new(TextIndex::new())),
        Arc::new(RwLock::new(QuotaManager::new(Default::default()))),
        Arc::new(EventBus::new(64)),
        vec![0u8; 32],
        vec![0u8; 32],
    )
}

fn parse_entity_id(hex_str: &str) -> Result<EntityId> {
    let bytes = hex::decode(hex_str)?;
    let mut id = [0u8; 32];
    let len = bytes.len().min(32);
    id[..len].copy_from_slice(&bytes[..len]);
    Ok(EntityId(id))
}

/// Run the memctl CLI with the given parsed arguments.
pub async fn run(cli: Cli) -> Result<()> {
    let data_dir = cli.data_dir.unwrap_or_else(default_data_dir);
    let db_override = cli.db;

    // Helper: open the store using --db if provided, otherwise data_dir/blocks.redb.
    let make_store = || -> Result<Arc<MemvaultStore>> {
        if let Some(ref db_path) = db_override {
            open_store_at(db_path)
        } else {
            open_store(&data_dir)
        }
    };

    match cli.command {
        Commands::Genesis { admin_key } => {
            std::fs::create_dir_all(&data_dir)?;
            let cluster_id = ClusterId::random();
            let id_hex = hex::encode(cluster_id.0);
            let id_path = data_dir.join("cluster_id");
            std::fs::write(&id_path, id_hex.as_bytes())?;
            std::fs::create_dir_all(data_dir.join("identity"))?;
            std::fs::create_dir_all(data_dir.join("trust"))?;
            println!("Cluster genesis complete.");
            println!("  Cluster ID: {id_hex}");
            println!("  Data dir:   {}", data_dir.display());
            if let Some(key_path) = admin_key {
                println!("  Admin key:  {}", key_path.display());
            }
            println!("\nCluster ID written to {}", id_path.display());
        }
        Commands::Put { text, tag, visibility, title } => {
            let text = match text {
                Some(t) => t,
                None => {
                    use std::io::Read;
                    let mut buf = String::new();
                    std::io::stdin().read_to_string(&mut buf)?;
                    buf
                }
            };
            let store = make_store()?;
            let client = create_client(store);
            let tags = crate::docs::parse_tags(&tag);
            let vis = crate::docs::parse_visibility(Some(&visibility));
            let result = crate::docs::create_doc(&client, &text, title.as_deref(), None, tags, vis, None).await?;
            println!("{}", result.node_id);
        }
        Commands::Get { cid } => {
            let cid_bytes = hex::decode(&cid)?;
            let store = make_store()?;
            if let Some(block) = store.get_block(&cid_bytes)? {
                println!("{}", String::from_utf8_lossy(&block));
            } else {
                eprintln!("Block not found: {cid}");
                std::process::exit(1);
            }
        }
        Commands::Search { query, limit } => {
            let store = make_store()?;
            let client = create_client(store);
            let hits = client.search(&query, limit).await?;
            for hit in hits {
                println!("{} (score: {:.2})", hex::encode(hit.doc_id.0), hit.score);
                println!("  {}", hit.snippet.chars().take(80).collect::<String>());
                println!();
            }
        }
        Commands::List { limit, scope } => {
            let store = make_store()?;
            let client = create_client(store);
            let tag_filter = scope.map(|s| (s, "*".to_string()));
            let docs = client.list_docs(tag_filter, limit).await?;
            for doc in docs {
                let title = doc.title.unwrap_or_else(|| "(untitled)".into());
                println!("{} -- {}", hex::encode(&doc.cid), title);
            }
        }
        Commands::Status => {
            let store = make_store()?;
            let client = create_client(store);
            let status = client.status().await?;
            println!("Memvault Node Status");
            println!("  Blocks:   {}", status.block_count);
            println!("  Docs:     {}", status.doc_count);
            println!("  Peers:    {}", status.peer_count);
            println!("  Uptime:   {}s", status.uptime_secs);
        }
        Commands::Retract { cid, reason } => {
            let cid_bytes = hex::decode(&cid)?;
            let store = make_store()?;
            let client = create_client(store);
            let tombstone = client.retract(&cid_bytes, &reason).await?;
            println!("Retracted. Tombstone: {}", hex::encode(&tombstone));
        }
        Commands::TokenIssue { role, ttl, max_uses, label } => {
            let role = match role.as_str() {
                "admin" => Role::Admin, "auditor" => Role::Auditor, "service" => Role::Service,
                _ => Role::AgentHost,
            };
            let store = make_store()?;
            let client = create_client(store);
            let token_str = client.issue_token(role, ttl, max_uses, label).await?;
            println!("{token_str}");
        }
        Commands::TokenList => {
            let store = make_store()?;
            let client = create_client(store);
            let tokens = client.list_tokens().await?;
            for t in tokens {
                let label = t.label.unwrap_or_else(|| "-".into());
                let status = if t.revoked { "revoked" } else { "active" };
                println!("{} [{}] role={:?} uses={}/{} {}", hex::encode(&t.cid), status, t.role, t.consumed_count, t.max_uses, label);
            }
        }
        Commands::TokenRevoke { cid, reason } => {
            let cid_bytes = hex::decode(&cid)?;
            let store = make_store()?;
            let client = create_client(store);
            client.revoke_token(&cid_bytes, &reason).await?;
            println!("Token revoked.");
        }
        Commands::Rotations => {
            let store = make_store()?;
            let client = create_client(store);
            let rotations = client.list_rotations().await?;
            for r in rotations {
                let status = if r.aborted { "ABORTED" } else { "active" };
                println!("{} [{}] kind={} from_ns={} overlap_until_ns={}", hex::encode(&r.rotation_id), status, r.kind, r.valid_from_ns, r.overlap_until_ns);
            }
        }
        Commands::Audit { limit, kind: _ } => {
            let store = make_store()?;
            let cids = store.query_by_time(0, u64::MAX, limit)?;
            println!("{} audit records found.", cids.len());
            for cid in cids { println!("  {}", hex::encode(&cid)); }
        }
        Commands::History { doc_id } => {
            let doc_id_bytes = hex::decode(&doc_id)?;
            let mut id = [0u8; 32];
            let len = doc_id_bytes.len().min(32);
            id[..len].copy_from_slice(&doc_id_bytes[..len]);
            let did = DocId(id);
            let store = make_store()?;
            let client = create_client(store);
            let records = client.history_of(&did).await?;
            println!("History for doc {doc_id}: {} ops", records.len());
            for r in records { println!("  {} kind={:?}", hex::encode(&r.cid), r.op_kind); }
        }
        Commands::GraphAdd { kind, prop } => {
            let store = make_store()?;
            let client = create_client(store);
            let props: BTreeMap<String, serde_json::Value> = prop.iter()
                .filter_map(|p| { let (k, v) = p.split_once('=')?; Some((k.to_string(), serde_json::Value::String(v.to_string()))) })
                .collect();
            let entity = Entity { id: EntityId::random(), kind, props, edges_out: vec![] };
            let id = client.add_entity(entity, Visibility::Internal).await?;
            println!("{}", hex::encode(id.0));
        }
        Commands::GraphLink { source, target, relation, weight } => {
            let source_id = parse_entity_id(&source)?;
            let target_id = parse_entity_id(&target)?;
            let store = make_store()?;
            let client = create_client(store);
            let source_ref = memvault_core::NodeRef::Entity(source_id);
            let edge = Edge { id: memvault_core::EdgeId::random(), relation, target: memvault_core::NodeRef::Entity(target_id), weight, props: BTreeMap::new(), provenance: None };
            let edge_id = client.add_link(&source_ref, edge, Visibility::Internal).await?;
            println!("{}", hex::encode(edge_id.0));
        }
        Commands::GraphQuery { from, relation, max_depth } => {
            let entity_id = parse_entity_id(&from)?;
            let store = make_store()?;
            let client = create_client(store);
            let from_ref = memvault_core::NodeRef::Entity(entity_id);
            let hits = client.traverse_from(&from_ref, relation.as_deref(), max_depth).await?;
            for hit in hits { println!("depth={} node={}", hit.depth, hit.node); }
        }
        Commands::Gc { doc, before } => {
            println!("GC: doc={doc:?} before={before:?}");
            println!("  (manual GC not yet wired to compaction)");
        }
        Commands::Peers => { println!("Connected peers: 0 (standalone mode)"); }
        Commands::RepairIndex => {
            let store = make_store()?;

            // Phase 0: Validate block CID integrity.
            // Uses verify_cid which parses the multihash from the CID and
            // recomputes the digest with the correct algorithm (Blake3, SHA2-256, etc.).
            println!("Phase 0: Validating block CIDs...");
            let blocks = store.iter_blocks()?;
            let mut cid_ok = 0usize;
            let mut cid_envelope = 0usize;
            let mut cid_mismatch = 0usize;
            let mut cid_unchecked = 0usize;
            for (cid, data) in &blocks {
                // Direct match: CID hash matches the stored block data.
                match memvault_core::verify_cid(cid, data) {
                    Ok(true) => { cid_ok += 1; continue; }
                    Err(_) => { cid_unchecked += 1; continue; }
                    Ok(false) => {}
                }
                // Legacy op envelopes (pre-fix): CID was computed from the
                // payload struct bytes, not the envelope. Can't verify since
                // re-serializing the payload from Value reorders fields.
                // New envelopes: CID = hash(envelope_bytes) — verified above.
                if let Ok(val) = serde_json::from_slice::<serde_json::Value>(data) {
                    if val.get("payload").is_some() {
                        cid_envelope += 1;
                        continue;
                    }
                }
                cid_mismatch += 1;
                eprintln!("  CID mismatch: {}", hex::encode(cid));
            }
            println!("  {cid_ok} verified, {cid_envelope} envelopes (legacy payload CID), {cid_mismatch} mismatched, {cid_unchecked} unchecked");
            if cid_mismatch > 0 {
                eprintln!("  WARNING: {cid_mismatch} block(s) have CID mismatches (data corruption)");
            }

            // Phase 0b: Migrate legacy envelopes from payload-derived CID to
            // envelope-derived CID. This ensures CID = hash(block_bytes) so
            // sync peers can verify blocks.
            if cid_envelope > 0 {
                println!("Phase 0b: Migrating {cid_envelope} legacy envelope CIDs...");
                let blocks = store.iter_blocks()?;
                let mut migrated = 0usize;
                for (old_cid, data) in &blocks {
                    // Skip blocks that already verify.
                    if let Ok(true) = memvault_core::verify_cid(old_cid, data) {
                        continue;
                    }
                    // Only migrate envelopes (blocks with a "payload" field).
                    let is_envelope = serde_json::from_slice::<serde_json::Value>(data)
                        .ok()
                        .and_then(|v| v.get("payload").map(|_| true))
                        .unwrap_or(false);
                    if !is_envelope {
                        continue;
                    }
                    let new_cid = memvault_core::cid_from_bytes(data);
                    let new_cid_bytes = new_cid.to_bytes();
                    if new_cid_bytes == *old_cid {
                        continue; // already correct
                    }
                    store.put_block_unchecked(&new_cid_bytes, data)?;
                    store.delete_block(old_cid)?;
                    migrated += 1;
                }
                println!("  Migrated {migrated} envelope(s) to content-addressed CIDs");
            }

            // Phase 1: Rebuild store secondary indexes (BY_TAG, BY_AUTHOR, BY_TIME, etc.)
            println!("Phase 1: Clearing secondary index tables...");
            store.clear_secondary_indexes()?;

            println!("Phase 1: Scanning blocks and rebuilding store indexes...");
            let blocks = store.iter_blocks()?;
            let total_blocks = blocks.len();
            let mut indexed_envelopes = 0usize;
            for (cid, data) in &blocks {
                if store.reindex_block(cid, data)? {
                    indexed_envelopes += 1;
                }
            }
            println!("  {indexed_envelopes}/{total_blocks} blocks re-indexed into store tables");

            // Phase 2: Rebuild full-text search index
            println!("Phase 2: Rebuilding full-text search index...");
            let client = create_client(store.clone());
            let (doc_count, entity_count, attachment_count) = client.populate_index().await?;
            println!("  {doc_count} docs, {entity_count} entities, {attachment_count} attachments");

            // Save the index cache to disk
            let cache_path = if let Some(ref db_path) = db_override {
                db_path.with_extension("text_index.json")
            } else {
                data_dir.join("text_index.json")
            };
            client.save_index(&cache_path).await?;
            println!("  Index cache saved to {}", cache_path.display());

            // Phase 3: Scan for double-prefixed entity IDs in edge envelopes.
            // A prior bug in the VFS/MCP layer could produce "entity:entity:<hex>"
            // node references. The HTTP API rejects these, so they shouldn't exist
            // in the blockstore, but we validate defensively.
            println!("Phase 3: Scanning for double-prefixed entity IDs...");
            let blocks_scan = store.iter_blocks()?;
            let mut double_prefix_count = 0usize;
            for (_cid, data) in &blocks_scan {
                if let Ok(val) = serde_json::from_slice::<serde_json::Value>(&data) {
                    if let Some(tags) = val.get("tags").and_then(|v| v.as_array()) {
                        for tag in tags {
                            if let Some(arr) = tag.as_array() {
                                if let Some(label) = arr.get(1).and_then(|v| v.as_str()) {
                                    if label.starts_with("entity:entity:") {
                                        double_prefix_count += 1;
                                        eprintln!("  Found double-prefixed tag: {label}");
                                    }
                                }
                            }
                        }
                    }
                }
            }
            if double_prefix_count > 0 {
                eprintln!("  WARNING: {double_prefix_count} envelope(s) have double-prefixed entity IDs");
                eprintln!("  Run Phase 1 rebuild (already done above) to clean secondary indexes");
            } else {
                println!("  No double-prefixed entity IDs found (data clean)");
            }

            // Phase 4: Repair VFS tree — ensure all vfs:dir entities are reachable from the root
            println!("Phase 4: Checking VFS tree integrity...");
            let vfs_repaired = repair_vfs_tree(&client).await?;
            if vfs_repaired > 0 {
                println!("  Linked {vfs_repaired} orphaned directory/ies to VFS root");
                // Re-save index cache (Phase 4 may have retracted entities).
                client.save_index(&cache_path).await?;
                println!("  Index cache re-saved");
            } else {
                println!("  VFS tree OK (no orphans)");
            }

            // Phase 5: Migrate entities tagged vfs_status:pending_repair.
            // After the double-prefix fix, VFS operations work again. Link pending
            // entities at their intended VFS paths and update their status tag.
            println!("Phase 5: Migrating pending VFS entries...");
            let pending_cids = store.query_by_tag("vfs_status", "pending_repair", 0, 10_000)?;
            let mut migrated_vfs = 0usize;
            let mut migration_errors = 0usize;
            for cid in &pending_cids {
                if let Some(data) = store.get_block(cid)? {
                    if let Ok(val) = serde_json::from_slice::<serde_json::Value>(&data) {
                        // Find the entity this envelope belongs to.
                        let entity_tag = val.get("tags").and_then(|v| v.as_array()).and_then(|tags| {
                            tags.iter().find_map(|t| {
                                let arr = t.as_array()?;
                                let scope = arr.first()?.as_str()?;
                                let label = arr.get(1)?.as_str()?;
                                if scope == "entity" { Some(label.to_string()) } else { None }
                            })
                        });
                        let intended_path = val.get("tags").and_then(|v| v.as_array()).and_then(|tags| {
                            tags.iter().find_map(|t| {
                                let arr = t.as_array()?;
                                let scope = arr.first()?.as_str()?;
                                let label = arr.get(1)?.as_str()?;
                                if scope == "vfs_intended_path" { Some(label.to_string()) } else { None }
                            })
                        });
                        if let (Some(entity_hex), Some(path)) = (entity_tag, intended_path) {
                            let node_ref = format!("entity:{entity_hex}");
                            // Ensure parent dirs exist, then link.
                            match crate::vfs::link_node_at_path(&client, &path, &node_ref).await {
                                Ok(_) => {
                                    // Update status tag: pending_repair → linked.
                                    let _ = client.remove_tags(&node_ref, vec![("vfs_status".into(), "pending_repair".into())]).await;
                                    let _ = client.add_tags(&node_ref, vec![("vfs_status".into(), "linked".into())]).await;
                                    println!("  Linked {node_ref} at {path}");
                                    migrated_vfs += 1;
                                }
                                Err(e) => {
                                    eprintln!("  Failed to link {node_ref} at {path}: {e}");
                                    migration_errors += 1;
                                }
                            }
                        }
                    }
                }
            }
            if migrated_vfs > 0 || migration_errors > 0 {
                println!("  {migrated_vfs} migrated, {migration_errors} errors");
                if migrated_vfs > 0 {
                    client.save_index(&cache_path).await?;
                    println!("  Index cache re-saved");
                }
            } else if pending_cids.is_empty() {
                println!("  No pending VFS entries found");
            } else {
                println!("  {} pending entries found but none had vfs_intended_path", pending_cids.len());
            }
            println!("Repair complete.");
        }
        Commands::RenewAttestation { peer_id } => { println!("Attestation renewal for {peer_id}: not yet implemented in standalone mode"); }
        Commands::FixClusterId => {
            // Read current cluster_id from disk.
            let id_path = data_dir.join("cluster_id");
            let id_hex = std::fs::read_to_string(&id_path)
                .map_err(|e| anyhow::anyhow!("Cannot read {}: {e}. Run 'genesis' first.", id_path.display()))?;
            let cluster_bytes = hex::decode(id_hex.trim())
                .map_err(|e| anyhow::anyhow!("Invalid cluster_id hex: {e}"))?;
            println!("Cluster ID: {}", hex::encode(&cluster_bytes));

            let store = make_store()?;
            let blocks = store.iter_blocks()?;
            let mut patched = 0usize;
            let mut skipped = 0usize;

            for (cid, data) in &blocks {
                let val: serde_json::Value = match serde_json::from_slice(data) {
                    Ok(v) => v,
                    Err(_) => { skipped += 1; continue; }
                };

                // Check if this looks like an envelope.
                let is_envelope = val.get("wall_ns").is_some() || val.get("author").is_some();
                if !is_envelope {
                    skipped += 1;
                    continue;
                }

                // Check if cluster_id is null or missing.
                let needs_fix = match val.get("cluster_id") {
                    None => true,
                    Some(serde_json::Value::Null) => true,
                    Some(serde_json::Value::Array(arr)) if arr.is_empty() => true,
                    _ => false,
                };

                if !needs_fix {
                    continue;
                }

                let wall_ns: u64 = val.get("wall_ns").and_then(|v| v.as_u64()).unwrap_or(0);

                // Don't mutate the block — blocks are content-addressed, so
                // changing bytes would break the CID invariant. Instead, just
                // add the missing CLUSTER_ORIGIN index entry.
                store.index_cluster_origin(cid, &cluster_bytes, wall_ns)?;

                patched += 1;
            }

            println!("Indexed {patched} envelopes into CLUSTER_ORIGIN ({skipped} non-envelope blocks skipped).");
        }
        Commands::ImportFiles { path, vfs, tag, visibility } => {
            let store = make_store()?;
            let client = create_client(store.clone());
            // Rebuild index so VFS operations work.
            client.populate_index().await?;

            let tags = crate::docs::parse_tags(&tag);
            let imported = import_files(&client, &path, vfs.as_deref(), &tags, &visibility).await?;
            println!("Imported {imported} file(s).");
        }
        Commands::ImportDocs { path, vfs, tag, visibility } => {
            let store = make_store()?;
            let client = create_client(store.clone());
            client.populate_index().await?;

            let tags = crate::docs::parse_tags(&tag);
            let vis = crate::docs::parse_visibility(Some(&visibility));
            let imported = import_docs(&client, &path, vfs.as_deref(), &tags, vis).await?;
            println!("Imported {imported} document(s).");
        }
    }

    Ok(())
}

/// Import files recursively, optionally placing them in the VFS.
async fn import_files(
    client: &LocalClient,
    path: &Path,
    vfs_folder: Option<&str>,
    tags: &[(String, String)],
    visibility: &str,
) -> Result<usize> {
    let mut files: Vec<PathBuf> = Vec::new();
    if path.is_file() {
        files.push(path.to_path_buf());
    } else if path.is_dir() {
        collect_files_recursive(path, &mut files, None)?;
    } else {
        anyhow::bail!("path does not exist: {}", path.display());
    }
    if files.is_empty() {
        println!("No files found at {}", path.display());
        return Ok(0);
    }

    let base_dir = if path.is_dir() { path } else { path.parent().unwrap_or(Path::new(".")) };
    let mut count = 0usize;

    for file_path in &files {
        let data = std::fs::read(file_path)?;
        let filename = file_path.file_name().and_then(|n| n.to_str()).unwrap_or("unnamed");
        let mime = crate::files::detect_mime(file_path);
        let vfs_path = vfs_folder.map(|f| compute_vfs_path(f, base_dir, file_path, path.is_dir()));
        let (_cid, node_id) = crate::files::upload_file(
            client, &data, Some(filename), mime, tags.to_vec(), visibility, vfs_path.as_deref(),
        ).await?;
        println!("  {} -> {node_id}", file_path.display());
        count += 1;
    }
    Ok(count)
}

/// Import text/markdown files as documents, optionally placing them in the VFS.
async fn import_docs(
    client: &LocalClient,
    path: &Path,
    vfs_folder: Option<&str>,
    tags: &[(String, String)],
    vis: Visibility,
) -> Result<usize> {
    let doc_extensions = &["md", "txt", "markdown", "text", "rst"];
    let mut files: Vec<PathBuf> = Vec::new();
    if path.is_file() {
        files.push(path.to_path_buf());
    } else if path.is_dir() {
        collect_files_recursive(path, &mut files, Some(doc_extensions))?;
    } else {
        anyhow::bail!("path does not exist: {}", path.display());
    }
    if files.is_empty() {
        println!("No document files found at {}", path.display());
        return Ok(0);
    }

    let base_dir = if path.is_dir() { path } else { path.parent().unwrap_or(Path::new(".")) };
    let mut count = 0usize;

    for file_path in &files {
        let body = std::fs::read_to_string(file_path)?;
        let title = file_path.file_stem().and_then(|s| s.to_str()).map(|s| s.to_string());
        let vfs_path = vfs_folder.map(|f| compute_vfs_path(f, base_dir, file_path, path.is_dir()));
        let result = crate::docs::create_doc(
            client, &body, title.as_deref(), None, tags.to_vec(), vis, vfs_path.as_deref(),
        ).await?;
        println!("  {} -> {}", file_path.display(), result.node_id);
        count += 1;
    }
    Ok(count)
}

/// Compute the VFS path for a file being imported.
fn compute_vfs_path(vfs_folder: &str, base_dir: &Path, file_path: &Path, is_dir_import: bool) -> String {
    let folder = vfs_folder.trim_end_matches('/');
    if is_dir_import {
        let rel = file_path.strip_prefix(base_dir).unwrap_or(file_path);
        let rel_str = rel.to_string_lossy();
        format!("{folder}/{rel_str}")
    } else {
        let filename = file_path.file_name().and_then(|n| n.to_str()).unwrap_or("unnamed");
        format!("{folder}/{filename}")
    }
}

/// Collect files recursively, skipping hidden entries.
/// If `extensions` is Some, only includes files with matching extensions.
fn collect_files_recursive(dir: &Path, out: &mut Vec<PathBuf>, extensions: Option<&[&str]>) -> Result<()> {
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        if name.starts_with('.') {
            continue;
        }
        if path.is_file() {
            if let Some(exts) = extensions {
                let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
                if !exts.iter().any(|e| e.eq_ignore_ascii_case(ext)) {
                    continue;
                }
            }
            out.push(path);
        } else if path.is_dir() {
            collect_files_recursive(&path, out, extensions)?;
        }
    }
    Ok(())
}

/// Repair the VFS tree:
/// 1. Find the canonical root (smallest-ID entity with name="/").
/// 2. Retract all duplicate "/" entities after re-parenting their children.
/// 3. Link any remaining orphaned vfs:dir entities to the root.
async fn repair_vfs_tree(client: &LocalClient) -> Result<usize> {
    use memvault_core::{EdgeId, NodeRef};
    use std::collections::HashSet;
    use crate::vfs::{VFS_DIR_KIND, VFS_CHILD_REL};

    // 1. Collect all vfs:dir entities.
    let entities = client.list_entities(10_000).await?;
    let mut all_dirs: Vec<([u8; 32], String)> = Vec::new();
    for e in &entities {
        if e.kind == VFS_DIR_KIND {
            let name = e.props.get("name").and_then(|v| v.as_str()).unwrap_or("").to_string();
            all_dirs.push((e.id.0, name));
        }
    }
    if all_dirs.is_empty() {
        return Ok(0);
    }

    // 2. Pick canonical root — smallest ID among name="/" entities.
    let mut root_candidates: Vec<[u8; 32]> = all_dirs.iter()
        .filter(|(_, name)| name == "/")
        .map(|(id, _)| *id)
        .collect();
    root_candidates.sort();
    let root_bytes = match root_candidates.first() {
        Some(id) => *id,
        None => return Ok(0),
    };
    // Ensure root is tagged.
    let root_node_id = format!("entity:{}", hex::encode(root_bytes));
    let _ = client.add_tags(&root_node_id, vec![("vfs".into(), "root".into())]).await;
    let root_ref = NodeRef::Entity(EntityId(root_bytes));

    let mut actions = 0usize;

    // 3. Retract duplicate "/" entities, re-parenting their children first.
    for &dup_bytes in &root_candidates[1..] {
        let dup_ref = NodeRef::Entity(EntityId(dup_bytes));
        let edges = client.edges_of(&dup_ref).await.unwrap_or_default();
        for (src, edge) in &edges {
            if *src != dup_ref || edge.relation != VFS_CHILD_REL { continue; }
            let child_name = edge.props.get("name").and_then(|v| v.as_str()).unwrap_or("?").to_string();
            // Skip if root already has this child name.
            let root_edges = client.edges_of(&root_ref).await.unwrap_or_default();
            let exists = root_edges.iter().any(|(s, e)| {
                *s == root_ref && e.relation == VFS_CHILD_REL
                    && e.props.get("name").and_then(|v| v.as_str()) == Some(&child_name)
            });
            if exists { continue; }
            let mut props = BTreeMap::new();
            props.insert("name".to_string(), serde_json::Value::String(child_name.clone()));
            let new_edge = Edge {
                id: EdgeId::random(), relation: VFS_CHILD_REL.to_string(),
                target: edge.target.clone(), weight: None, props, provenance: None,
            };
            if client.add_link(&root_ref, new_edge, Visibility::Internal).await.is_ok() {
                println!("  Re-parented \"{child_name}\" from duplicate root");
                actions += 1;
            }
        }
        let dup_node_id = format!("entity:{}", hex::encode(dup_bytes));
        if client.retract_node(&dup_node_id, "duplicate VFS root").await.is_ok() {
            println!("  Retracted duplicate root {}", &dup_node_id);
            actions += 1;
        }
    }

    // 4. Walk tree from canonical root to find all reachable dirs.
    let mut reachable: HashSet<[u8; 32]> = HashSet::new();
    reachable.insert(root_bytes);
    let mut stack: Vec<NodeRef> = vec![root_ref.clone()];
    while let Some(current) = stack.pop() {
        let edges = client.edges_of(&current).await.unwrap_or_default();
        for (src, edge) in &edges {
            if *src != current || edge.relation != VFS_CHILD_REL { continue; }
            if let NodeRef::Entity(child_eid) = &edge.target {
                if reachable.insert(child_eid.0) {
                    stack.push(edge.target.clone());
                }
            }
        }
    }

    // 5. Link genuinely orphaned dirs to root (not duplicates, not already reachable).
    let retracted: HashSet<[u8; 32]> = root_candidates[1..].iter().copied().collect();
    for (id, name) in &all_dirs {
        if reachable.contains(id) || retracted.contains(id) { continue; }
        let entry_name = if name.is_empty() { hex::encode(id)[..8].to_string() } else { name.clone() };
        let mut props = BTreeMap::new();
        props.insert("name".to_string(), serde_json::Value::String(entry_name.clone()));
        let child_ref = NodeRef::Entity(EntityId(*id));
        let edge = Edge {
            id: EdgeId::random(), relation: VFS_CHILD_REL.to_string(),
            target: child_ref, weight: None, props, provenance: None,
        };
        if client.add_link(&root_ref, edge, Visibility::Internal).await.is_ok() {
            println!("  Linked orphan \"{entry_name}\" ({})", hex::encode(id));
            actions += 1;
        }
    }

    Ok(actions)
}

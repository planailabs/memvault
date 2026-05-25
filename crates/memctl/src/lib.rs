//! memctl — Memvault management CLI library.
//!
//! All CLI/daemon logic is native-only. The WASM build only uses main.rs
//! to launch the Dioxus web client.

#[cfg(not(target_arch = "wasm32"))]
mod native {

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::Result;
use clap::{Parser, Subcommand};
use tokio::sync::RwLock;

use memvault_api::{EventBus, LocalClient, MemvaultClient};
use memvault_core::{ClusterId, DocId, EntityId, Visibility};
use memvault_doc::{Edge, Entity};
use memvault_query::{QuotaManager, TextIndex};
use memvault_auth::Role;
use memvault_store::MemvaultStore;

// Re-export for convenience
pub use memvault_api;
pub use memvault_export;
pub use memvault_import;

#[derive(Parser, Debug)]
#[command(name = "memctl", about = "Memvault management CLI")]
pub struct Cli {
    /// Data directory (fallback when --db is not set)
    #[arg(long, env = "MEMVAULT_DATA_DIR")]
    pub data_dir: Option<PathBuf>,

    #[command(flatten)]
    pub client: memvault_api::ClientArgs,

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
        /// Bind an existing bucket as the cluster's default (hex or bs58)
        #[arg(long)]
        default_bucket: Option<String>,
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
    /// Export vault content to a directory or tar archive
    Export {
        /// Output path (directory or .tar/.tar.gz file)
        #[arg(short, long, default_value = "./memvault-export")]
        output: PathBuf,
        /// Force tar output
        #[arg(long)]
        tar: bool,
        /// Compress tar with gzip
        #[arg(long)]
        gzip: bool,
        /// Include historical versions of documents
        #[arg(long)]
        history: bool,
        /// Skip VFS symlink tree
        #[arg(long)]
        no_vfs: bool,
        /// Filter by tag (scope:label format)
        #[arg(long)]
        tag: Option<String>,
        /// Filter by view name
        #[arg(long)]
        view: Option<String>,
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
    /// List share inbox (proposals received)
    ShareInbox,
    /// List share outbox (proposals sent)
    ShareOutbox,
    /// Approve a share proposal
    ShareApprove {
        /// Hex-encoded proposal CID
        cid: String,
    },
    /// Reject a share proposal
    ShareReject {
        /// Hex-encoded proposal CID
        cid: String,
        /// Reason for rejection
        #[arg(short, long)]
        reason: String,
    },
    /// Create a new bucket
    BucketNew {
        /// Bucket name
        name: String,
        /// Description
        #[arg(long)]
        desc: Option<String>,
        /// Visibility (internal, federated, public)
        #[arg(long, default_value = "internal")]
        visibility: String,
        /// Classification (public, internal, confidential)
        #[arg(long, default_value = "internal")]
        classification: String,
    },
    /// List buckets
    BucketList,
    /// Show bucket details
    BucketShow {
        /// Bucket ID (hex)
        id: String,
    },
    /// Rename a bucket
    BucketRename {
        /// Bucket ID (hex)
        id: String,
        /// New name
        name: String,
    },
    /// Attach a private bucket to the cluster (makes it visible to peers)
    BucketAttach {
        /// Bucket ID (hex)
        id: String,
    },
    /// Archive a bucket (soft-remove, data preserved)
    BucketArchive {
        /// Bucket ID (hex)
        id: String,
        /// Reason for archival
        #[arg(short, long)]
        reason: String,
    },
    /// Bind a bucket to a cluster
    BucketBind {
        /// Bucket ID (hex)
        bucket_id: String,
        /// Cluster ID (hex)
        cluster_id: String,
        /// Set as the cluster's default bucket
        #[arg(long)]
        default: bool,
    },
    /// Run a standalone memvault daemon with full P2P networking
    Daemon {
        /// Listen address (default: /ip4/0.0.0.0/tcp/0)
        #[arg(long, default_value = "/ip4/0.0.0.0/tcp/0")]
        listen: String,
        /// Bootstrap peer multiaddrs (comma-separated)
        #[arg(long, value_delimiter = ',')]
        bootstrap: Vec<String>,
        /// HTTP API port for the embedded REST server
        #[arg(long, env = "MEMVAULT_API_PORT", default_value = "8401")]
        api_port: u16,
    },
    /// Enroll an agent using a join token
    AgentEnroll {
        /// Join token string (mvjoin1:...)
        #[arg(long)]
        token: String,
        /// Agent identifier (e.g. "openclaw")
        #[arg(long)]
        agent_id: String,
        /// Identity directory (default: ~/.local/share/memvault/agents/<agent-id>/)
        #[arg(long)]
        identity_dir: Option<PathBuf>,
    },
    /// List enrolled agents
    AgentList,
    /// Show an agent's enrollment details
    AgentShow {
        /// Agent identifier
        agent_id: String,
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
    let peer_id = store.get_local_peer_id().ok().flatten().unwrap_or_else(|| vec![0u8; 32]);
    let cluster_id = store.get_local_cluster_id().ok().flatten().unwrap_or_else(|| vec![0u8; 32]);
    LocalClient::new(
        store,
        Arc::new(RwLock::new(TextIndex::new())),
        Arc::new(RwLock::new(QuotaManager::new(Default::default()))),
        Arc::new(EventBus::new(64)),
        peer_id,
        cluster_id,
    )
}

/// Load a libp2p Ed25519 keypair from disk, or generate and save a new one.
///
/// Stores the 32-byte Ed25519 secret seed (not the 64-byte expanded keypair)
/// so that `Keypair::ed25519_from_bytes` can reload it.
fn load_or_generate_keypair(key_path: &Path) -> Result<libp2p::identity::Keypair> {
    if key_path.exists() {
        let mut key_bytes = std::fs::read(key_path)?;
        // ed25519_from_bytes expects the 32-byte seed. If we accidentally
        // saved 64 bytes (seed + public), truncate to the seed portion.
        if key_bytes.len() == 64 {
            key_bytes.truncate(32);
        }
        let kp = libp2p::identity::Keypair::ed25519_from_bytes(key_bytes)
            .map_err(|e| anyhow::anyhow!("failed to load keypair from {}: {e}", key_path.display()))?;
        return Ok(kp);
    }

    // Generate new keypair and save the 32-byte secret seed.
    let kp = libp2p::identity::Keypair::generate_ed25519();
    if let Some(parent) = key_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let ed_kp = kp.clone().try_into_ed25519()
        .map_err(|e| anyhow::anyhow!("keypair is not ed25519: {e}"))?;
    let full_bytes = ed_kp.to_bytes();
    // Save only the 32-byte seed (first half of the 64-byte keypair)
    std::fs::write(key_path, &full_bytes[..32])?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(key_path, std::fs::Permissions::from_mode(0o600));
    }
    Ok(kp)
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
    let client_args = cli.client;

    // For commands that need direct store access (RepairIndex, FixClusterId, etc.),
    // use the db path from client_args or fall back to data_dir.
    let make_store = || -> Result<Arc<MemvaultStore>> {
        if let Some(ref db_path) = client_args.db {
            open_store_at(db_path)
        } else {
            open_store(&data_dir)
        }
    };

    // For commands that work via MemvaultClient (local or HTTP).
    let connect = || {
        let mut args = client_args.clone();
        // If no --db was given and no explicit --url, default to data_dir/blocks.redb
        if args.db.is_none() && args.url == "http://127.0.0.1:8401" {
            args.db = Some(data_dir.join("blocks.redb"));
        }
        args
    };

    match cli.command {
        Commands::Genesis { admin_key, default_bucket } => {
            std::fs::create_dir_all(&data_dir)?;
            let cluster_id = ClusterId::random();
            let id_hex = hex::encode(cluster_id.0);
            let id_path = data_dir.join("cluster_id");
            std::fs::write(&id_path, id_hex.as_bytes())?;
            std::fs::create_dir_all(data_dir.join("identity"))?;
            std::fs::create_dir_all(data_dir.join("trust"))?;

            // Create or bind the default bucket
            let store = make_store()?;

            // Generate a local PeerId and persist both identifiers in the store
            let mut peer_id_bytes = [0u8; 32];
            rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut peer_id_bytes);
            store.set_local_peer_id(&peer_id_bytes)?;
            store.set_local_cluster_id(&cluster_id.0)?;

            let client = create_client(store.clone());
            let bucket_id = if let Some(ref bucket_hex) = default_bucket {
                // Bind an existing bucket
                let bucket_bytes = hex::decode(bucket_hex)?;
                let bucket_arr: [u8; 32] = bucket_bytes.try_into()
                    .map_err(|_| anyhow::anyhow!("bucket id must be 32 bytes"))?;
                let bid = memvault_core::BucketId(bucket_arr);
                // Verify it exists
                if store.get_bucket(&bid.0)?.is_none() {
                    anyhow::bail!("bucket {} not found in store", bucket_hex);
                }
                bid
            } else {
                // Create a new default bucket
                use memvault_core::Visibility;
                use memvault_core::classification::Classification;
                client.bucket_create("default", None, Visibility::Internal, Classification::Internal).await?
            };
            store.bind_bucket(&bucket_id.0, &cluster_id.0, true)?;

            // Rebind any pre-existing unbound buckets to this cluster
            let rebound = store.bind_unbound_buckets(&cluster_id.0)?;
            if rebound > 0 {
                println!("  Rebound {rebound} pre-existing bucket(s) to new cluster.");
            }

            println!("Cluster genesis complete.");
            println!("  Cluster ID:      {id_hex}");
            println!("  Default bucket:  {}", hex::encode(bucket_id.0));
            println!("  Data dir:        {}", data_dir.display());
            if let Some(key_path) = admin_key {
                println!("  Admin key:       {}", key_path.display());
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
            let tags = memvault_api::docs::parse_tags(&tag);
            let vis = memvault_api::docs::parse_visibility(Some(&visibility));
            let result = memvault_api::docs::create_doc(&client, &text, title.as_deref(), None, tags, vis, None).await?;
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
            println!("Phase 0: Validating block CIDs...");
            let blocks = store.iter_blocks()?;
            let mut cid_ok = 0usize;
            let mut cid_envelope = 0usize;
            let mut cid_mismatch = 0usize;
            let mut cid_unchecked = 0usize;
            for (cid, data) in &blocks {
                match memvault_core::verify_cid(cid, data) {
                    Ok(true) => { cid_ok += 1; continue; }
                    Err(_) => { cid_unchecked += 1; continue; }
                    Ok(false) => {}
                }
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

            // Phase 0b: Migrate legacy envelopes
            if cid_envelope > 0 {
                println!("Phase 0b: Migrating {cid_envelope} legacy envelope CIDs...");
                let blocks = store.iter_blocks()?;
                let mut migrated = 0usize;
                for (old_cid, data) in &blocks {
                    if let Ok(true) = memvault_core::verify_cid(old_cid, data) {
                        continue;
                    }
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
                        continue;
                    }
                    store.put_block_unchecked(&new_cid_bytes, data)?;
                    store.delete_block(old_cid)?;
                    migrated += 1;
                }
                println!("  Migrated {migrated} envelope(s) to content-addressed CIDs");
            }

            // Phase 1: Rebuild store secondary indexes
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

            // Phase 1b: Rebuild BUCKETS table from BucketDecl blocks
            println!("Phase 1b: Rebuilding bucket metadata from blocks...");
            let mut bucket_count = 0usize;
            for (cid, data) in &blocks {
                if let Ok(val) = serde_json::from_slice::<serde_json::Value>(data) {
                    // Check if this block has a kind:bucket-decl tag
                    let is_bucket_decl = val.get("tags")
                        .and_then(|v| v.as_array())
                        .map(|tags| tags.iter().any(|t| {
                            if let Some(arr) = t.as_array() {
                                arr.first().and_then(|v| v.as_str()) == Some("kind")
                                    && arr.get(1).and_then(|v| v.as_str()) == Some("bucket-decl")
                            } else {
                                false
                            }
                        }))
                        .unwrap_or(false);

                    if is_bucket_decl {
                        // Try to parse bucket_id from the block
                        if let Some(bucket_id) = val.get("bucket_id").and_then(|v| {
                            serde_json::from_value::<[u8; 32]>(v.clone()).ok()
                        }) {
                            store.put_bucket(&bucket_id, cid)?;
                            bucket_count += 1;
                        }
                    }
                }
            }
            println!("  {bucket_count} bucket declaration(s) rebuilt");

            // Phase 2: Rebuild full-text search index
            println!("Phase 2: Rebuilding full-text search index...");
            let client = create_client(store.clone());
            let (doc_count, entity_count, attachment_count) = client.populate_index().await?;
            println!("  {doc_count} docs, {entity_count} entities, {attachment_count} attachments");

            let cache_path = if let Some(ref db_path) = client_args.db {
                db_path.with_extension("text_index.json")
            } else {
                data_dir.join("text_index.json")
            };
            client.save_index(&cache_path).await?;
            println!("  Index cache saved to {}", cache_path.display());

            // Phase 3: Scan for double-prefixed entity IDs
            println!("Phase 3: Scanning for double-prefixed entity IDs...");
            let blocks_scan = store.iter_blocks()?;
            let mut double_prefix_count = 0usize;
            for (_cid, data) in &blocks_scan {
                if let Ok(val) = serde_json::from_slice::<serde_json::Value>(data) {
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
            } else {
                println!("  No double-prefixed entity IDs found (data clean)");
            }

            // Phase 4: Repair VFS tree
            println!("Phase 4: Checking VFS tree integrity...");
            let vfs_repaired = repair_vfs_tree(&client).await?;
            if vfs_repaired > 0 {
                println!("  Linked {vfs_repaired} orphaned directory/ies to VFS root");
                client.save_index(&cache_path).await?;
                println!("  Index cache re-saved");
            } else {
                println!("  VFS tree OK (no orphans)");
            }

            // Phase 5: Migrate pending VFS entries
            println!("Phase 5: Migrating pending VFS entries...");
            let pending_cids = store.query_by_tag("vfs_status", "pending_repair", 0, 10_000)?;
            let mut migrated_vfs = 0usize;
            let mut migration_errors = 0usize;
            for cid in &pending_cids {
                if let Some(data) = store.get_block(cid)? {
                    if let Ok(val) = serde_json::from_slice::<serde_json::Value>(&data) {
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
                            match memvault_api::vfs::link_node_at_path(&client, &path, &node_ref).await {
                                Ok(_) => {
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
                let is_envelope = val.get("wall_ns").is_some() || val.get("author").is_some();
                if !is_envelope {
                    skipped += 1;
                    continue;
                }
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
                store.index_cluster_origin(cid, &cluster_bytes, wall_ns)?;
                patched += 1;
            }

            println!("Indexed {patched} envelopes into CLUSTER_ORIGIN ({skipped} non-envelope blocks skipped).");
        }
        Commands::Export { output, tar, gzip, history, no_vfs, tag, view } => {
            let client = connect().connect().await?;
            let tag_filter = tag.as_deref().and_then(|t| {
                let parts: Vec<&str> = t.splitn(2, ':').collect();
                if parts.len() == 2 {
                    Some((parts[0].to_string(), parts[1].to_string()))
                } else {
                    None
                }
            });
            let opts = memvault_export::ExportOptions {
                history,
                include_vfs: !no_vfs,
                tag_filter,
                view_filter: view,
            };
            let sink = memvault_export::create_sink(&output, tar, gzip)?;
            let stats = memvault_export::run_export(&*client, sink, opts).await?;
            println!(
                "Exported {} documents, {} files, {} entities ({} history versions) to {}",
                stats.documents, stats.files, stats.entities, stats.history_versions,
                output.display()
            );
        }
        Commands::ImportFiles { path, vfs, tag, visibility } => {
            let client = connect().connect().await?;
            let tags = memvault_api::docs::parse_tags(&tag);
            let imported = memvault_import::import_files(&*client, &path, vfs.as_deref(), &tags, &visibility).await?;
            println!("Imported {imported} file(s).");
        }
        Commands::ImportDocs { path, vfs, tag, visibility } => {
            let client = connect().connect().await?;
            let tags = memvault_api::docs::parse_tags(&tag);
            let vis = memvault_api::docs::parse_visibility(Some(&visibility));
            let imported = memvault_import::import_docs(&*client, &path, vfs.as_deref(), &tags, vis).await?;
            println!("Imported {imported} document(s).");
        }
        Commands::ShareInbox => {
            let client = connect().connect().await?;
            let proposals = client.share_inbox().await?;
            if proposals.is_empty() {
                println!("No pending share proposals.");
            }
            for cid in proposals {
                println!("{}", hex::encode(&cid));
            }
        }
        Commands::ShareOutbox => {
            let client = connect().connect().await?;
            let proposals = client.share_outbox().await?;
            if proposals.is_empty() {
                println!("No outbound share proposals.");
            }
            for cid in proposals {
                println!("{}", hex::encode(&cid));
            }
        }
        Commands::ShareApprove { cid } => {
            let cid_bytes = hex::decode(&cid)?;
            let client = connect().connect().await?;
            client.share_decide(&cid_bytes, true, None).await?;
            println!("Share proposal approved.");
        }
        Commands::ShareReject { cid, reason } => {
            let cid_bytes = hex::decode(&cid)?;
            let client = connect().connect().await?;
            client.share_decide(&cid_bytes, false, Some(&reason)).await?;
            println!("Share proposal rejected.");
        }
        Commands::BucketNew { name, desc, visibility, classification } => {
            let vis = memvault_api::docs::parse_visibility(Some(&visibility));
            let class = match classification.as_str() {
                "public" => memvault_core::classification::Classification::Public,
                "confidential" => memvault_core::classification::Classification::Confidential,
                _ => memvault_core::classification::Classification::Internal,
            };
            let client = connect().connect().await?;
            let bucket_id = client.bucket_create(&name, desc.as_deref(), vis, class).await?;
            println!("Bucket created: {}", hex::encode(bucket_id.0));
        }
        Commands::BucketList => {
            let client = connect().connect().await?;
            let buckets = client.bucket_list().await?;
            if buckets.is_empty() {
                println!("No buckets.");
            }
            for b in buckets {
                let status = if !b.is_attached { "private" }
                    else if b.cluster_id.is_none() { "unbound" }
                    else { "attached" };
                let default_marker = if b.is_default { " [default]" } else { "" };
                println!("{} {} [{}]{} items={}",
                    hex::encode(b.id.0), b.name, status, default_marker, b.envelope_count);
            }
        }
        Commands::BucketShow { id } => {
            let bucket_bytes = hex::decode(&id)?;
            let bucket_arr: [u8; 32] = bucket_bytes.try_into()
                .map_err(|_| anyhow::anyhow!("bucket id must be 32 bytes"))?;
            let bucket_id = memvault_core::BucketId(bucket_arr);
            let client = connect().connect().await?;
            match client.bucket_get(&bucket_id).await? {
                Some(b) => {
                    println!("Bucket: {}", b.name);
                    println!("  ID:             {}", hex::encode(b.id.0));
                    println!("  Description:    {}", b.description.unwrap_or_else(|| "-".into()));
                    println!("  Owner:          {}", b.owner_agent.map(|a| a.0).unwrap_or_else(|| "cluster".into()));
                    println!("  Cluster:        {}", b.cluster_id.map(|c| hex::encode(c.0)).unwrap_or_else(|| "unbound".into()));
                    println!("  Default:        {}", b.is_default);
                    println!("  Attached:       {}", b.is_attached);
                    println!("  Visibility:     {:?}", b.default_visibility);
                    println!("  Classification: {:?}", b.default_classification);
                    println!("  Created:        {} ns", b.created_ns);
                    println!("  Envelopes:      {}", b.envelope_count);
                }
                None => {
                    println!("Bucket not found: {id}");
                }
            }
        }
        Commands::BucketRename { id, name } => {
            let bucket_bytes = hex::decode(&id)?;
            let bucket_arr: [u8; 32] = bucket_bytes.try_into()
                .map_err(|_| anyhow::anyhow!("bucket id must be 32 bytes"))?;
            let bucket_id = memvault_core::BucketId(bucket_arr);
            let client = connect().connect().await?;
            client.bucket_rename(&bucket_id, &name).await?;
            println!("Bucket renamed to '{name}'.");
        }
        Commands::BucketAttach { id } => {
            let bucket_bytes = hex::decode(&id)?;
            let bucket_arr: [u8; 32] = bucket_bytes.try_into()
                .map_err(|_| anyhow::anyhow!("bucket id must be 32 bytes"))?;
            let bucket_id = memvault_core::BucketId(bucket_arr);
            let client = connect().connect().await?;
            client.bucket_attach(&bucket_id).await?;
            println!("Bucket attached to cluster.");
        }
        Commands::BucketArchive { id, reason } => {
            let bucket_bytes = hex::decode(&id)?;
            let bucket_arr: [u8; 32] = bucket_bytes.try_into()
                .map_err(|_| anyhow::anyhow!("bucket id must be 32 bytes"))?;
            let bucket_id = memvault_core::BucketId(bucket_arr);
            let client = connect().connect().await?;
            client.bucket_archive(&bucket_id, &reason).await?;
            println!("Bucket archived: {reason}");
        }
        Commands::BucketBind { bucket_id, cluster_id, default } => {
            let bucket_bytes = hex::decode(&bucket_id)?;
            let bucket_arr: [u8; 32] = bucket_bytes.try_into()
                .map_err(|_| anyhow::anyhow!("bucket id must be 32 bytes"))?;
            let bid = memvault_core::BucketId(bucket_arr);
            let cluster_bytes = hex::decode(&cluster_id)?;
            let cluster_arr: [u8; 32] = cluster_bytes.try_into()
                .map_err(|_| anyhow::anyhow!("cluster id must be 32 bytes"))?;
            let cid = ClusterId(cluster_arr);
            let client = connect().connect().await?;
            client.bucket_bind(&bid, &cid, default).await?;
            println!("Bucket bound to cluster{}.", if default { " (default)" } else { "" });
        }
        Commands::Daemon { listen, bootstrap, api_port } => {
            // Open the store and reconcile PeerId
            let store = make_store()?;

            // Load or generate a persistent libp2p keypair.
            // The keypair is saved to `identity/libp2p.key` in the data dir
            // so the PeerId stays stable across restarts.
            let key_path = data_dir.join("identity").join("libp2p.key");
            let keypair = load_or_generate_keypair(&key_path)?;
            let local_peer_id = keypair.public().to_peer_id();
            let peer_id_bytes = local_peer_id.to_bytes();

            // Persist/verify PeerId in store
            store.set_local_peer_id(&peer_id_bytes)
                .map_err(|e| anyhow::anyhow!("PeerId reconciliation failed: {e}"))?;

            // Read cluster_id from store or file
            let cluster_id_bytes = store.get_local_cluster_id()?
                .or_else(|| {
                    let id_path = data_dir.join("cluster_id");
                    std::fs::read_to_string(&id_path).ok()
                        .and_then(|hex| hex::decode(hex.trim()).ok())
                })
                .unwrap_or_else(|| vec![0u8; 32]);

            let client = create_client(store.clone());

            // Load or rebuild the full-text search index
            let index_cache_path = data_dir.join("text_index.json");
            match client.load_or_rebuild_index(&index_cache_path).await {
                Ok((d, e, a)) => tracing::info!("text index ready: {d} docs, {e} entities, {a} attachments"),
                Err(e) => tracing::warn!("failed to populate text index: {e}"),
            }

            // Parse the listen address
            let listen_addr: libp2p::Multiaddr = listen.parse()
                .map_err(|e| anyhow::anyhow!("invalid listen address: {e}"))?;

            // Parse bootstrap peers
            let bootstrap_addrs: Vec<libp2p::Multiaddr> = bootstrap.iter()
                .filter_map(|s| s.parse().ok())
                .collect();

            println!("Starting memvault daemon...");
            println!("  Peer ID:    {local_peer_id}");
            println!("  Listen:     {listen}");
            println!("  API port:   {api_port}");
            println!("  Cluster:    {}", hex::encode(&cluster_id_bytes));
            println!("  Bootstraps: {}", bootstrap_addrs.len());

            // Start the web API + UI server.
            // Uses dioxus::serve() which handles port negotiation with dx serve
            // automatically, and also works standalone.
            #[cfg(feature = "daemon")]
            {
                use dioxus::server::{DioxusRouterExt, ServeConfig};

                let auth_token = memvault_web::load_or_generate_token(&data_dir)
                    .map_err(|e| anyhow::anyhow!("failed to load/generate API token: {e}"))?;

                let client_arc = std::sync::Arc::new(client) as std::sync::Arc<dyn memvault_api::MemvaultClient>;
                memvault_web::ui::state::set_client(std::sync::Arc::clone(&client_arc));

                let app_state = std::sync::Arc::new(memvault_web::AppState {
                    client: client_arc,
                    event_bus: std::sync::Arc::new(memvault_api::EventBus::new(256)),
                    auth_token: auth_token.clone(),
                    metrics: std::sync::Arc::new(memvault_api::metrics::Metrics::new()),
                });
                println!("  API token:  {}", &auth_token[..8]);

                // Build standalone swarm in a background task
                let mut swarm = memvault_net::standalone_swarm(
                    keypair, listen_addr, bootstrap_addrs,
                ).await.map_err(|e| anyhow::anyhow!("swarm error: {e}"))?;

                println!("Daemon running.");
                use futures::StreamExt as _;
                tokio::spawn(async move {
                    loop {
                        tokio::select! {
                            event = swarm.next() => {
                                match event {
                                    Some(libp2p::swarm::SwarmEvent::NewListenAddr { address, .. }) => {
                                        tracing::info!(%address, "P2P listening");
                                    }
                                    Some(libp2p::swarm::SwarmEvent::Behaviour(_)) => {}
                                    _ => {}
                                }
                            }
                        }
                    }
                });

                // dioxus::serve is the main driver — it handles port negotiation
                // with dx serve and runs the axum server.
                dioxus::serve(move || {
                    let state = std::sync::Arc::clone(&app_state);
                    async move {
                        let router = axum::Router::new()
                            .serve_dioxus_application(ServeConfig::new(), memvault_web::ui::app::App)
                            .nest("/api/v1", memvault_web::api::routes(state));
                        Ok(router)
                    }
                });
            }

            // Without the daemon feature, run P2P only (no web UI)
            #[cfg(not(feature = "daemon"))]
            {
                let mut swarm = memvault_net::standalone_swarm(
                    keypair, listen_addr, bootstrap_addrs,
                ).await.map_err(|e| anyhow::anyhow!("swarm error: {e}"))?;

                println!("Daemon running (P2P only, no web UI). Press Ctrl+C to stop.");
                use futures::StreamExt as _;
                loop {
                    tokio::select! {
                        event = swarm.next() => {
                            match event {
                                Some(libp2p::swarm::SwarmEvent::NewListenAddr { address, .. }) => {
                                    println!("  Listening on: {address}");
                                }
                                Some(libp2p::swarm::SwarmEvent::Behaviour(_)) => {}
                                _ => {}
                            }
                        }
                        _ = tokio::signal::ctrl_c() => {
                            println!("\nShutting down daemon...");
                            break;
                        }
                    }
                }
            }
        }
        Commands::AgentEnroll { token, agent_id, identity_dir } => {
            // Decode the join token to extract cluster info
            let join_token = memvault_auth::decode_token_string(&token)
                .map_err(|e| anyhow::anyhow!("failed to decode token: {e}"))?;

            let identity_dir = identity_dir.unwrap_or_else(|| {
                dirs::data_local_dir()
                    .unwrap_or_else(|| PathBuf::from("."))
                    .join("memvault")
                    .join("agents")
                    .join(&agent_id)
            });

            if memvault_api::agent_identity::AgentIdentity::exists(&identity_dir) {
                println!("Agent identity already exists at {}", identity_dir.display());
                println!("To re-enroll, remove the directory first.");
                return Ok(());
            }

            // For CLI enrollment, we need an admin key to sign the enrollment.
            // In the local case, we generate a temporary admin identity.
            // In production, this would go through the /join/1.0 protocol.
            let _store = make_store()?;

            // Read cluster_id from the data dir
            let cluster_id_path = data_dir.join("cluster_id");
            let cluster_id_hex = std::fs::read_to_string(&cluster_id_path)
                .map_err(|e| anyhow::anyhow!("failed to read cluster_id: {e} (run genesis first)"))?;
            let cluster_id_bytes = hex::decode(cluster_id_hex.trim())?;
            let cluster_id_arr: [u8; 32] = cluster_id_bytes.try_into()
                .map_err(|_| anyhow::anyhow!("cluster_id must be 32 bytes"))?;
            let cluster_id = ClusterId(cluster_id_arr);

            // Load or generate admin key from identity dir
            let admin_key_path = data_dir.join("identity").join("admin_key.pem");
            let admin_sk = if admin_key_path.exists() {
                let id = memvault_api::agent_identity::AgentIdentity::load(
                    &data_dir.join("identity")
                ).map_err(|e| anyhow::anyhow!("failed to load admin identity: {e}"))?;
                id.signing_key
            } else {
                // Generate a temporary admin key for local enrollment
                let mut secret = [0u8; 32];
                rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut secret);
                ed25519_dalek::SigningKey::from_bytes(&secret)
            };

            let admin_vk = admin_sk.verifying_key();
            let admin_peer_id = memvault_core::PeerId(admin_vk.as_bytes().to_vec());

            let identity = memvault_api::agent_identity::AgentIdentity::generate_local(
                &identity_dir,
                &agent_id,
                &cluster_id,
                &admin_peer_id,
                &admin_sk,
                join_token.role,
                join_token.not_after_ns.saturating_sub(memvault_core::time::wall_ns()),
            ).map_err(|e| anyhow::anyhow!("enrollment failed: {e}"))?;

            println!("Agent enrolled successfully.");
            println!("  Agent ID:     {agent_id}");
            println!("  Cluster:      {}", hex::encode(cluster_id.0));
            println!("  Identity dir: {}", identity_dir.display());
            println!("  Public key:   {}", hex::encode(identity.verifying_key.as_bytes()));
        }
        Commands::AgentList => {
            let agents_dir = dirs::data_local_dir()
                .unwrap_or_else(|| PathBuf::from("."))
                .join("memvault")
                .join("agents");

            if !agents_dir.exists() {
                println!("No agents enrolled.");
                return Ok(());
            }

            let mut found = false;
            for entry in std::fs::read_dir(&agents_dir)? {
                let entry = entry?;
                if !entry.file_type()?.is_dir() { continue; }
                let agent_dir = entry.path();
                if memvault_api::agent_identity::AgentIdentity::exists(&agent_dir) {
                    match memvault_api::agent_identity::AgentIdentity::load(&agent_dir) {
                        Ok(id) => {
                            println!("{} cluster={} pubkey={}",
                                id.agent_id.0,
                                hex::encode(id.cluster_id.0),
                                hex::encode(id.verifying_key.as_bytes()),
                            );
                            found = true;
                        }
                        Err(e) => {
                            eprintln!("  (error loading {}: {e})", agent_dir.display());
                        }
                    }
                }
            }
            if !found {
                println!("No agents enrolled.");
            }
        }
        Commands::AgentShow { agent_id } => {
            let agent_dir = dirs::data_local_dir()
                .unwrap_or_else(|| PathBuf::from("."))
                .join("memvault")
                .join("agents")
                .join(&agent_id);

            if !memvault_api::agent_identity::AgentIdentity::exists(&agent_dir) {
                println!("Agent '{agent_id}' not found at {}", agent_dir.display());
                return Ok(());
            }

            let id = memvault_api::agent_identity::AgentIdentity::load(&agent_dir)
                .map_err(|e| anyhow::anyhow!("failed to load agent: {e}"))?;

            println!("Agent: {}", id.agent_id.0);
            println!("  Cluster:      {}", hex::encode(id.cluster_id.0));
            println!("  Public key:   {}", hex::encode(id.verifying_key.as_bytes()));
            println!("  Role:         {:?}", id.attestation.role);
            println!("  Expires:      {} ns", id.attestation.not_after_ns);
            println!("  Identity dir: {}", agent_dir.display());
        }
    }

    Ok(())
}

/// Repair the VFS tree.
async fn repair_vfs_tree(client: &LocalClient) -> Result<usize> {
    use memvault_core::{EdgeId, NodeRef};
    use memvault_api::vfs::{VFS_DIR_KIND, VFS_CHILD_REL};
    use std::collections::HashSet;

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

    let mut root_candidates: Vec<[u8; 32]> = all_dirs.iter()
        .filter(|(_, name)| name == "/")
        .map(|(id, _)| *id)
        .collect();
    root_candidates.sort();
    let root_bytes = match root_candidates.first() {
        Some(id) => *id,
        None => return Ok(0),
    };
    let root_node_id = format!("entity:{}", hex::encode(root_bytes));
    let _ = client.add_tags(&root_node_id, vec![("vfs".into(), "root".into())]).await;
    let root_ref = NodeRef::Entity(EntityId(root_bytes));

    let mut actions = 0usize;

    for &dup_bytes in &root_candidates[1..] {
        let dup_ref = NodeRef::Entity(EntityId(dup_bytes));
        let edges = client.edges_of(&dup_ref).await.unwrap_or_default();
        for (src, edge) in &edges {
            if *src != dup_ref || edge.relation != VFS_CHILD_REL { continue; }
            let child_name = edge.props.get("name").and_then(|v| v.as_str()).unwrap_or("?").to_string();
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

    // Deduplicate same-name entries within each directory.
    {
        let mut dedup_stack: Vec<NodeRef> = vec![root_ref.clone()];
        let mut visited: HashSet<[u8; 32]> = HashSet::new();
        visited.insert(root_bytes);
        while let Some(current) = dedup_stack.pop() {
            let edges = client.edges_of(&current).await.unwrap_or_default();
            let mut by_name: BTreeMap<String, Vec<([u8; 32], NodeRef)>> = BTreeMap::new();
            for (src, edge) in &edges {
                if *src != current || edge.relation != VFS_CHILD_REL { continue; }
                let name = edge.props.get("name").and_then(|v| v.as_str()).unwrap_or("").to_string();
                by_name.entry(name).or_default().push((edge.id.0, edge.target.clone()));
            }
            for (name, mut entries) in by_name {
                entries.sort_by(|a, b| a.0.cmp(&b.0));
                if let Some((_, target)) = entries.first() {
                    if let NodeRef::Entity(eid) = target {
                        if visited.insert(eid.0) {
                            dedup_stack.push(target.clone());
                        }
                    }
                }
                for (dup_eid, _) in &entries[1..] {
                    if client.remove_link_from(&current, &EdgeId(*dup_eid)).await.is_ok() {
                        println!("  Retracted duplicate edge for \"{name}\" (edge {})", hex::encode(dup_eid));
                        actions += 1;
                    }
                }
            }
        }
    }

    // Walk tree from root to find all reachable dirs.
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

    // Link orphaned dirs to root.
    let retracted: std::collections::HashSet<[u8; 32]> = root_candidates[1..].iter().copied().collect();
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

} // mod native

#[cfg(not(target_arch = "wasm32"))]
pub use native::*;

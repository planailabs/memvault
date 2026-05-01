//! memctl CLI — can be invoked as a standalone binary or as a daemon subcommand.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::Result;
use clap::{Parser, Subcommand};
use tokio::sync::RwLock;

use crate::{EventBus, LocalClient, MemvaultClient};
use memvault_core::{ClusterId, DocId, EntityId, Visibility};
use memvault_doc::{Document, Edge, Entity};
use memvault_query::{QuotaManager, TextIndex};
use memvault_auth::Role;
use memvault_store::MemvaultStore;

#[derive(Parser, Debug)]
#[command(name = "memctl", about = "Memvault management CLI")]
pub struct Cli {
    /// Data directory
    #[arg(long, env = "MEMVAULT_DATA_DIR")]
    pub data_dir: Option<PathBuf>,

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
    /// Repair the search index
    RepairIndex,
    /// Renew attestation
    RenewAttestation {
        /// Target peer ID (hex)
        peer_id: String,
    },
}

fn default_data_dir() -> PathBuf {
    dirs::data_local_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("memvault")
}

fn open_store(data_dir: &Path) -> Result<Arc<MemvaultStore>> {
    std::fs::create_dir_all(data_dir)?;
    let db_path = data_dir.join("blocks.redb");
    let store = MemvaultStore::open(&db_path)?;
    Ok(Arc::new(store))
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

fn parse_visibility(s: &str) -> Visibility {
    match s {
        "public" => Visibility::Public,
        "federated" => Visibility::Federated,
        _ => Visibility::Internal,
    }
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
            let store = open_store(&data_dir)?;
            let client = create_client(store);
            let tags: Vec<(String, String)> = tag.iter()
                .filter_map(|t| { let (s, l) = t.split_once(':')?; Some((s.to_string(), l.to_string())) })
                .collect();
            let vis = parse_visibility(&visibility);
            let mut frontmatter = BTreeMap::new();
            if let Some(t) = title {
                frontmatter.insert("title".into(), serde_json::Value::String(t));
            }
            let doc = Document::new(DocId::random(), text, frontmatter);
            let cid = client.put_doc(doc, tags, vis).await?;
            println!("{}", hex::encode(&cid));
        }
        Commands::Get { cid } => {
            let cid_bytes = hex::decode(&cid)?;
            let store = open_store(&data_dir)?;
            if let Some(block) = store.get_block(&cid_bytes)? {
                println!("{}", String::from_utf8_lossy(&block));
            } else {
                eprintln!("Block not found: {cid}");
                std::process::exit(1);
            }
        }
        Commands::Search { query, limit } => {
            let store = open_store(&data_dir)?;
            let client = create_client(store);
            let hits = client.search(&query, limit).await?;
            for hit in hits {
                println!("{} (score: {:.2})", hex::encode(hit.doc_id.0), hit.score);
                println!("  {}", hit.snippet.chars().take(80).collect::<String>());
                println!();
            }
        }
        Commands::List { limit, scope } => {
            let store = open_store(&data_dir)?;
            let client = create_client(store);
            let tag_filter = scope.map(|s| (s, "*".to_string()));
            let docs = client.list_docs(tag_filter, limit).await?;
            for doc in docs {
                let title = doc.title.unwrap_or_else(|| "(untitled)".into());
                println!("{} -- {}", hex::encode(&doc.cid), title);
            }
        }
        Commands::Status => {
            let store = open_store(&data_dir)?;
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
            let store = open_store(&data_dir)?;
            let client = create_client(store);
            let tombstone = client.retract(&cid_bytes, &reason).await?;
            println!("Retracted. Tombstone: {}", hex::encode(&tombstone));
        }
        Commands::TokenIssue { role, ttl, max_uses, label } => {
            let role = match role.as_str() {
                "admin" => Role::Admin, "auditor" => Role::Auditor, "service" => Role::Service,
                _ => Role::AgentHost,
            };
            let store = open_store(&data_dir)?;
            let client = create_client(store);
            let token_str = client.issue_token(role, ttl, max_uses, label).await?;
            println!("{token_str}");
        }
        Commands::TokenList => {
            let store = open_store(&data_dir)?;
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
            let store = open_store(&data_dir)?;
            let client = create_client(store);
            client.revoke_token(&cid_bytes, &reason).await?;
            println!("Token revoked.");
        }
        Commands::Rotations => {
            let store = open_store(&data_dir)?;
            let client = create_client(store);
            let rotations = client.list_rotations().await?;
            for r in rotations {
                let status = if r.aborted { "ABORTED" } else { "active" };
                println!("{} [{}] kind={} from_ns={} overlap_until_ns={}", hex::encode(&r.rotation_id), status, r.kind, r.valid_from_ns, r.overlap_until_ns);
            }
        }
        Commands::Audit { limit, kind: _ } => {
            let store = open_store(&data_dir)?;
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
            let store = open_store(&data_dir)?;
            let client = create_client(store);
            let records = client.history_of(&did).await?;
            println!("History for doc {doc_id}: {} ops", records.len());
            for r in records { println!("  {} kind={:?}", hex::encode(&r.cid), r.op_kind); }
        }
        Commands::GraphAdd { kind, prop } => {
            let store = open_store(&data_dir)?;
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
            let store = open_store(&data_dir)?;
            let client = create_client(store);
            let edge = Edge { id: memvault_core::EdgeId::random(), relation, target: target_id, weight, props: BTreeMap::new(), provenance: None };
            let edge_id = client.add_edge(&source_id, edge, Visibility::Internal).await?;
            println!("{}", hex::encode(edge_id.0));
        }
        Commands::GraphQuery { from, relation, max_depth } => {
            let entity_id = parse_entity_id(&from)?;
            let store = open_store(&data_dir)?;
            let client = create_client(store);
            let hits = client.traverse(&entity_id, relation.as_deref(), max_depth).await?;
            for hit in hits { println!("depth={} entity={}", hit.depth, hex::encode(hit.entity_id.0)); }
        }
        Commands::Gc { doc, before } => {
            println!("GC: doc={doc:?} before={before:?}");
            println!("  (manual GC not yet wired to compaction)");
        }
        Commands::Peers => { println!("Connected peers: 0 (standalone mode)"); }
        Commands::RepairIndex => { println!("Index repair: rebuilding from blockstore..."); println!("  (not yet implemented)"); }
        Commands::RenewAttestation { peer_id } => { println!("Attestation renewal for {peer_id}: not yet implemented in standalone mode"); }
    }

    Ok(())
}

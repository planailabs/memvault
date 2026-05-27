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
    use memvault_auth::Role;
    use memvault_core::{ClusterId, DocId, EntityId, Visibility};
    use memvault_doc::{Edge, Entity};
    use memvault_query::{QuotaManager, TextIndex};
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
            /// Bind an existing bucket to the new cluster (hex)
            #[arg(long)]
            bucket: Option<String>,
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
        /// Diff blocks between two stores (semantic, deserialized)
        DiffBlocks {
            /// Path to first redb database
            db_a: PathBuf,
            /// Path to second redb database
            db_b: PathBuf,
        },
        /// Export all raw blocks (one file per CID, hex-encoded name)
        ExportBlocks {
            /// Output path (directory or .tar/.tar.gz file)
            #[arg(short, long, default_value = "./memvault-blocks")]
            output: PathBuf,
            /// Force tar output
            #[arg(long)]
            tar: bool,
            /// Compress tar with gzip
            #[arg(long)]
            gzip: bool,
        },
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
        },
        /// Run a standalone memvault cluster node with P2P networking + API
        ///
        /// A cluster node participates in gossip, bitswap, and serves the REST API.
        /// This is different from an agent — nodes replicate data, agents consume it.
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
        /// Join this node to an existing cluster using a join token
        ///
        /// The token (issued by the cluster admin via `token-issue`) carries
        /// the cluster_id and the cluster's `AdminGenesis` block. The join
        /// pins the admin pubkey from the token — this is the only path
        /// that establishes the chain of trust required to verify
        /// admin-signed sigchain blocks. Raw-cluster_id joining was
        /// removed: it could not pin admin and left the joining node
        /// permanently in pre-genesis mode.
        ///
        /// For enrolling an AGENT (like openclaw), use `agent-enroll`.
        ClusterJoin {
            /// Join token (`mvjoin1:…`) issued by the cluster admin.
            token: String,
        },
        /// Attest a peer node into the cluster (admin-only)
        ///
        /// Publishes a `NodeAttestation` for the given peer pubkey,
        /// signed by this node's admin key. After the block syncs to
        /// the peer, that peer's bootstrap stops registering itself
        /// as pre-genesis. Manual interim step until /join/1.0
        /// round-trip lands.
        NodeAttest {
            /// Hex-encoded peer ed25519 pubkey (32 bytes / 64 hex chars).
            peer_pubkey: String,
            /// Role to grant the peer (default: agent-host).
            #[arg(long, default_value = "agent-host")]
            role: String,
        },
        /// Enroll an agent (e.g. openclaw, hermes) for API access
        ///
        /// Agents are CLIENTS that connect to a cluster node's HTTP API.
        /// They have their own Ed25519 identity for signing operations.
        /// This is different from cluster nodes — agents don't participate
        /// in P2P gossip/bitswap; they just read and write via the API.
        AgentEnroll {
            /// Join token string (mvjoin1:...)
            #[arg(long)]
            token: String,
            /// Agent identifier (e.g. "openclaw", "hermes")
            #[arg(long)]
            agent_id: String,
            /// Identity directory (default: <data-dir>/agents/<agent-id>/)
            #[arg(long)]
            identity_dir: Option<PathBuf>,
        },
        /// List enrolled agents on this node
        AgentList,
        /// Show an agent's enrollment details
        AgentShow {
            /// Agent identifier
            agent_id: String,
        },
        /// Seed the vault with random documents, entities, files, links and VFS entries
        #[command(hide = true)]
        Seed {
            /// Number of documents to create
            #[arg(long, default_value = "30")]
            docs: usize,
            /// Number of entities to create
            #[arg(long, default_value = "20")]
            entities: usize,
            /// Number of files to create
            #[arg(long, default_value = "10")]
            files: usize,
            /// Number of links between nodes
            #[arg(long, default_value = "25")]
            links: usize,
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

    fn create_client_with_data_dir(store: Arc<MemvaultStore>, data_dir: &Path) -> LocalClient {
        create_client_with_bus(store, data_dir, Arc::new(EventBus::new(64)))
    }

    pub fn create_client_with_bus(
        store: Arc<MemvaultStore>,
        data_dir: &Path,
        event_bus: Arc<EventBus>,
    ) -> LocalClient {
        let peer_id = store
            .get_local_peer_id()
            .ok()
            .flatten()
            .unwrap_or_else(|| vec![0u8; 32]);
        let cluster_id = store
            .get_local_cluster_id()
            .ok()
            .flatten()
            .unwrap_or_else(|| vec![0u8; 32]);
        let mut client = LocalClient::open(
            store,
            Arc::new(RwLock::new(TextIndex::new())),
            Arc::new(RwLock::new(QuotaManager::new(Default::default()))),
            event_bus,
            peer_id,
            cluster_id,
        )
        .unwrap_or_else(|e| {
            tracing::warn!("LocalClient::open failed: {e}, falling back to new()");
            panic!("LocalClient::open failed: {e}");
        });
        // Load admin signing key if available (enables token issuance)
        let admin_key_path = data_dir.join("identity").join("admin.key");
        if admin_key_path.exists() {
            if let Ok(key_bytes) = std::fs::read(&admin_key_path) {
                if key_bytes.len() >= 32 {
                    let mut seed = [0u8; 32];
                    seed.copy_from_slice(&key_bytes[..32]);
                    client.set_admin_signing_key(ed25519_dalek::SigningKey::from_bytes(&seed));
                }
            }
        }
        // Load the pinned AdminGenesis so `token issue` embeds it for
        // joining peers, and so peers themselves can verify trust.
        let pin_path = data_dir.join("identity").join("cluster_admin_genesis.cbor");
        if let Ok(pin_bytes) = std::fs::read(&pin_path) {
            match serde_ipld_dagcbor::from_slice::<memvault_auth::AdminGenesis>(&pin_bytes) {
                Ok(g) => {
                    if g.verify_self_signature().is_ok() {
                        client.set_pinned_admin_genesis(g);
                    } else {
                        tracing::warn!("pinned admin_genesis has bad signature; ignoring");
                    }
                }
                Err(e) => tracing::warn!(error = %e, "decode pinned admin_genesis"),
            }
        }
        client
    }

    fn create_client(store: Arc<MemvaultStore>) -> LocalClient {
        // Resolve data_dir from env or default (for admin key loading)
        let data_dir = std::env::var("MEMVAULT_DATA_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|_| {
                dirs::data_local_dir()
                    .unwrap_or_else(|| PathBuf::from("."))
                    .join("memvault")
            });
        create_client_with_data_dir(store, &data_dir)
    }

    /// Spawn the swarm with an already-opened store.  Call AFTER
    /// `create_client_with_bus` (which runs the rebuild) to avoid
    /// serving blocks while CIDs are being rewritten.
    pub fn spawn_swarm_with_store(
        store: Arc<MemvaultStore>,
        data_dir: &Path,
        event_bus: Arc<EventBus>,
    ) -> Result<std::thread::JoinHandle<()>> {
        let data_dir = data_dir.to_path_buf();

        let key_path = data_dir.join("identity").join("libp2p.key");
        let keypair = load_or_generate_keypair(&key_path)?;
        let peer_id_bytes = keypair.public().to_peer_id().to_bytes();
        store
            .set_local_peer_id(&peer_id_bytes)
            .map_err(|e| anyhow::anyhow!("PeerId reconciliation: {e}"))?;

        let cluster_id = store
            .get_local_cluster_id()?
            .or_else(|| {
                let id_path = data_dir.join("cluster_id");
                std::fs::read_to_string(&id_path)
                    .ok()
                    .and_then(|hex| hex::decode(hex.trim()).ok())
            })
            .unwrap_or_else(|| vec![0u8; 32]);

        let sync_config = memvault_swarm::SyncConfig {
            cluster_id,
            ..Default::default()
        };

        let handle = std::thread::Builder::new()
            .name("memvault-swarm".into())
            .spawn(move || {
                let rt = tokio::runtime::Builder::new_multi_thread()
                    .enable_all()
                    .build()
                    .expect("swarm runtime");
                rt.block_on(async move {
                    // Bridge EventBus → head announcements (must be inside a runtime).
                    let (head_tx, head_rx) = memvault_swarm::head_channel();
                    spawn_event_bridge(event_bus, head_tx);

                    let listen: libp2p::Multiaddr = "/ip4/0.0.0.0/tcp/0".parse().unwrap();
                    let mut swarm =
                        match memvault_net::standalone_swarm(keypair, listen, vec![]).await {
                            Ok(s) => s,
                            Err(e) => {
                                tracing::error!("failed to start swarm: {e}");
                                return;
                            }
                        };
                    tracing::info!("P2P swarm started on background thread");
                    memvault_swarm::run_sync_loop(&mut swarm, store, head_rx, sync_config).await;
                });
            })?;

        Ok(handle)
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
            let kp = libp2p::identity::Keypair::ed25519_from_bytes(key_bytes).map_err(|e| {
                anyhow::anyhow!("failed to load keypair from {}: {e}", key_path.display())
            })?;
            return Ok(kp);
        }

        // Generate new keypair and save the 32-byte secret seed.
        let kp = libp2p::identity::Keypair::generate_ed25519();
        if let Some(parent) = key_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let ed_kp = kp
            .clone()
            .try_into_ed25519()
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
        EntityId::from_hex(hex_str).map_err(Into::into)
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
            Commands::Genesis {
                admin_key,
                bucket,
            } => {
                std::fs::create_dir_all(&data_dir)?;
                let cluster_id = ClusterId::random();
                let id_hex = hex::encode(cluster_id.0);
                let id_path = data_dir.join("cluster_id");
                std::fs::write(&id_path, id_hex.as_bytes())?;
                std::fs::create_dir_all(data_dir.join("identity"))?;
                std::fs::create_dir_all(data_dir.join("trust"))?;

                let store = make_store()?;
                store.set_local_cluster_id(&cluster_id.0)?;

                // Generate admin signing key (for token issuance)
                let admin_key_path = data_dir.join("identity").join("admin.key");
                if !admin_key_path.exists() {
                    std::fs::create_dir_all(admin_key_path.parent().unwrap())?;
                    let mut seed = [0u8; 32];
                    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut seed);
                    std::fs::write(&admin_key_path, &seed)?;
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::PermissionsExt;
                        let _ = std::fs::set_permissions(
                            &admin_key_path,
                            std::fs::Permissions::from_mode(0o600),
                        );
                    }
                }

                // Write the AdminGenesis pin file — this is the cluster's
                // root of trust for peers. Self-signed; the matching
                // signing key just got persisted above.
                let admin_key_bytes = std::fs::read(&admin_key_path)?;
                if admin_key_bytes.len() >= 32 {
                    let mut seed = [0u8; 32];
                    seed.copy_from_slice(&admin_key_bytes[..32]);
                    let admin_sk = ed25519_dalek::SigningKey::from_bytes(&seed);
                    let now_ns = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|d| d.as_nanos() as u64)
                        .unwrap_or(0);
                    let genesis = memvault_auth::sign_admin_genesis(
                        &admin_sk,
                        cluster_id.clone(),
                        now_ns,
                    )?;
                    let pin_path = data_dir
                        .join("identity")
                        .join("cluster_admin_genesis.cbor");
                    std::fs::write(&pin_path, serde_ipld_dagcbor::to_vec(&genesis)?)?;
                }

                // Optionally bind an existing bucket to the cluster.
                if let Some(ref bucket_hex) = bucket {
                    let bucket_bytes = hex::decode(bucket_hex)?;
                    let bucket_arr: [u8; 32] = bucket_bytes
                        .try_into()
                        .map_err(|_| anyhow::anyhow!("bucket id must be 32 bytes"))?;
                    if store.get_bucket(&bucket_arr)?.is_none() {
                        anyhow::bail!("bucket {} not found in store", bucket_hex);
                    }
                    store.bind_bucket(&bucket_arr, &cluster_id.0)?;
                    println!("  Bound bucket:    {bucket_hex}");
                }

                // Bind any pre-existing unbound buckets to this cluster.
                let rebound = store.bind_unbound_buckets(&cluster_id.0)?;
                if rebound > 0 {
                    println!("  Rebound {rebound} pre-existing bucket(s) to new cluster.");
                }

                println!("Cluster genesis complete.");
                println!("  Cluster ID:      {id_hex}");
                println!("  Data dir:        {}", data_dir.display());
                if let Some(key_path) = admin_key {
                    println!("  Admin key:       {}", key_path.display());
                }
                println!("\nCluster ID written to {}", id_path.display());
            }
            Commands::Put {
                text,
                tag,
                visibility,
                title,
            } => {
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
                let result = memvault_api::docs::create_doc(
                    &client,
                    &text,
                    title.as_deref(),
                    None,
                    tags,
                    vis,
                    None,
                    None,
                )
                .await?;
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
                let docs = client.list_docs(tag_filter, limit, None).await?;
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
            Commands::TokenIssue {
                role,
                ttl,
                max_uses,
                label,
            } => {
                let role = match role.as_str() {
                    "admin" => Role::Admin,
                    "auditor" => Role::Auditor,
                    "service" => Role::Service,
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
                    println!(
                        "{} [{}] role={:?} uses={}/{} {}",
                        hex::encode(&t.cid),
                        status,
                        t.role,
                        t.consumed_count,
                        t.max_uses,
                        label
                    );
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
                    println!(
                        "{} [{}] kind={} from_ns={} overlap_until_ns={}",
                        hex::encode(&r.rotation_id),
                        status,
                        r.kind,
                        r.valid_from_ns,
                        r.overlap_until_ns
                    );
                }
            }
            Commands::Audit { limit, kind: _ } => {
                let store = make_store()?;
                let cids = store.query_by_time(0, u64::MAX, limit)?;
                println!("{} audit records found.", cids.len());
                for cid in cids {
                    println!("  {}", hex::encode(&cid));
                }
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
                for r in records {
                    println!("  {} kind={:?}", hex::encode(&r.cid), r.op_kind);
                }
            }
            Commands::GraphAdd { kind, prop } => {
                let store = make_store()?;
                let client = create_client(store);
                let props: BTreeMap<String, serde_json::Value> = prop
                    .iter()
                    .filter_map(|p| {
                        let (k, v) = p.split_once('=')?;
                        Some((k.to_string(), serde_json::Value::String(v.to_string())))
                    })
                    .collect();
                let entity = Entity {
                    id: EntityId::random(),
                    kind,
                    props,
                    edges_out: vec![],
                };
                let id = client
                    .add_entity(entity, Visibility::Internal, None)
                    .await?;
                println!("{}", hex::encode(id.0));
            }
            Commands::GraphLink {
                source,
                target,
                relation,
                weight,
            } => {
                let source_id = parse_entity_id(&source)?;
                let target_id = parse_entity_id(&target)?;
                let store = make_store()?;
                let client = create_client(store);
                let source_ref = memvault_core::NodeRef::Entity(source_id);
                let edge = Edge {
                    id: memvault_core::EdgeId::random(),
                    relation,
                    target: memvault_core::NodeRef::Entity(target_id),
                    weight,
                    props: BTreeMap::new(),
                    provenance: None,
                };
                let edge_id = client
                    .add_link(&source_ref, edge, Visibility::Internal)
                    .await?;
                println!("{}", hex::encode(edge_id.0));
            }
            Commands::GraphQuery {
                from,
                relation,
                max_depth,
            } => {
                let entity_id = parse_entity_id(&from)?;
                let store = make_store()?;
                let client = create_client(store);
                let from_ref = memvault_core::NodeRef::Entity(entity_id);
                let hits = client
                    .traverse_from(&from_ref, relation.as_deref(), max_depth)
                    .await?;
                for hit in hits {
                    println!("depth={} node={}", hit.depth, hit.node);
                }
            }
            Commands::Gc { doc, before } => {
                println!("GC: doc={doc:?} before={before:?}");
                println!("  (manual GC not yet wired to compaction)");
            }
            Commands::DiffBlocks { db_a, db_b } => {
                diff_blocks(&db_a, &db_b)?;
            }
            Commands::Peers => {
                println!("Connected peers: 0 (standalone mode)");
            }
            Commands::ExportBlocks { output, tar, gzip } => {
                let store = make_store()?;
                let mut sink = memvault_export::create_sink(&output, tar, gzip)?;
                let count = memvault_export::blocks::export_blocks(&store, &mut *sink)?;
                sink.finish()?;
                println!("Exported {count} blocks to {}", output.display());
            }
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
                        Ok(true) => {
                            cid_ok += 1;
                            continue;
                        }
                        Err(_) => {
                            cid_unchecked += 1;
                            continue;
                        }
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
                println!(
                    "  {cid_ok} verified, {cid_envelope} envelopes (legacy payload CID), {cid_mismatch} mismatched, {cid_unchecked} unchecked"
                );
                if cid_mismatch > 0 {
                    // Remove previously synthesized manifests (CID doesn't match content).
                    // These were created by an older Phase 1c and break sync.
                    let blocks_cleanup = store.iter_blocks()?;
                    let mut cleaned = 0usize;
                    for (cid, data) in &blocks_cleanup {
                        if let Ok(true) = memvault_core::verify_cid(cid, data) {
                            continue;
                        }
                        if let Ok(val) = serde_json::from_slice::<serde_json::Value>(data) {
                            if val.get("payload").is_some() {
                                continue;
                            } // envelope, not a synth manifest
                            if val.get("content_size").is_some() && val.get("filename").is_some() {
                                store.delete_block(cid)?;
                                cleaned += 1;
                            }
                        }
                    }
                    if cleaned > 0 {
                        println!("  Removed {cleaned} synthesized manifest(s) with broken CIDs");
                        // Recount after cleanup.
                        cid_mismatch -= cleaned;
                    }
                    if cid_mismatch > 0 {
                        eprintln!(
                            "  WARNING: {cid_mismatch} block(s) have CID mismatches (data corruption)"
                        );
                    }
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
                        store.put_block(&new_cid_bytes, data)?;
                        store.delete_block(old_cid)?;
                        migrated += 1;
                    }
                    println!("  Migrated {migrated} envelope(s) to content-addressed CIDs");
                }

                // Full deterministic rebuild from BLOCKS.
                println!("Rebuilding all derived state from blocks...");
                let client = create_client(store.clone());
                let report = memvault_api::rebuild::rebuild_store(&client)?;

                println!("  Blocks:       {}", report.blocks_total);
                println!("  Rewritten:    {}", report.unbucketed_rewritten);
                println!("  Envelopes:    {}", report.envelopes_indexed);
                println!("  Buckets:      {}", report.buckets_rebuilt);
                println!("  VFS orphans:  {}", report.vfs_orphans_linked);
                println!("  VFS dupes:    {}", report.vfs_dupes_removed);
                println!("  VFS pending:  {}", report.vfs_pending_migrated);
                println!("  Docs indexed: {}", report.docs_indexed);
                println!("  Entities:     {}", report.entities_indexed);
                println!("  Files:        {}", report.attachments_indexed);

                let cache_path = if let Some(ref db_path) = client_args.db {
                    db_path.with_extension("text_index.json")
                } else {
                    data_dir.join("text_index.json")
                };
                client.save_index(&cache_path).await?;
                println!("  Index cache saved to {}", cache_path.display());
                println!("Rebuild complete (blockstore v{}).", memvault_api::rebuild::BLOCKSTORE_VERSION);
            }
            Commands::RenewAttestation { peer_id } => {
                println!(
                    "Attestation renewal for {peer_id}: not yet implemented in standalone mode"
                );
            }
            Commands::FixClusterId => {
                let id_path = data_dir.join("cluster_id");
                let id_hex = std::fs::read_to_string(&id_path).map_err(|e| {
                    anyhow::anyhow!(
                        "Cannot read {}: {e}. Run 'genesis' first.",
                        id_path.display()
                    )
                })?;
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
                        Err(_) => {
                            skipped += 1;
                            continue;
                        }
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

                println!(
                    "Indexed {patched} envelopes into CLUSTER_ORIGIN ({skipped} non-envelope blocks skipped)."
                );
            }
            Commands::Export {
                output,
                tar,
                gzip,
                history,
                no_vfs,
                tag,
                view,
            } => {
                let client = connect().connect().await?;
                let tag_filter = tag.as_deref().and_then(memvault_api::docs::parse_tag_filter);
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
                    stats.documents,
                    stats.files,
                    stats.entities,
                    stats.history_versions,
                    output.display()
                );
            }
            Commands::ImportFiles {
                path,
                vfs,
                tag,
                visibility,
            } => {
                let client = connect().connect().await?;
                let tags = memvault_api::docs::parse_tags(&tag);
                let imported = memvault_import::import_files(
                    &*client,
                    &path,
                    vfs.as_deref(),
                    &tags,
                    &visibility,
                )
                .await?;
                println!("Imported {imported} file(s).");
            }
            Commands::ImportDocs {
                path,
                vfs,
                tag,
                visibility,
            } => {
                let client = connect().connect().await?;
                let tags = memvault_api::docs::parse_tags(&tag);
                let vis = memvault_api::docs::parse_visibility(Some(&visibility));
                let imported =
                    memvault_import::import_docs(&*client, &path, vfs.as_deref(), &tags, vis)
                        .await?;
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
                client
                    .share_decide(&cid_bytes, false, Some(&reason))
                    .await?;
                println!("Share proposal rejected.");
            }
            Commands::BucketNew {
                name,
                desc,
                visibility,
                classification,
            } => {
                let vis = memvault_api::docs::parse_visibility(Some(&visibility));
                let class = match classification.as_str() {
                    "public" => memvault_core::classification::Classification::Public,
                    "confidential" => memvault_core::classification::Classification::Confidential,
                    _ => memvault_core::classification::Classification::Internal,
                };
                let client = connect().connect().await?;
                let bucket_id = client
                    .bucket_create(&name, desc.as_deref(), vis, class, memvault_doc::BucketRole::Standard)
                    .await?;
                println!("Bucket created: {}", hex::encode(bucket_id.0));
            }
            Commands::BucketList => {
                let client = connect().connect().await?;
                let buckets = client.bucket_list().await?;
                if buckets.is_empty() {
                    println!("No buckets.");
                }
                for b in buckets {
                    let status = if !b.is_attached {
                        "private"
                    } else if b.cluster_id.is_none() {
                        "unbound"
                    } else {
                        "attached"
                    };
                    println!(
                        "{} {} [{}] items={}",
                        hex::encode(b.id.0),
                        b.name,
                        status,
                        b.envelope_count
                    );
                }
            }
            Commands::BucketShow { id } => {
                let bucket_bytes = hex::decode(&id)?;
                let bucket_arr: [u8; 32] = bucket_bytes
                    .try_into()
                    .map_err(|_| anyhow::anyhow!("bucket id must be 32 bytes"))?;
                let bucket_id = memvault_core::BucketId(bucket_arr);
                let client = connect().connect().await?;
                match client.bucket_get(&bucket_id).await? {
                    Some(b) => {
                        println!("Bucket: {}", b.name);
                        println!("  ID:             {}", hex::encode(b.id.0));
                        println!(
                            "  Description:    {}",
                            b.description.unwrap_or_else(|| "-".into())
                        );
                        println!(
                            "  Owner:          {}",
                            b.owner_agent
                                .map(|a| a.0)
                                .unwrap_or_else(|| "cluster".into())
                        );
                        println!(
                            "  Cluster:        {}",
                            b.cluster_id
                                .map(|c| hex::encode(c.0))
                                .unwrap_or_else(|| "unbound".into())
                        );
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
                let bucket_arr: [u8; 32] = bucket_bytes
                    .try_into()
                    .map_err(|_| anyhow::anyhow!("bucket id must be 32 bytes"))?;
                let bucket_id = memvault_core::BucketId(bucket_arr);
                let client = connect().connect().await?;
                client.bucket_rename(&bucket_id, &name).await?;
                println!("Bucket renamed to '{name}'.");
            }
            Commands::BucketAttach { id } => {
                let bucket_bytes = hex::decode(&id)?;
                let bucket_arr: [u8; 32] = bucket_bytes
                    .try_into()
                    .map_err(|_| anyhow::anyhow!("bucket id must be 32 bytes"))?;
                let bucket_id = memvault_core::BucketId(bucket_arr);
                let client = connect().connect().await?;
                client.bucket_attach(&bucket_id).await?;
                println!("Bucket attached to cluster.");
            }
            Commands::BucketArchive { id, reason } => {
                let bucket_bytes = hex::decode(&id)?;
                let bucket_arr: [u8; 32] = bucket_bytes
                    .try_into()
                    .map_err(|_| anyhow::anyhow!("bucket id must be 32 bytes"))?;
                let bucket_id = memvault_core::BucketId(bucket_arr);
                let client = connect().connect().await?;
                client.bucket_archive(&bucket_id, &reason).await?;
                println!("Bucket archived: {reason}");
            }
            Commands::BucketBind {
                bucket_id,
                cluster_id,
            } => {
                let bucket_bytes = hex::decode(&bucket_id)?;
                let bucket_arr: [u8; 32] = bucket_bytes
                    .try_into()
                    .map_err(|_| anyhow::anyhow!("bucket id must be 32 bytes"))?;
                let bid = memvault_core::BucketId(bucket_arr);
                let cluster_bytes = hex::decode(&cluster_id)?;
                let cluster_arr: [u8; 32] = cluster_bytes
                    .try_into()
                    .map_err(|_| anyhow::anyhow!("cluster id must be 32 bytes"))?;
                let cid = ClusterId(cluster_arr);
                let client = connect().connect().await?;
                client.bucket_bind(&bid, &cid).await?;
                println!("Bucket bound to cluster.");
            }
            Commands::Daemon {
                listen,
                bootstrap,
                api_port,
            } => {
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
                store
                    .set_local_peer_id(&peer_id_bytes)
                    .map_err(|e| anyhow::anyhow!("PeerId reconciliation failed: {e}"))?;

                // Read cluster_id from store or file
                let cluster_id_bytes = store
                    .get_local_cluster_id()?
                    .or_else(|| {
                        let id_path = data_dir.join("cluster_id");
                        std::fs::read_to_string(&id_path)
                            .ok()
                            .and_then(|hex| hex::decode(hex.trim()).ok())
                    })
                    .unwrap_or_else(|| vec![0u8; 32]);

                let event_bus_shared = std::sync::Arc::new(EventBus::new(256));
                let client = create_client_with_bus(
                    store.clone(),
                    &data_dir,
                    std::sync::Arc::clone(&event_bus_shared),
                );

                // Rebuild derived state if blockstore version is outdated.
                // Load or rebuild the full-text search index
                let index_cache_path = data_dir.join("text_index.json");
                match client.load_or_rebuild_index(&index_cache_path).await {
                    Ok((d, e, a)) => {
                        tracing::info!("text index ready: {d} docs, {e} entities, {a} attachments")
                    }
                    Err(e) => tracing::warn!("failed to populate text index: {e}"),
                }

                // Parse the listen address
                let listen_addr: libp2p::Multiaddr = listen
                    .parse()
                    .map_err(|e| anyhow::anyhow!("invalid listen address: {e}"))?;

                // Parse bootstrap peers
                let bootstrap_addrs: Vec<libp2p::Multiaddr> =
                    bootstrap.iter().filter_map(|s| s.parse().ok()).collect();

                println!("Starting memvault daemon...");
                println!("  Peer ID:    {local_peer_id}");
                println!("  Listen:     {listen}");
                println!("  API port:   {api_port}");
                println!("  Cluster:    {}", hex::encode(&cluster_id_bytes));
                println!("  Bootstraps: {}", bootstrap_addrs.len());

                // Start the web API + UI server.
                // Uses memvault_web::serve_app() which wraps dioxus::serve() —
                // handles port negotiation with dx serve automatically.
                #[cfg(feature = "daemon")]
                {
                    let _ = local_peer_id;
                    // Dev daemon mode: derive a node key from a local file
                    // (or generate one) — keeps node identity stable across
                    // restarts without depending on a libp2p host key.
                    client.set_node_signing_key(
                        memvault_api::node_key::load_or_generate(&data_dir)
                            .map_err(|e| anyhow::anyhow!("node key: {e}"))?,
                    );
                    let local_client = std::sync::Arc::new(client);
                    let trust = memvault_api::bootstrap::bootstrap_cluster_trust(&local_client)
                        .map_err(|e| anyhow::anyhow!("cluster trust bootstrap: {e}"))?;

                    // Inside `pub async fn run` driven by the caller's
                    // tokio runtime — spawn the watcher onto it.
                    let _watcher = memvault_api::sigchain::spawn_sigchain_watcher(
                        std::sync::Arc::clone(&local_client),
                        trust.admin_pubkey,
                        trust.trust_state.clone(),
                    );
                    memvault_web::init_ui_agent(&local_client, &data_dir)
                        .map_err(|e| anyhow::anyhow!("init ui agent: {e}"))?;

                    memvault_web::ui::state::set_client(std::sync::Arc::clone(&local_client));
                    let client_arc = local_client
                        as std::sync::Arc<dyn memvault_api::MemvaultClient>;

                    let app_state = std::sync::Arc::new(memvault_web::AppState {
                        client: client_arc,
                        event_bus: std::sync::Arc::clone(&event_bus_shared),
                        admin_pubkey: trust.admin_pubkey,
                        node_trust: std::sync::Arc::clone(&trust.trust_state.node_trust),
                        revoked_agents: std::sync::Arc::clone(&trust.trust_state.revoked_agents),
                        revoked_nodes: std::sync::Arc::clone(&trust.trust_state.revoked_nodes),
                        metrics: std::sync::Arc::new(memvault_api::metrics::Metrics::new()),
                    });

                    // Start the web server. Use fullstack (SSR + UI) if assets
                    // exist, otherwise API-only to avoid a panic from Dioxus.
                    // With embed feature, assets are baked in — always fullstack.
                    #[cfg(feature = "embed")]
                    let public_exists = true;
                    #[cfg(not(feature = "embed"))]
                    let public_exists = std::env::current_exe()
                        .ok()
                        .and_then(|p| p.parent().map(|d| d.join("public").exists()))
                        .unwrap_or(false);
                    let router: axum::Router = if public_exists {
                        println!("  Web UI:     http://127.0.0.1:{api_port}");
                        memvault_web::build_fullstack_router(app_state)
                    } else {
                        println!("  Web UI:     disabled (run `dx build` first)");
                        memvault_web::build_router(app_state).into()
                    };
                    let addr = std::net::SocketAddr::from(([127, 0, 0, 1], api_port));
                    tokio::spawn(async move {
                        let listener = match tokio::net::TcpListener::bind(addr).await {
                            Ok(l) => l,
                            Err(e) => {
                                tracing::error!("failed to bind API port {api_port}: {e}");
                                return;
                            }
                        };
                        tracing::info!(port = api_port, "memvault web UI + API started");
                        if let Err(e) = axum::serve(listener, router).await {
                            tracing::error!("web server error: {e}");
                        }
                    });

                    // Build standalone swarm
                    let mut swarm =
                        memvault_net::standalone_swarm(keypair, listen_addr, bootstrap_addrs)
                            .await
                            .map_err(|e| anyhow::anyhow!("swarm error: {e}"))?;

                    // Bridge EventBus → sync loop head announcements
                    let (head_tx, head_rx) = memvault_swarm::head_channel();
                    spawn_event_bridge(event_bus_shared, head_tx);

                    let sync_config = memvault_swarm::SyncConfig {
                        cluster_id: cluster_id_bytes.clone(),
                        ..Default::default()
                    };

                    println!("Daemon running. Press Ctrl+C to stop.");
                    memvault_swarm::run_sync_loop(&mut swarm, store, head_rx, sync_config).await;
                }

                // Without the daemon feature, run P2P only (no web UI)
                #[cfg(not(feature = "daemon"))]
                {
                    let mut swarm =
                        memvault_net::standalone_swarm(keypair, listen_addr, bootstrap_addrs)
                            .await
                            .map_err(|e| anyhow::anyhow!("swarm error: {e}"))?;

                    let (head_tx, head_rx) = memvault_swarm::head_channel();
                    spawn_event_bridge(event_bus_shared, head_tx);

                    let sync_config = memvault_swarm::SyncConfig {
                        cluster_id: cluster_id_bytes.clone(),
                        ..Default::default()
                    };

                    println!("Daemon running (P2P only, no web UI). Press Ctrl+C to stop.");
                    memvault_swarm::run_sync_loop(&mut swarm, store, head_rx, sync_config).await;
                }
            }
            Commands::ClusterJoin { token } => {
                // Token-only join. Decode + verify the embedded
                // AdminGenesis, then pin it; without the pin the joining
                // node has no trust root.
                let parsed = memvault_auth::decode_token_string(&token)
                    .map_err(|e| anyhow::anyhow!("decode token: {e}"))?;
                let genesis = parsed.admin_genesis.clone().ok_or_else(|| {
                    anyhow::anyhow!(
                        "join token has no AdminGenesis — admin must \
                         reissue with the current memctl"
                    )
                })?;
                genesis
                    .verify_self_signature()
                    .map_err(|e| anyhow::anyhow!("admin_genesis signature: {e}"))?;
                if genesis.cluster_id.0 != parsed.cluster_id.0 {
                    anyhow::bail!(
                        "join token cluster_id {} does not match its admin_genesis cluster_id {}",
                        hex::encode(parsed.cluster_id.0),
                        hex::encode(genesis.cluster_id.0)
                    );
                }
                let cluster_id = parsed.cluster_id.clone();
                let cluster_hex = hex::encode(cluster_id.0);

                let store = make_store()?;
                store.set_local_cluster_id(&cluster_id.0)?;

                let id_path = data_dir.join("cluster_id");
                std::fs::create_dir_all(&data_dir)?;
                std::fs::write(&id_path, cluster_hex.as_bytes())?;

                let rebound = store.bind_unbound_buckets(&cluster_id.0)?;
                if rebound > 0 {
                    println!("Rebound {rebound} existing bucket(s) to cluster.");
                }

                std::fs::create_dir_all(data_dir.join("identity"))?;
                let pin_path = data_dir.join("identity").join("cluster_admin_genesis.cbor");
                std::fs::write(&pin_path, serde_ipld_dagcbor::to_vec(&genesis)?)?;
                println!("  Admin pinned:  {}", hex::encode(genesis.admin_pubkey));

                // NOTE: do NOT mint a local admin.key. Peers are not admins.

                println!("Joined cluster {cluster_hex}");
                println!("  Data dir:  {}", data_dir.display());
            }
            Commands::NodeAttest { peer_pubkey, role } => {
                let pk_bytes = hex::decode(&peer_pubkey)
                    .map_err(|e| anyhow::anyhow!("decode peer_pubkey hex: {e}"))?;
                let pk_arr: [u8; 32] = pk_bytes
                    .try_into()
                    .map_err(|_| anyhow::anyhow!("peer_pubkey must be 32 bytes"))?;
                let role_enum = match role.as_str() {
                    "admin" => memvault_auth::Role::Admin,
                    "agent-host" | "agenthost" | "host" => memvault_auth::Role::AgentHost,
                    "auditor" => memvault_auth::Role::Auditor,
                    "service" => memvault_auth::Role::Service,
                    other => anyhow::bail!("unknown role: {other}"),
                };
                let store = make_store()?;
                let client = create_client(store);
                let cid = client
                    .attest_node(pk_arr, role_enum)
                    .map_err(|e| anyhow::anyhow!("attest_node: {e}"))?;
                println!("Attested peer {peer_pubkey}");
                println!("  Attestation CID: {}", hex::encode(&cid));
                println!("  Role:            {role}");
                println!("  The peer's pre-genesis status will clear once this block syncs over.");
            }
            Commands::AgentEnroll {
                token,
                agent_id,
                identity_dir,
            } => {
                // Decode the join token to extract cluster info
                let join_token = memvault_auth::decode_token_string(&token)
                    .map_err(|e| anyhow::anyhow!("failed to decode token: {e}"))?;

                let identity_dir =
                    identity_dir.unwrap_or_else(|| data_dir.join("agents").join(&agent_id));

                if memvault_api::agent_identity::AgentIdentity::exists(&identity_dir) {
                    println!(
                        "Agent identity already exists at {}",
                        identity_dir.display()
                    );
                    println!("To re-enroll, remove the directory first.");
                    return Ok(());
                }

                // For CLI enrollment, we need an admin key to sign the enrollment.
                // In the local case, we generate a temporary admin identity.
                // In production, this would go through the /join/1.0 protocol.
                let _store = make_store()?;

                // Read cluster_id from the data dir
                let cluster_id_path = data_dir.join("cluster_id");
                let cluster_id_hex = std::fs::read_to_string(&cluster_id_path).map_err(|e| {
                    anyhow::anyhow!("failed to read cluster_id: {e} (run genesis first)")
                })?;
                let cluster_id_bytes = hex::decode(cluster_id_hex.trim())?;
                let cluster_id_arr: [u8; 32] = cluster_id_bytes
                    .try_into()
                    .map_err(|_| anyhow::anyhow!("cluster_id must be 32 bytes"))?;
                let cluster_id = ClusterId(cluster_id_arr);

                // Load or generate admin key from identity dir
                let admin_key_path = data_dir.join("identity").join("admin_key.pem");
                let admin_sk = if admin_key_path.exists() {
                    let id = memvault_api::agent_identity::AgentIdentity::load(
                        &data_dir.join("identity"),
                    )
                    .map_err(|e| anyhow::anyhow!("failed to load admin identity: {e}"))?;
                    id.signing_key
                } else {
                    // Generate a temporary admin key for local enrollment
                    let mut secret = [0u8; 32];
                    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut secret);
                    ed25519_dalek::SigningKey::from_bytes(&secret)
                };

                // Single-key dev-mode enrollment: admin == node. Real multi-node
                // enrollment will pass the joining node's own signing key here.
                let identity = memvault_api::agent_identity::AgentIdentity::generate_local(
                    &identity_dir,
                    &agent_id,
                    &cluster_id,
                    &admin_sk,
                    join_token.role,
                    join_token
                        .not_after_ns
                        .saturating_sub(memvault_core::time::wall_ns()),
                )
                .map_err(|e| anyhow::anyhow!("enrollment failed: {e}"))?;

                println!("Agent enrolled successfully.");
                println!("  Agent ID:     {agent_id}");
                println!("  Cluster:      {}", hex::encode(cluster_id.0));
                println!("  Identity dir: {}", identity_dir.display());
                println!(
                    "  Public key:   {}",
                    hex::encode(identity.verifying_key.as_bytes())
                );
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
                    if !entry.file_type()?.is_dir() {
                        continue;
                    }
                    let agent_dir = entry.path();
                    if memvault_api::agent_identity::AgentIdentity::exists(&agent_dir) {
                        match memvault_api::agent_identity::AgentIdentity::load(&agent_dir) {
                            Ok(id) => {
                                println!(
                                    "{} cluster={} pubkey={}",
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
                println!(
                    "  Public key:   {}",
                    hex::encode(id.verifying_key.as_bytes())
                );
                println!("  Role:         {:?}", id.attestation.role);
                println!("  Expires:      {} ns", id.attestation.not_after_ns);
                println!("  Identity dir: {}", agent_dir.display());
            }
            Commands::Seed {
                docs,
                entities,
                files,
                links,
            } => {
                let store = make_store()?;
                let client = create_client(store);
                run_seed(&client, docs, entities, files, links).await?;
            }
        }

        Ok(())
    }

    /// Spawn a background task that bridges EventBus events to the
    /// sync loop's head announcement channel.
    fn spawn_event_bridge(
        event_bus: Arc<EventBus>,
        head_tx: tokio::sync::mpsc::UnboundedSender<memvault_swarm::OutboundHead>,
    ) {
        tokio::spawn(async move {
            let mut rx = event_bus.subscribe();
            loop {
                match rx.recv().await {
                    Ok(event) => {
                        let cid = match &event {
                            memvault_api::MemvaultEvent::DocCreated { cid, .. } => {
                                Some(cid.clone())
                            }
                            memvault_api::MemvaultEvent::DocUpdated { cid, .. } => {
                                Some(cid.clone())
                            }
                            memvault_api::MemvaultEvent::BucketCreated { cid, .. } => {
                                Some(cid.clone())
                            }
                            memvault_api::MemvaultEvent::Retracted { cid } => Some(cid.clone()),
                            memvault_api::MemvaultEvent::TokenConsumed { token_cid } => {
                                Some(token_cid.clone())
                            }
                            // Push-on-create: announce sigchain blocks
                            // immediately over gossip so peers don't have to
                            // wait for the next RBSR cycle to learn about a
                            // new attestation, revocation, or envelope
                            // authorship sidecar.
                            memvault_api::MemvaultEvent::SigchainBlock { cid, .. } => {
                                Some(cid.clone())
                            }
                            _ => None,
                        };
                        if let Some(cid) = cid {
                            if head_tx
                                .send(memvault_swarm::OutboundHead {
                                    cid,
                                    bucket_id: None,
                                })
                                .is_err()
                            {
                                break;
                            }
                        }
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                        tracing::warn!(skipped = n, "event bus lagged, some heads not announced");
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                }
            }
        });
    }

    async fn run_seed(
        client: &LocalClient,
        n_docs: usize,
        n_entities: usize,
        n_files: usize,
        n_links: usize,
    ) -> Result<()> {
        use memvault_core::{EdgeId, NodeRef};
        use rand::Rng;

        let mut rng = rand::thread_rng();
        // Pick a bucket to write into, in order of preference:
        //   1. The legacy bucket if one exists (adopted pre-bucket data).
        //   2. An existing bucket named "seed" — keeps repeat `memctl
        //      seed` runs idempotent.
        //   3. Create a fresh bucket named "seed".
        // Falling back through 2 → 3 means seeding works on a clean
        // node that has never seen any pre-bucket data.
        let bucket = if let Some(b) = client.find_legacy_bucket() {
            b
        } else {
            use memvault_api::MemvaultClient;
            let existing = client.bucket_list().await?;
            if let Some(b) = existing.iter().find(|b| b.name == "seed") {
                b.id.clone()
            } else {
                println!("No legacy bucket found; creating bucket \"seed\" for synthetic data.");
                client
                    .bucket_create(
                        "seed",
                        Some("Synthetic data generated by `memctl seed`"),
                        memvault_core::Visibility::Internal,
                        memvault_core::classification::Classification::Internal,
                        memvault_doc::BucketRole::Standard,
                    )
                    .await?
            }
        };

        // ── Vocabulary for generating plausible content ──────────────────
        let topics = [
            "architecture",
            "deployment",
            "security",
            "performance",
            "testing",
            "networking",
            "storage",
            "observability",
            "authentication",
            "CI/CD",
            "database",
            "caching",
            "messaging",
            "containers",
            "serverless",
        ];
        let adjectives = [
            "distributed",
            "scalable",
            "resilient",
            "automated",
            "zero-trust",
            "event-driven",
            "declarative",
            "immutable",
            "stateless",
            "real-time",
        ];
        let entity_kinds = [
            "person", "project", "service", "team", "tool", "library", "server", "database",
            "topic", "standard",
        ];
        let names = [
            "Alice", "Bob", "Charlie", "Diana", "Eve", "Frank", "Grace", "Hector", "Iris", "Jack",
            "Kara", "Leo", "Maya", "Nate", "Olivia", "Pablo", "Quinn", "Rosa",
        ];
        let project_names = [
            "memvault",
            "hermes",
            "openclaw",
            "atlas",
            "beacon",
            "compass",
            "dynamo",
            "echo",
            "forge",
            "gateway",
            "horizon",
            "ignite",
            "jetstream",
            "keystone",
            "lighthouse",
        ];
        let relations = [
            "works_on",
            "depends_on",
            "maintains",
            "reviewed_by",
            "related_to",
            "part_of",
            "blocks",
            "extends",
        ];
        let file_exts = [
            ("txt", "text/plain"),
            ("md", "text/markdown"),
            ("json", "application/json"),
            ("csv", "text/csv"),
            ("log", "text/plain"),
            ("yaml", "text/yaml"),
        ];
        let vfs_dirs = [
            "/notes",
            "/projects",
            "/attachments",
            "/docs",
            "/reports",
            "/specs",
            "/logs",
        ];

        // ── Ensure VFS directories exist ────────────────────────────────
        for dir in &vfs_dirs {
            let _ = memvault_api::vfs::ensure_dir_path(client, &bucket, dir).await;
        }
        println!("  VFS directories created: {}", vfs_dirs.len());

        // Track all created node refs for linking later.
        let mut all_nodes: Vec<NodeRef> = Vec::new();

        // ── Documents ───────────────────────────────────────────────────
        for i in 0..n_docs {
            let topic = topics[rng.gen_range(0..topics.len())];
            let adj = adjectives[rng.gen_range(0..adjectives.len())];
            let title = format!("{} {} notes #{}", adj, topic, i + 1);
            let paragraphs: usize = rng.gen_range(2..6);
            let mut body = String::new();
            for _ in 0..paragraphs {
                let sentences: usize = rng.gen_range(2..5);
                for _ in 0..sentences {
                    let t1 = topics[rng.gen_range(0..topics.len())];
                    let t2 = topics[rng.gen_range(0..topics.len())];
                    let a = adjectives[rng.gen_range(0..adjectives.len())];
                    body.push_str(&format!(
                        "The {} approach to {} integrates well with {}. ",
                        a, t1, t2
                    ));
                }
                body.push('\n');
            }
            let mut fm = BTreeMap::new();
            fm.insert(
                "title".to_string(),
                serde_json::Value::String(title.clone()),
            );
            let doc = memvault_doc::Document::new(DocId::random(), body, fm);
            let mut tags = vec![("topic".to_string(), topic.to_string())];
            if rng.gen_bool(0.3) {
                tags.push((
                    "priority".to_string(),
                    ["low", "medium", "high"][rng.gen_range(0..3)].to_string(),
                ));
            }
            let cid = client
                .put_doc(doc.clone(), tags, Visibility::Internal, Some(&bucket))
                .await?;
            all_nodes.push(NodeRef::Doc(doc.id.clone()));

            // Place some docs in VFS
            if rng.gen_bool(0.5) {
                let dir = vfs_dirs[rng.gen_range(0..vfs_dirs.len())];
                let slug: String = title
                    .chars()
                    .filter(|c| c.is_alphanumeric() || *c == ' ')
                    .collect::<String>()
                    .replace(' ', "-")
                    .to_lowercase();
                let path = format!("{}/{}.md", dir, &slug[..slug.len().min(40)]);
                let node_id = format!("doc:{}", hex::encode(doc.id.0));
                let _ =
                    memvault_api::vfs::link_node_at_path(client, &bucket, &path, &node_id).await;
            }

            if (i + 1) % 10 == 0 || i + 1 == n_docs {
                println!("  Documents: {}/{}", i + 1, n_docs);
            }
            let _ = cid;
        }

        // ── Entities ────────────────────────────────────────────────────
        for i in 0..n_entities {
            let kind = entity_kinds[rng.gen_range(0..entity_kinds.len())];
            let name = match kind {
                "person" => names[rng.gen_range(0..names.len())].to_string(),
                "project" | "service" | "tool" => {
                    project_names[rng.gen_range(0..project_names.len())].to_string()
                }
                "team" => format!(
                    "team-{}",
                    &["platform", "infra", "product", "security", "data"][rng.gen_range(0..5)]
                ),
                _ => format!("{}-{}", kind, rng.gen_range(1..100u32)),
            };
            let mut props = BTreeMap::new();
            props.insert("name".to_string(), serde_json::json!(name));
            if rng.gen_bool(0.4) {
                props.insert(
                    "description".to_string(),
                    serde_json::json!(format!(
                        "A {} entity for {} purposes",
                        adjectives[rng.gen_range(0..adjectives.len())],
                        topics[rng.gen_range(0..topics.len())]
                    )),
                );
            }
            if kind == "person" && rng.gen_bool(0.5) {
                props.insert(
                    "role".to_string(),
                    serde_json::json!(
                        ["engineer", "manager", "designer", "analyst", "lead"][rng.gen_range(0..5)]
                    ),
                );
            }
            let entity = Entity {
                id: EntityId::random(),
                kind: kind.to_string(),
                props,
                edges_out: vec![],
            };
            let eid = client
                .add_entity(entity.clone(), Visibility::Internal, Some(&bucket))
                .await?;
            all_nodes.push(NodeRef::Entity(eid));

            if (i + 1) % 10 == 0 || i + 1 == n_entities {
                println!("  Entities:  {}/{}", i + 1, n_entities);
            }
        }

        // ── Files ───────────────────────────────────────────────────────
        for i in 0..n_files {
            let (ext, mime) = file_exts[rng.gen_range(0..file_exts.len())];
            let topic = topics[rng.gen_range(0..topics.len())];
            let filename = format!("{}-report-{}.{}", topic, rng.gen_range(1..999u32), ext);

            // Generate plausible file content
            let content = match ext {
                "json" => serde_json::to_vec_pretty(&serde_json::json!({
                    "report": topic,
                    "generated": format!("{}ns", memvault_core::wall_ns()),
                    "metrics": {
                        "latency_p99_ms": rng.gen_range(10..500),
                        "throughput_rps": rng.gen_range(100..10000),
                        "error_rate": format!("{:.2}%", rng.gen_range(0.0..5.0f64)),
                    },
                    "tags": [adjectives[rng.gen_range(0..adjectives.len())]],
                }))
                .unwrap_or_default(),
                "csv" => {
                    let mut csv = "timestamp,metric,value\n".to_string();
                    for row in 0..rng.gen_range(5..20) {
                        csv.push_str(&format!(
                            "2026-01-{:02}T00:00:00Z,{},{}\n",
                            row + 1,
                            topic,
                            rng.gen_range(1..1000)
                        ));
                    }
                    csv.into_bytes()
                }
                _ => {
                    let mut text = String::new();
                    for _ in 0..rng.gen_range(3..10) {
                        let t = topics[rng.gen_range(0..topics.len())];
                        let a = adjectives[rng.gen_range(0..adjectives.len())];
                        text.push_str(&format!("{} {} — details and analysis.\n", a, t));
                    }
                    text.into_bytes()
                }
            };

            let cid = client
                .upload_file(
                    &content,
                    Some(&filename),
                    mime,
                    vec![],
                    "internal",
                    Some(&bucket),
                )
                .await?;
            all_nodes.push(NodeRef::Attachment(cid.clone()));

            // Place in VFS
            if rng.gen_bool(0.7) {
                let dir = vfs_dirs[rng.gen_range(0..vfs_dirs.len())];
                let path = format!("{}/{}", dir, filename);
                let node_id = format!("file:{}", hex::encode(&cid));
                let _ =
                    memvault_api::vfs::link_node_at_path(client, &bucket, &path, &node_id).await;
            }

            if (i + 1) % 5 == 0 || i + 1 == n_files {
                println!("  Files:     {}/{}", i + 1, n_files);
            }
        }

        // ── Links ───────────────────────────────────────────────────────
        let mut link_count = 0;
        for _ in 0..n_links * 3 {
            if link_count >= n_links {
                break;
            }
            if all_nodes.len() < 2 {
                break;
            }

            let src = &all_nodes[rng.gen_range(0..all_nodes.len())];
            let dst = &all_nodes[rng.gen_range(0..all_nodes.len())];
            if src == dst {
                continue;
            }

            let relation = relations[rng.gen_range(0..relations.len())];
            let weight = if rng.gen_bool(0.5) {
                Some(rng.gen_range(0.1..1.0f32))
            } else {
                None
            };
            let edge = Edge {
                id: EdgeId::random(),
                relation: relation.to_string(),
                target: dst.clone(),
                weight,
                props: BTreeMap::new(),
                provenance: None,
            };
            if client
                .add_link(src, edge, Visibility::Internal)
                .await
                .is_ok()
            {
                link_count += 1;
            }
        }
        println!("  Links:     {}/{}", link_count, n_links);

        println!(
            "\nSeed complete: {} docs, {} entities, {} files, {} links.",
            n_docs, n_entities, n_files, link_count
        );
        Ok(())
    }

    fn diff_blocks(db_a: &Path, db_b: &Path) -> Result<()> {
        use std::collections::{BTreeMap, HashSet};

        let store_a = Arc::new(MemvaultStore::open(db_a)?);
        let store_b = Arc::new(MemvaultStore::open(db_b)?);

        let blocks_a = store_a.iter_blocks()?;
        let blocks_b = store_b.iter_blocks()?;

        let cids_a: HashSet<Vec<u8>> = blocks_a.iter().map(|(c, _)| c.clone()).collect();
        let cids_b: HashSet<Vec<u8>> = blocks_b.iter().map(|(c, _)| c.clone()).collect();

        let only_a: Vec<&Vec<u8>> = cids_a.difference(&cids_b).collect();
        let only_b: Vec<&Vec<u8>> = cids_b.difference(&cids_a).collect();
        let common = cids_a.intersection(&cids_b).count();

        println!("Node A: {} blocks  ({})", blocks_a.len(), db_a.display());
        println!("Node B: {} blocks  ({})", blocks_b.len(), db_b.display());
        println!("Common: {common}");
        println!("Only A: {}", only_a.len());
        println!("Only B: {}", only_b.len());

        if only_a.is_empty() && only_b.is_empty() {
            println!("\nStores are identical.");
            return Ok(());
        }

        let map_a: BTreeMap<Vec<u8>, Vec<u8>> = blocks_a.into_iter().collect();
        let map_b: BTreeMap<Vec<u8>, Vec<u8>> = blocks_b.into_iter().collect();

        if !only_a.is_empty() {
            println!("\n=== Only on Node A ({}) ===\n", only_a.len());
            for cid in &only_a {
                if let Some(data) = map_a.get(*cid) {
                    print_block_summary(cid, data);
                }
            }
        }

        if !only_b.is_empty() {
            println!("\n=== Only on Node B ({}) ===\n", only_b.len());
            for cid in &only_b {
                if let Some(data) = map_b.get(*cid) {
                    print_block_summary(cid, data);
                }
            }
        }

        Ok(())
    }

    fn print_block_summary(cid: &[u8], data: &[u8]) {
        let cid_hex = &hex::encode(cid)[..16];
        let size = data.len();

        if let Some(val) = memvault_store::deserialize_block(data) {
            // Envelope or manifest — show structured content.
            let kind = if val.get("payload").is_some() {
                let payload = val.get("payload").unwrap();
                if payload.get("DocCreate").is_some() {
                    "DocCreate"
                } else if payload.get("DocEdit").is_some() {
                    "DocEdit"
                } else if payload.get("EntityCreate").is_some() {
                    "EntityCreate"
                } else if payload.get("EntityUpdate").is_some() {
                    "EntityUpdate"
                } else if payload.get("EdgeAdd").is_some() {
                    "EdgeAdd"
                } else if payload.get("BucketCreate").is_some() {
                    "BucketCreate"
                } else {
                    "envelope"
                }
            } else if val.get("content_root").is_some() {
                "manifest"
            } else if val.get("kind").and_then(|v| v.as_str()) == Some("attachment") {
                "attachment"
            } else if val.get("kind").and_then(|v| v.as_str()) == Some("annotation") {
                "annotation"
            } else {
                "json/cbor"
            };

            let author = val
                .get("author")
                .and_then(|v| v.as_array())
                .map(|a| {
                    let bytes: Vec<u8> = a.iter().filter_map(|n| n.as_u64().map(|n| n as u8)).collect();
                    hex::encode(&bytes)
                })
                .unwrap_or_default();
            let author_short = if author.len() > 16 { &author[..16] } else { &author };

            println!("  {cid_hex}…  {kind:<16} {size:>6}B  author={author_short}…");
            // Full deserialized content
            println!("{}", serde_json::to_string_pretty(&val).unwrap_or_default());
            println!();
        } else {
            println!("  {cid_hex}…  raw             {size:>6}B");
            println!();
        }
    }

} // mod native

#[cfg(not(target_arch = "wasm32"))]
pub use native::*;

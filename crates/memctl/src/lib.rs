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

        /// Operate as the given enrolled agent. When set, the
        /// LocalClient binds the agent's identity (loaded from
        /// `<data-dir>/agents/<agent-id>/`) before running the
        /// command. Writes produced under this flag get an
        /// `EnvelopeAuthorship` sidecar signed by the agent, and
        /// future read-path enforcement (`verify_envelope_authorship`)
        /// will name this agent as the author.
        ///
        /// Has effect on commands that go through `create_client*`
        /// (`put`, `get`, `list`, `search`, etc.). Administrative
        /// commands that read raw files (`genesis`, `cluster-join`,
        /// `token issue`, `agent enroll`) ignore it.
        #[arg(long, global = true, env = "MEMVAULT_AGENT_ID")]
        pub agent_id: Option<String>,

        /// Target a specific bucket for the command. Hex-encoded
        /// 32-byte BucketId. When unset, bucket-aware commands fall
        /// back to the bound agent's own bucket (when `--agent-id`
        /// is also set) — auto-created via
        /// `LocalClient::ensure_agent_bucket_for`. If neither is
        /// set, the command hard-fails: we deliberately do NOT
        /// auto-pick "the first existing bucket", and we don't allow
        /// writes to land in the void either. Buckets are
        /// tenant-scoped; the operator should always know which one.
        #[arg(long, global = true, env = "MEMVAULT_BUCKET_ID")]
        pub bucket_id: Option<String>,

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
        /// Document link tooling (links / backlinks / dangling / reindex-links)
        #[command(subcommand)]
        Doc(DocCommands),
        /// Retract a memory
        Retract {
            /// Hex-encoded CID to retract
            cid: String,
            /// Reason for retraction
            #[arg(short, long)]
            reason: String,
        },
        /// Join-token management (issue / list / revoke)
        #[command(subcommand)]
        Token(TokenCommands),
        /// List key rotations
        Rotations,
        /// Multi-admin key management
        #[command(subcommand)]
        Admin(AdminCommands),
        /// Show node status
        Status,
        /// Knowledge-graph operations (add / link / query)
        #[command(subcommand)]
        Graph(GraphCommands),
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
        /// Share-proposal operations (inbox / outbox / approve / reject)
        #[command(subcommand)]
        Share(ShareCommands),
        /// Bucket operations (new / list / show / rename / attach / archive / bind)
        #[command(subcommand)]
        Bucket(BucketCommands),
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
        /// The token (issued by the cluster admin via `token issue`) carries
        /// the cluster_id and the cluster's `AdminGenesis` block. The join
        /// pins the admin pubkey from the token — this is the only path
        /// that establishes the chain of trust required to verify
        /// admin-signed sigchain blocks. Raw-cluster_id joining was
        /// removed: it could not pin admin and left the joining node
        /// permanently in pre-genesis mode.
        ///
        /// For enrolling an AGENT (like openclaw), use `agent enroll`.
        ClusterJoin {
            /// Join token (`mvjoin1:…`) issued by the cluster admin.
            token: String,
            /// Also request co-admin status: generate a fresh admin key and
            /// present it for admission during the join. Only works if the
            /// token was issued with `token issue --admit-as-admin`.
            #[arg(long)]
            admit_as_admin: bool,
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
        },
        /// Agent operations (enroll / list / show)
        ///
        /// Agents are CLIENTS that connect to a cluster node's HTTP API.
        /// They have their own Ed25519 identity for signing operations.
        /// This is different from cluster nodes — agents don't participate
        /// in P2P gossip/bitswap; they just read and write via the API.
        #[command(subcommand)]
        Agent(AgentCommands),
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

    /// Multi-admin key management subcommands.
    #[derive(Subcommand, Debug)]
    pub enum AdminCommands {
        /// Generate a new admin keypair, writing the 32-byte seed to a file.
        GenKey {
            /// Output path for the new admin key seed.
            #[arg(long)]
            out: PathBuf,
        },
        /// Print a proof-of-possession for an admin key seed file, to hand
        /// to an existing admin for admission. Requires the cluster id.
        Pop {
            /// Path to the admin key seed file (from `gen-key`).
            #[arg(long)]
            key: PathBuf,
            /// POP validity, in seconds from now. The admitting admin must
            /// issue the admission before this elapses.
            #[arg(long, default_value = "86400")]
            ttl: u64,
        },
        /// Admit a new admin key. Provide its pubkey (hex), POP (hex), and
        /// the POP expiry, produced by the incoming operator via
        /// `gen-key` + `pop`.
        Admit {
            /// New admin verifying key (64 hex chars).
            #[arg(long)]
            new_pubkey: String,
            /// Proof-of-possession (128 hex chars) from the incoming admin.
            #[arg(long)]
            pop: String,
            /// POP expiry in unix-ns, as printed by `memctl admin pop`.
            #[arg(long)]
            pop_not_after_ns: u64,
        },
        /// Retire an admin key (hex pubkey). Cannot retire the last admin.
        Retire {
            /// Admin verifying key to retire (64 hex chars).
            #[arg(long)]
            pubkey: String,
            /// Reason (audit).
            #[arg(long, default_value = "retired")]
            reason: String,
        },
        /// List the cluster's admin keys and their validity windows.
        List,
    }

    /// Join-token subcommands.
    #[derive(Subcommand, Debug)]
    pub enum TokenCommands {
        /// Issue a join token. Exactly one of `--agent-role` (an agent-enrol
        /// token) or `--node-role` (a node-join token) must be given.
        Issue {
            /// Agent role for an agent-enrolment token.
            #[arg(long, value_enum, conflicts_with = "node_role")]
            agent_role: Option<AgentRoleArg>,
            /// Node role for a node-join token. `admin` also permits admin-key
            /// admission at join (joiner runs `cluster-join --admit-as-admin`).
            #[arg(long, value_enum, conflicts_with = "agent_role")]
            node_role: Option<NodeRoleArg>,
            /// TTL in seconds
            #[arg(long, default_value = "3600")]
            ttl: u64,
            /// Maximum uses
            #[arg(long, default_value = "1")]
            max_uses: u32,
            /// Human-readable label
            #[arg(long)]
            label: Option<String>,
            /// Dialable multiaddr(s) of this node to embed in the token, so a
            /// joiner can connect directly instead of waiting to discover the
            /// issuer's peer id. Repeatable. Omit to rely on mDNS/Kademlia
            /// discovery of the issuer.
            #[arg(long = "addr")]
            addrs: Vec<String>,
        },
        /// List tokens
        List,
        /// Revoke a token
        Revoke {
            /// Hex-encoded token CID
            cid: String,
            /// Reason
            #[arg(short, long)]
            reason: String,
        },
    }

    /// Document link-graph subcommands.
    #[derive(Subcommand, Debug)]
    pub enum DocCommands {
        /// List outlinks for a document (cached, from the latest extracted-text
        /// annotation under doc:<head-cid>).
        Links {
            /// Hex-encoded DocId
            doc_id: String,
        },
        /// List backlinks pointing at a node (any kind).
        Backlinks {
            /// Target tag label, e.g. `doc:abcd…`, `entity:1234…`, `file:c0ffee…`.
            node: String,
        },
        /// List body-extracted edges whose target is a pending (unresolved)
        /// alias placeholder. These are the dangling links.
        Dangling {
            /// Optional bucket filter (hex bucket-id).
            #[arg(long)]
            bucket: Option<String>,
        },
        /// Force a re-parse of a document's body — drops the cached
        /// extraction annotation and re-runs the extractor, which in turn
        /// re-reconciles graph edges.
        ReindexLinks {
            /// Hex-encoded DocId. If omitted, reindex every doc.
            #[arg(long)]
            doc_id: Option<String>,
        },
    }

    /// Knowledge-graph subcommands.
    #[derive(Subcommand, Debug)]
    pub enum GraphCommands {
        /// Add an entity to the knowledge graph
        Add {
            /// Entity kind
            kind: String,
            /// Properties as key=value pairs
            #[arg(short, long)]
            prop: Vec<String>,
        },
        /// Link two entities
        Link {
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
        Query {
            /// Starting entity ID (hex)
            from: String,
            /// Relation filter
            #[arg(long)]
            relation: Option<String>,
            /// Maximum depth
            #[arg(long, default_value = "3")]
            max_depth: usize,
        },
    }

    /// Share-proposal subcommands.
    #[derive(Subcommand, Debug)]
    pub enum ShareCommands {
        /// List share inbox (proposals received)
        Inbox,
        /// List share outbox (proposals sent)
        Outbox,
        /// Approve a share proposal
        Approve {
            /// Hex-encoded proposal CID
            cid: String,
        },
        /// Reject a share proposal
        Reject {
            /// Hex-encoded proposal CID
            cid: String,
            /// Reason for rejection
            #[arg(short, long)]
            reason: String,
        },
    }

    /// Bucket subcommands.
    #[derive(Subcommand, Debug)]
    pub enum BucketCommands {
        /// Create a new bucket
        New {
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
        List,
        /// Show bucket details
        Show {
            /// Bucket ID (hex)
            id: String,
        },
        /// Rename a bucket
        Rename {
            /// Bucket ID (hex)
            id: String,
            /// New name
            name: String,
        },
        /// Attach a private bucket to the cluster (makes it visible to peers)
        Attach {
            /// Bucket ID (hex)
            id: String,
        },
        /// Archive a bucket (soft-remove, data preserved)
        Archive {
            /// Bucket ID (hex)
            id: String,
            /// Reason for archival
            #[arg(short, long)]
            reason: String,
        },
        /// Bind a bucket to a cluster
        Bind {
            /// Bucket ID (hex)
            bucket_id: String,
            /// Cluster ID (hex)
            cluster_id: String,
        },
    }

    /// Agent subcommands.
    #[derive(Subcommand, Debug)]
    pub enum AgentCommands {
        /// Enroll an agent (e.g. openclaw, hermes) for API access
        Enroll {
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
        List,
        /// Show an agent's enrollment details
        Show {
            /// Agent identifier
            agent_id: String,
        },
    }

    /// Cluster role, as a validated CLI value (`admin`, `agent-host`,
    /// `auditor`, `service`). A thin clap wrapper over [`memvault_auth::Role`]
    /// (a foreign type we can't derive `ValueEnum` on) — gives `--help`
    /// listing, shell completion, and rejects typos instead of silently
    /// defaulting to agent-host.
    #[derive(Copy, Clone, Debug, clap::ValueEnum)]
    pub enum AgentRoleArg {
        AgentHost,
        Auditor,
        Service,
        Admin,
    }

    impl From<AgentRoleArg> for memvault_auth::AgentRole {
        fn from(r: AgentRoleArg) -> Self {
            match r {
                AgentRoleArg::AgentHost => Self::AgentHost,
                AgentRoleArg::Auditor => Self::Auditor,
                AgentRoleArg::Service => Self::Service,
                AgentRoleArg::Admin => Self::Admin,
            }
        }
    }

    /// Node-join role. `admin` also requests an admin attestation at join
    /// (the joiner must present a valid POP via `cluster-join --admit-as-admin`).
    #[derive(Copy, Clone, Debug, clap::ValueEnum)]
    pub enum NodeRoleArg {
        Node,
        Admin,
    }

    impl From<NodeRoleArg> for memvault_auth::NodeRole {
        fn from(r: NodeRoleArg) -> Self {
            match r {
                NodeRoleArg::Node => Self::Node,
                NodeRoleArg::Admin => Self::Admin,
            }
        }
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

    fn create_client_with_data_dir(
        store: Arc<MemvaultStore>,
        data_dir: &Path,
    ) -> Result<LocalClient> {
        create_client_with_bus(store, data_dir, Arc::new(EventBus::new(64)))
    }

    pub fn create_client_with_bus(
        store: Arc<MemvaultStore>,
        data_dir: &Path,
        event_bus: Arc<EventBus>,
    ) -> Result<LocalClient> {
        // Prefer the peer_id already persisted by a prior swarm spawn.
        // Otherwise derive it from the libp2p key file (loading / creating
        // it eagerly so the client sees a stable peer_id even when the
        // swarm hasn't been spawned yet — e.g. dx-serve dev mode where
        // the trust-tree UI reads peer_id before any P2P starts).
        //
        // Hard-fail if neither source is available: a zero peer_id would
        // silently break attestation chains and is never what we want.
        let peer_id = match store.get_local_peer_id().ok().flatten() {
            Some(pid) => pid,
            None => {
                let key_path = data_dir.join("identity").join("libp2p.key");
                let kp = load_or_generate_keypair(&key_path).map_err(|e| {
                    anyhow::anyhow!("could not derive peer_id from {key_path:?}: {e}")
                })?;
                let pid = kp.public().to_peer_id().to_bytes();
                store
                    .set_local_peer_id(&pid)
                    .map_err(|e| anyhow::anyhow!("persist peer_id: {e}"))?;
                pid
            }
        };
        // Bridge a legacy root `cluster_id` file into the store before
        // construction, so the client is built with the right cluster_id.
        // (migrate_legacy_identity_files deletes the file afterwards.)
        if store.get_local_cluster_id().ok().flatten().is_none() {
            if let Ok(hex_str) = std::fs::read_to_string(data_dir.join("cluster_id")) {
                if let Ok(bytes) = hex::decode(hex_str.trim()) {
                    if bytes.len() == 32 && bytes.iter().any(|&x| x != 0) {
                        let _ = store.set_local_cluster_id(&bytes);
                    }
                }
            }
        }
        let cluster_id = store
            .get_local_cluster_id()
            .ok()
            .flatten()
            .unwrap_or_else(|| vec![0u8; 32]);
        let client = LocalClient::open(
            store,
            Arc::new(RwLock::new(QuotaManager::new(Default::default()))),
            event_bus,
            peer_id,
            cluster_id,
        )
        .map_err(|e| anyhow::anyhow!("LocalClient::open: {e}"))?;
        // The keystore is opened by LocalClient itself (beside the
        // blockstore). Import + delete any legacy loose identity files, then
        // run the one-off redb→keystore token migration.
        client.migrate_legacy_identity_files(&data_dir.join("identity"));
        let _ = client.migrate_tokens_to_keystore();
        // Load admin signing key (enables token issuance) from the keystore.
        client.load_admin_keys_from_keystore();
        // Load the node signing key (the libp2p host key, design A-1).
        // Needed by anything that mints sigchain blocks — including
        // `enroll_remote_agent` on the non-daemon CLI path. Silent if
        // libp2p.key doesn't exist yet (genesis hasn't run, or this is
        // a fresh data_dir); callers that need it will fail later
        // with a clear error.
        if data_dir.join("identity").join("libp2p.key").exists() {
            if let Ok(node_sk) = libp2p_node_signing_key(data_dir) {
                client.set_node_signing_key(node_sk);
                // Stamp node ownership of the per-node legacy bucket now
                // that the node key is available (rebuild ran without it).
                let _ = client.ensure_legacy_bucket_node_owner();
            }
        }
        // Load the pinned AdminGenesis from the keystore so `token issue`
        // embeds it for joining peers, and so peers can verify trust.
        if let Some(pin_bytes) = client.pinned_admin_genesis_bytes_from_keystore() {
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
        // Rebuild the multi-admin key set from the chain so admitted admins
        // (and retirements) are known to this short-lived CLI client, not
        // just the seeded anchor.
        if let Some(anchor) = client
            .pinned_admin_genesis()
            .and_then(|g| ed25519_dalek::VerifyingKey::from_bytes(&g.admin_pubkey).ok())
            .or_else(|| client.admin_verifying_key())
        {
            if let Err(e) = memvault_api::sigchain::rebuild_admin_key_state(&client, &anchor) {
                tracing::warn!(error = %e, "rebuild admin key state");
            }
        }
        // Bind agent identity if `MEMVAULT_AGENT_ID` is set (the global
        // `--agent-id` flag exports it). Writes through this client get
        // signed for that agent (EnvelopeAuthorship sidecar).
        //
        // "Not enrolled" is silent: it's the expected state right
        // before `memctl agent-enroll` runs (the CLI may have
        // exported MEMVAULT_AGENT_ID from the shell), and it's also
        // expected if the user typo'd the agent id — the failure mode
        // shows up at the first write/JWT attempt and is clearer
        // there than as a warn here. Failed-to-load (file exists but
        // unreadable) IS still warned, since that's an unexpected
        // error.
        if let Ok(agent_id) = std::env::var("MEMVAULT_AGENT_ID") {
            if !agent_id.is_empty() {
                let identity_dir = data_dir.join("agents").join(&agent_id);
                if memvault_api::agent_identity::AgentIdentity::exists(&identity_dir) {
                    match memvault_api::agent_identity::AgentIdentity::load(&identity_dir) {
                        Ok(id) => client.set_agent_identity(id),
                        Err(e) => tracing::warn!(
                            error = %e,
                            "could not load agent identity at {}; running as node",
                            identity_dir.display()
                        ),
                    }
                }
            }
        }
        Ok(client)
    }

    fn create_client(store: Arc<MemvaultStore>) -> Result<LocalClient> {
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

    /// Resolve the data dir from `MEMVAULT_DATA_DIR` or the platform default.
    fn cli_data_dir() -> PathBuf {
        std::env::var("MEMVAULT_DATA_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|_| {
                dirs::data_local_dir()
                    .unwrap_or_else(|| PathBuf::from("."))
                    .join("memvault")
            })
    }

    /// Assemble the `JoinConfig` for the swarm, reading all identity from the
    /// keystore (no loose files):
    /// - `pendingtoken`: the joining peer's redemption credential.
    /// - first `adminkey:*`: the admin signing key (admin node serves joins).
    /// - `genesis`: the pinned AdminGenesis (its pubkey rejects foreign
    ///   NodeAttestations at sync ingress).
    /// - `pendingadmit`: an opt-in co-admin key to present for admission.
    /// `on_join_success` clears `pendingtoken` and, on a co-admin admission,
    /// promotes `pendingadmit` to a held `adminkey:` (activated live).
    fn build_join_config(
        data_dir: &Path,
        cluster_id: &[u8],
        keypair: &libp2p::identity::Keypair,
    ) -> Result<memvault_swarm::JoinConfig> {
        let identity_dir = data_dir.join("identity");
        let keystore = memvault_api::keystore_open::open_token_keystore(&identity_dir)
            .map_err(|e| anyhow::anyhow!("open keystore: {e}"))?;

        let pending_token = keystore
            .get(b"pendingtoken")
            .and_then(|b| String::from_utf8(b).ok())
            .map(|s| s.trim().to_string())
            .filter(|s| s.starts_with("mvjoin1:"));

        let admin_signing_key = keystore
            .keys_with_prefix(b"adminkey:")
            .into_iter()
            .next()
            .and_then(|k| keystore.get(&k))
            .filter(|b| b.len() == 32)
            .map(|b| {
                let mut seed = [0u8; 32];
                seed.copy_from_slice(&b[..32]);
                ed25519_dalek::SigningKey::from_bytes(&seed)
            });

        // Pinned admin verifying key — sync uses it to reject foreign
        // NodeAttestations BEFORE storing them.
        let pinned_admin_pubkey = keystore
            .get(b"genesis")
            .and_then(|b| serde_ipld_dagcbor::from_slice::<memvault_auth::AdminGenesis>(&b).ok())
            .filter(|g| g.verify_self_signature().is_ok())
            .map(|g| g.admin_pubkey);

        // Hard-fail: the swarm-side node pubkey MUST match the libp2p
        // identity it's serving with. A zero pubkey would silently break
        // both incoming joins (PeerIdMismatch refusals) and outgoing
        // joins (admin can't verify our key).
        let node_pubkey: [u8; 32] = keypair
            .public()
            .try_into_ed25519()
            .map_err(|e| anyhow::anyhow!("libp2p keypair is not ed25519: {e}"))?
            .to_bytes();

        let mut cluster_arr = [0u8; 32];
        if cluster_id.len() == 32 {
            cluster_arr.copy_from_slice(cluster_id);
        }

        // Opt-in co-admin join: `cluster-join --admit-as-admin` stashed a key
        // under `pendingadmit`. `send_join_request` signs a fresh POP with it;
        // the admin only mints an AdminKeyAdmission if the token allows it.
        let admit_seed: Option<[u8; 32]> = keystore
            .get(b"pendingadmit")
            .filter(|b| b.len() == 32)
            .map(|b| {
                let mut seed = [0u8; 32];
                seed.copy_from_slice(&b[..32]);
                seed
            });
        let admit_admin_key = admit_seed.map(|s| ed25519_dalek::SigningKey::from_bytes(&s));

        let ks_cb = std::sync::Arc::clone(&keystore);
        let on_join_success: std::sync::Arc<dyn Fn() + Send + Sync> =
            std::sync::Arc::new(move || {
                let _ = ks_cb.delete(b"pendingtoken");
                // On a successful admission, promote the staged admit key to a
                // held admin key in the keystore. The running client's
                // admin-key rescan (fired when the AdminKeyAdmission block
                // lands) then activates it live — no restart. Only on success;
                // a refused admission leaves `pendingadmit` untouched.
                if let Some(seed) = admit_seed {
                    let pubkey =
                        ed25519_dalek::SigningKey::from_bytes(&seed).verifying_key().to_bytes();
                    let key = format!("adminkey:{}", hex::encode(pubkey));
                    if let Err(e) = ks_cb.put(key.as_bytes(), &seed) {
                        tracing::warn!(error = %e, "could not store admitted admin key");
                    } else {
                        let _ = ks_cb.delete(b"pendingadmit");
                        tracing::info!(
                            "/join/1.0 admitted this node as co-admin; admin key activated"
                        );
                    }
                }
                tracing::info!("/join/1.0 success; cleared pending token");
            });

        Ok(memvault_swarm::JoinConfig {
            pending_token,
            node_pubkey,
            admin_signing_key,
            pinned_admin_pubkey,
            cluster_id: cluster_arr,
            admit_admin_key,
            keystore: Some(keystore),
            on_join_success: Some(on_join_success),
        })
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

        // cluster_id is authoritative in the store (create_client* imported
        // any legacy file before this spawn).
        let cluster_id = store
            .get_local_cluster_id()?
            .unwrap_or_else(|| vec![0u8; 32]);

        let sync_config = memvault_swarm::SyncConfig {
            cluster_id: cluster_id.clone(),
            ..Default::default()
        };

        let join_config = build_join_config(&data_dir, &cluster_id, &keypair)?;

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
                    memvault_swarm::run_sync_loop(
                        &mut swarm,
                        store,
                        head_rx,
                        sync_config,
                        join_config,
                    )
                    .await;
                });
            })?;

        Ok(handle)
    }

    /// Load a libp2p Ed25519 keypair from disk, or generate and save a new one.
    ///
    /// Stores the 32-byte Ed25519 secret seed (not the 64-byte expanded keypair)
    /// so that `Keypair::ed25519_from_bytes` can reload it.
    /// Extract the 32-byte ed25519 seed from `<data_dir>/identity/libp2p.key`
    /// and return it as an `ed25519_dalek::SigningKey` — the daemon's
    /// cluster-node signing key. Same bytes as the libp2p host key, so
    /// the pubkey `bootstrap_cluster_trust` keys trust state by is the
    /// same pubkey the JoinRequest carries.
    pub fn libp2p_node_signing_key(data_dir: &Path) -> Result<ed25519_dalek::SigningKey> {
        let key_path = data_dir.join("identity").join("libp2p.key");
        let mut key_bytes = std::fs::read(&key_path)
            .map_err(|e| anyhow::anyhow!("read {}: {e}", key_path.display()))?;
        // `load_or_generate_keypair` accepts both 32-byte seed-only files
        // and 64-byte seed+public files — mirror that here.
        if key_bytes.len() == 64 {
            key_bytes.truncate(32);
        }
        let seed: [u8; 32] = key_bytes
            .try_into()
            .map_err(|_| anyhow::anyhow!("libp2p.key must contain a 32-byte seed"))?;
        Ok(ed25519_dalek::SigningKey::from_bytes(&seed))
    }

    /// Resolve the target bucket for a bucket-aware command. Hard-fails
    /// when no bucket can be determined — writes don't get to "go
    /// nowhere", even pre-genesis. (`LocalClient::require_bucket` does
    /// have a pre-genesis carve-out for legacy adoption, but at the
    /// memctl level we expect the operator to specify or bind one.)
    ///
    /// Order (we deliberately do NOT auto-pick "first existing bucket"):
    ///   1. `MEMVAULT_BUCKET_ID` env var, set by the global `--bucket-id`
    ///      flag — explicit user choice always wins.
    ///   2. The bound agent's own bucket when an agent is loaded on
    ///      the client (auto-created via `ensure_agent_bucket_for`).
    pub async fn resolve_target_bucket(
        client: &LocalClient,
    ) -> Result<memvault_core::BucketId> {
        if let Ok(hex_str) = std::env::var("MEMVAULT_BUCKET_ID") {
            if !hex_str.is_empty() {
                let bytes = hex::decode(hex_str.trim())
                    .map_err(|e| anyhow::anyhow!("--bucket-id is not valid hex: {e}"))?;
                let arr: [u8; 32] = bytes
                    .try_into()
                    .map_err(|_| anyhow::anyhow!("--bucket-id must decode to 32 bytes"))?;
                return Ok(memvault_core::BucketId(arr));
            }
        }
        if let Some(aid) = client.agent_id().cloned() {
            return Ok(client.ensure_agent_bucket_for(&aid).await?);
        }
        anyhow::bail!(
            "no bucket selected: pass --bucket-id <hex> or --agent-id <id> \
             (or set MEMVAULT_BUCKET_ID / MEMVAULT_AGENT_ID)"
        );
    }

    pub fn load_or_generate_keypair(key_path: &Path) -> Result<libp2p::identity::Keypair> {
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

    fn parse_doc_id(hex_str: &str) -> Result<DocId> {
        let bytes = hex::decode(hex_str)
            .map_err(|e| anyhow::anyhow!("invalid hex for doc_id: {e}"))?;
        if bytes.len() != 32 {
            return Err(anyhow::anyhow!(
                "doc_id must be 32 bytes (64 hex chars), got {}",
                bytes.len()
            ));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(DocId(arr))
    }

    fn parse_bucket_id(hex_str: &str) -> Result<memvault_core::BucketId> {
        let bytes = hex::decode(hex_str)
            .map_err(|e| anyhow::anyhow!("invalid hex for bucket_id: {e}"))?;
        if bytes.len() != 32 {
            return Err(anyhow::anyhow!(
                "bucket_id must be 32 bytes (64 hex chars), got {}",
                bytes.len()
            ));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(memvault_core::BucketId(arr))
    }

    /// Run the memctl CLI with the given parsed arguments.
    pub async fn run(cli: Cli) -> Result<()> {
        let data_dir = cli.data_dir.unwrap_or_else(default_data_dir);
        let client_args = cli.client;

        // Bridge the global `--agent-id` and `--bucket-id` flags to
        // helpers that live a few layers down and are also called from
        // non-CLI contexts. Setting the env vars here means every
        // `create_client*` and bucket-resolving call below this point
        // picks up the values without each match arm threading them.
        if let Some(ref id) = cli.agent_id {
            // SAFETY: single-threaded at this point — run() is called once
            // from main before any tokio task spawning that reads env.
            unsafe {
                std::env::set_var("MEMVAULT_AGENT_ID", id);
            }
        }
        if let Some(ref b) = cli.bucket_id {
            unsafe {
                std::env::set_var("MEMVAULT_BUCKET_ID", b);
            }
        }

        // For commands that need direct store access (RepairIndex, etc.),
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
                std::fs::create_dir_all(data_dir.join("identity"))?;
                std::fs::create_dir_all(data_dir.join("trust"))?;

                let store = make_store()?;
                store.set_local_cluster_id(&cluster_id.0)?;

                // Generate the admin signing key and self-sign the cluster's
                // AdminGenesis (root of trust). Both are persisted into the
                // keystore below via the client — no loose identity files.
                let mut seed = [0u8; 32];
                rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut seed);
                let admin_sk = ed25519_dalek::SigningKey::from_bytes(&seed);
                let now_ns = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_nanos() as u64)
                    .unwrap_or(0);
                let genesis =
                    memvault_auth::sign_admin_genesis(&admin_sk, cluster_id.clone(), now_ns)?;

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

                // Persist identity into the keystore (the intended store) via
                // a client: construction records peer_id + cluster_id; the
                // setters persist the admin key + genesis. No loose files.
                let client = create_client_with_data_dir(store, &data_dir)?;
                client.set_admin_signing_key(admin_sk);
                client.set_pinned_admin_genesis(genesis);

                println!("Cluster genesis complete.");
                println!("  Cluster ID:      {id_hex}");
                println!("  Data dir:        {}", data_dir.display());
                if let Some(key_path) = admin_key {
                    println!("  Admin key arg:   {} (ignored; key generated)", key_path.display());
                }
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
                let client = create_client(store)?;
                let tags = memvault_api::docs::parse_tags(&tag);
                let vis = memvault_api::docs::parse_visibility(Some(&visibility));
                let bucket = resolve_target_bucket(&client).await?;
                let result = memvault_api::docs::create_doc(
                    &client,
                    &text,
                    title.as_deref(),
                    None,
                    tags,
                    vis,
                    None,
                    Some(&bucket),
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
                let client = create_client(store)?;
                let hits = client.search(&query, limit).await?;
                for hit in hits {
                    println!("{} (score: {:.2})", hex::encode(hit.doc_id.0), hit.score);
                    println!("  {}", hit.snippet.chars().take(80).collect::<String>());
                    println!();
                }
            }
            Commands::List { limit, scope } => {
                let store = make_store()?;
                let client = create_client(store)?;
                let tag_filter = scope.map(|s| (s, "*".to_string()));
                let docs = client.list_docs(tag_filter, limit, None).await?;
                for doc in docs {
                    let title = doc.title.unwrap_or_else(|| "(untitled)".into());
                    println!("{} -- {}", hex::encode(&doc.cid), title);
                }
            }
            Commands::Status => {
                let store = make_store()?;
                let client = create_client(store)?;
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
                let client = create_client(store)?;
                let tombstone = client.retract(&cid_bytes, &reason).await?;
                println!("Retracted. Tombstone: {}", hex::encode(&tombstone));
            }
            Commands::Token(TokenCommands::Issue {
                agent_role,
                node_role,
                ttl,
                max_uses,
                label,
                addrs,
            }) => {
                let role: memvault_auth::TokenRole = match (agent_role, node_role) {
                    (Some(a), None) => memvault_auth::TokenRole::Agent(a.into()),
                    (None, Some(n)) => memvault_auth::TokenRole::Node(n.into()),
                    (None, None) => {
                        anyhow::bail!("specify exactly one of --agent-role or --node-role")
                    }
                    (Some(_), Some(_)) => unreachable!("clap conflicts_with"),
                };
                let admits_as_admin =
                    matches!(role, memvault_auth::TokenRole::Node(memvault_auth::NodeRole::Admin));
                // `issue_token` parses + canonicalises each --addr as a real
                // multiaddr (rejecting malformed input), so no pre-check here.
                // Keystore-only: never opens redb, so this works while the
                // daemon holds the blockstore. Identity (admin key, peer_id,
                // cluster_id, genesis) is read from the keystore, populated by
                // the daemon / a prior full memctl run / genesis.
                let ks = memvault_api::keystore_open::open_token_keystore(
                    cli_data_dir().join("identity"),
                )
                .map_err(|e| anyhow::anyhow!("open token keystore: {e}"))?;
                let admin_key = ks
                    .keys_with_prefix(b"adminkey:")
                    .into_iter()
                    .next()
                    .and_then(|k| ks.get(&k))
                    .filter(|s| s.len() == 32)
                    .map(|s| {
                        let mut a = [0u8; 32];
                        a.copy_from_slice(&s);
                        ed25519_dalek::SigningKey::from_bytes(&a)
                    })
                    .ok_or_else(|| {
                        anyhow::anyhow!(
                            "no admin key in keystore — run `memctl genesis` or start the daemon once"
                        )
                    })?;
                let peer_id = memvault_core::PeerId(ks.get(b"peerid").ok_or_else(|| {
                    anyhow::anyhow!("no node peer_id in keystore — start the daemon once")
                })?);
                let cluster_id = ks
                    .get(b"clusterid")
                    .and_then(|v| <[u8; 32]>::try_from(v).ok())
                    .map(ClusterId)
                    .ok_or_else(|| {
                        anyhow::anyhow!("no cluster_id in keystore — run genesis/join first")
                    })?;
                let genesis = ks.get(b"genesis").and_then(|b| {
                    serde_ipld_dagcbor::from_slice::<memvault_auth::AdminGenesis>(&b).ok()
                });
                let token_str = memvault_api::tokens::issue_token(
                    &peer_id, &cluster_id, &admin_key, role, ttl, max_uses, label, genesis, addrs,
                    &ks,
                )?;
                println!("{token_str}");
                if admits_as_admin {
                    println!(
                        "  NOTE: this token also admits the joiner as a cluster admin; \
                         have them run `memctl cluster-join --admit-as-admin <token>`."
                    );
                }
            }
            Commands::Token(TokenCommands::List) => {
                let ks = memvault_api::keystore_open::open_token_keystore(
                    cli_data_dir().join("identity"),
                )
                .map_err(|e| anyhow::anyhow!("open token keystore: {e}"))?;
                let tokens = memvault_api::tokens::list_tokens(&ks)?;
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
            Commands::Token(TokenCommands::Revoke { cid, reason }) => {
                let cid_bytes = hex::decode(&cid)?;
                let ks = memvault_api::keystore_open::open_token_keystore(
                    cli_data_dir().join("identity"),
                )
                .map_err(|e| anyhow::anyhow!("open token keystore: {e}"))?;
                memvault_api::tokens::revoke_token(&ks, &cid_bytes, &reason)?;
                println!("Token revoked.");
            }
            Commands::Admin(sub) => {
                run_admin(sub, make_store()?).await?;
            }
            Commands::Rotations => {
                let store = make_store()?;
                let client = create_client(store)?;
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
                let client = create_client(store)?;
                let records = client.history_of(&did).await?;
                println!("History for doc {doc_id}: {} ops", records.len());
                for r in records {
                    println!("  {} kind={:?}", hex::encode(&r.cid), r.op_kind);
                }
            }
            Commands::Doc(DocCommands::Links { doc_id }) => {
                let did = parse_doc_id(&doc_id)?;
                let store = make_store()?;
                let client = create_client(store)?;
                let links = client.doc_outlinks(&did);
                println!("Outlinks for doc {doc_id}: {} links", links.len());
                for l in links {
                    let display = l.display_text.as_deref().unwrap_or("");
                    println!(
                        "  {} [{}]{}{}",
                        l.uri,
                        format!("{:?}", l.syntax),
                        if display.is_empty() { String::new() } else { format!(" — {display}") },
                        if l.byte_span != (0, 0) {
                            format!(" @[{}..{}]", l.byte_span.0, l.byte_span.1)
                        } else {
                            String::new()
                        },
                    );
                }
            }
            Commands::Doc(DocCommands::Backlinks { node }) => {
                let Some(node_ref) = memvault_core::NodeRef::from_tag_label(&node) else {
                    return Err(anyhow::anyhow!(
                        "node must be `doc:<hex>`, `entity:<hex>`, or `file:<hex>`"
                    ));
                };
                let store = make_store()?;
                let client = create_client(store)?;
                let edges = client.doc_backlinks(&node_ref)?;
                println!("Backlinks to {node}: {} edges", edges.len());
                for (source, edge) in edges {
                    let prov = memvault_doc::link::LinkProvenance::of(&edge)
                        .map(|p| p.as_str())
                        .unwrap_or("asserted");
                    println!(
                        "  {} —[{}/{}]→ {}",
                        source,
                        edge.relation,
                        prov,
                        edge.target,
                    );
                }
            }
            Commands::Doc(DocCommands::Dangling { bucket }) => {
                let bucket_id = match bucket {
                    Some(s) => Some(parse_bucket_id(&s)?),
                    None => None,
                };
                let store = make_store()?;
                let client = create_client(store)?;
                let dangling = client.dangling_link_edges(bucket_id.as_ref())?;
                println!("Dangling links: {} entries", dangling.len());
                for (source, alias) in dangling {
                    println!("  {source} → [[{alias}]]");
                }
            }
            Commands::Doc(DocCommands::ReindexLinks { doc_id }) => {
                let store = make_store()?;
                let client = create_client(store)?;
                match doc_id {
                    Some(id_hex) => {
                        let did = parse_doc_id(&id_hex)?;
                        match client.reindex_doc_links(&did).await? {
                            Some(cid) => println!(
                                "Reindexed doc {} (head {})",
                                id_hex,
                                hex::encode(&cid)
                            ),
                            None => println!("No body to reindex for {id_hex}"),
                        }
                    }
                    None => {
                        let count = client.reindex_all_doc_links().await?;
                        println!("Reindexed {count} doc(s).");
                    }
                }
            }
            Commands::Graph(GraphCommands::Add { kind, prop }) => {
                let store = make_store()?;
                let client = create_client(store)?;
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
            Commands::Graph(GraphCommands::Link {
                source,
                target,
                relation,
                weight,
            }) => {
                let source_id = parse_entity_id(&source)?;
                let target_id = parse_entity_id(&target)?;
                let store = make_store()?;
                let client = create_client(store)?;
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
            Commands::Graph(GraphCommands::Query {
                from,
                relation,
                max_depth,
            }) => {
                let entity_id = parse_entity_id(&from)?;
                let store = make_store()?;
                let client = create_client(store)?;
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
                let client = create_client(store.clone())?;
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
            Commands::Share(ShareCommands::Inbox) => {
                let client = connect().connect().await?;
                let proposals = client.share_inbox().await?;
                if proposals.is_empty() {
                    println!("No pending share proposals.");
                }
                for cid in proposals {
                    println!("{}", hex::encode(&cid));
                }
            }
            Commands::Share(ShareCommands::Outbox) => {
                let client = connect().connect().await?;
                let proposals = client.share_outbox().await?;
                if proposals.is_empty() {
                    println!("No outbound share proposals.");
                }
                for cid in proposals {
                    println!("{}", hex::encode(&cid));
                }
            }
            Commands::Share(ShareCommands::Approve { cid }) => {
                let cid_bytes = hex::decode(&cid)?;
                let client = connect().connect().await?;
                client.share_decide(&cid_bytes, true, None).await?;
                println!("Share proposal approved.");
            }
            Commands::Share(ShareCommands::Reject { cid, reason }) => {
                let cid_bytes = hex::decode(&cid)?;
                let client = connect().connect().await?;
                client
                    .share_decide(&cid_bytes, false, Some(&reason))
                    .await?;
                println!("Share proposal rejected.");
            }
            Commands::Bucket(BucketCommands::New {
                name,
                desc,
                visibility,
                classification,
            }) => {
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
            Commands::Bucket(BucketCommands::List) => {
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
            Commands::Bucket(BucketCommands::Show { id }) => {
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
            Commands::Bucket(BucketCommands::Rename { id, name }) => {
                let bucket_bytes = hex::decode(&id)?;
                let bucket_arr: [u8; 32] = bucket_bytes
                    .try_into()
                    .map_err(|_| anyhow::anyhow!("bucket id must be 32 bytes"))?;
                let bucket_id = memvault_core::BucketId(bucket_arr);
                let client = connect().connect().await?;
                client.bucket_rename(&bucket_id, &name).await?;
                println!("Bucket renamed to '{name}'.");
            }
            Commands::Bucket(BucketCommands::Attach { id }) => {
                let bucket_bytes = hex::decode(&id)?;
                let bucket_arr: [u8; 32] = bucket_bytes
                    .try_into()
                    .map_err(|_| anyhow::anyhow!("bucket id must be 32 bytes"))?;
                let bucket_id = memvault_core::BucketId(bucket_arr);
                let client = connect().connect().await?;
                client.bucket_attach(&bucket_id).await?;
                println!("Bucket attached to cluster.");
            }
            Commands::Bucket(BucketCommands::Archive { id, reason }) => {
                let bucket_bytes = hex::decode(&id)?;
                let bucket_arr: [u8; 32] = bucket_bytes
                    .try_into()
                    .map_err(|_| anyhow::anyhow!("bucket id must be 32 bytes"))?;
                let bucket_id = memvault_core::BucketId(bucket_arr);
                let client = connect().connect().await?;
                client.bucket_archive(&bucket_id, &reason).await?;
                println!("Bucket archived: {reason}");
            }
            Commands::Bucket(BucketCommands::Bind {
                bucket_id,
                cluster_id,
            }) => {
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

                let event_bus_shared = std::sync::Arc::new(EventBus::new(256));
                let client = create_client_with_bus(
                    store.clone(),
                    &data_dir,
                    std::sync::Arc::clone(&event_bus_shared),
                )?;

                // cluster_id is authoritative in the store after the client
                // build (which imports any legacy cluster_id file).
                let cluster_id_bytes = store
                    .get_local_cluster_id()?
                    .unwrap_or_else(|| vec![0u8; 32]);

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
                    // Design A-1: node signing key == libp2p host key.
                    // Pulling the seed from the same `libp2p.key` file the
                    // swarm uses guarantees that the pubkey
                    // `bootstrap_cluster_trust` keys trust state by matches
                    // the pubkey the JoinRequest carries — otherwise admin
                    // mints a NodeAttestation for libp2p_pk but bootstrap
                    // looks for node_pk and the local node stays PreGenesis
                    // (regression test:
                    // `tests::join_protocol::node_key_and_libp2p_key_must_be_the_same`).
                    let node_sk = libp2p_node_signing_key(&data_dir)
                        .map_err(|e| anyhow::anyhow!("node signing key: {e}"))?;
                    client.set_node_signing_key(node_sk);
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
                        agent_attestation_lookup: None,
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

                    // Build join_config BEFORE the keypair is moved into the swarm.
                    let join_config =
                        build_join_config(&data_dir, &cluster_id_bytes, &keypair)?;

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
                    memvault_swarm::run_sync_loop(
                        &mut swarm,
                        store,
                        head_rx,
                        sync_config,
                        join_config,
                    )
                    .await;
                }

                // Without the daemon feature, run P2P only (no web UI)
                #[cfg(not(feature = "daemon"))]
                {
                    let join_config =
                        build_join_config(&data_dir, &cluster_id_bytes, &keypair)?;
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
                    memvault_swarm::run_sync_loop(
                        &mut swarm,
                        store,
                        head_rx,
                        sync_config,
                        join_config,
                    )
                    .await;
                }
            }
            Commands::ClusterJoin {
                token,
                admit_as_admin,
            } => {
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
                std::fs::create_dir_all(data_dir.join("identity"))?;

                let rebound = store.bind_unbound_buckets(&cluster_id.0)?;
                if rebound > 0 {
                    println!("Rebound {rebound} existing bucket(s) to cluster.");
                }

                // Persist trust into the keystore (no loose files): construct
                // a client (records peer_id + cluster_id), pin the genesis,
                // and stash the pending token there for the swarm to redeem.
                let client = create_client_with_data_dir(store, &data_dir)?;
                client.set_pinned_admin_genesis(genesis.clone());
                client
                    .keystore()
                    .put(b"pendingtoken", token.as_bytes())
                    .map_err(|e| anyhow::anyhow!("stash pending token: {e}"))?;
                println!("  Admin pinned:  {}", hex::encode(genesis.admin_pubkey));
                println!("  Token stashed in keystore (redeemed via /join/1.0).");

                // NOTE: do NOT mint a local admin key here. Peers are not
                // admins — unless the operator asked for co-admin admission.
                if admit_as_admin {
                    if !parsed.admits_as_admin() {
                        println!(
                            "  WARNING: this token was not issued as --node-role admin; \
                             the admin will refuse the admission and attest you as a normal node."
                        );
                    }
                    let mut seed = [0u8; 32];
                    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut seed);
                    let sk = ed25519_dalek::SigningKey::from_bytes(&seed);
                    client
                        .keystore()
                        .put(b"pendingadmit", &seed)
                        .map_err(|e| anyhow::anyhow!("stash pending admit key: {e}"))?;
                    println!(
                        "  Admin key staged in keystore (pubkey {}); activated live on a \
                         successful join.",
                        hex::encode(sk.verifying_key().to_bytes())
                    );
                }

                println!("Joined cluster {cluster_hex}");
                println!("  Data dir:  {}", data_dir.display());
            }
            Commands::NodeAttest { peer_pubkey } => {
                let pk_bytes = hex::decode(&peer_pubkey)
                    .map_err(|e| anyhow::anyhow!("decode peer_pubkey hex: {e}"))?;
                let pk_arr: [u8; 32] = pk_bytes
                    .try_into()
                    .map_err(|_| anyhow::anyhow!("peer_pubkey must be 32 bytes"))?;
                let store = make_store()?;
                let client = create_client(store)?;
                let cid = client
                    .attest_node(pk_arr)
                    .map_err(|e| anyhow::anyhow!("attest_node: {e}"))?;
                println!("Attested peer {peer_pubkey}");
                println!("  Attestation CID: {}", hex::encode(&cid));
                println!("  The peer's pre-genesis status will clear once this block syncs over.");
            }
            Commands::Agent(AgentCommands::Enroll {
                token,
                agent_id,
                identity_dir,
            }) => {
                // Identity dir layout: `<data-dir>/agents/<agent-id>/`
                // unless explicitly overridden.
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

                // Generate the agent's keypair locally — the private key
                // never leaves this host.
                let mut agent_seed = [0u8; 32];
                rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut agent_seed);
                let agent_sk = ed25519_dalek::SigningKey::from_bytes(&agent_seed);
                let agent_pubkey = agent_sk.verifying_key().to_bytes();

                // Delegate to the same helper the HTTP endpoint uses:
                // verifies the token signature against the admin pubkey
                // held on this client, enforces max_uses, mints the
                // node-signed AgentAttestation, publishes to sigchain,
                // and records token consumption. The previous CLI path
                // bypassed all of these (and would even mint a fresh
                // admin key if none was on disk — a security hole this
                // closes).
                let store = make_store()?;
                let client = create_client(store)?;
                let result = memvault_api::agent_identity::enroll_remote_agent(
                    &client,
                    &token,
                    &agent_id,
                    agent_pubkey,
                )
                .map_err(|e| anyhow::anyhow!("enrollment failed: {e}"))?;

                // Persist the identity dir via the canonical writer.
                // The attestation is already on the chain (verifiers
                // look it up by agent_pubkey) — caching it locally is
                // for back-compat with `AgentIdentity::load` callers
                // that read attestation.cbor directly.
                std::fs::create_dir_all(&identity_dir)?;
                memvault_api::agent_identity::write_identity_dir(&identity_dir, &agent_sk)
                    .map_err(|e| anyhow::anyhow!("write identity dir: {e}"))?;

                println!("Agent enrolled successfully.");
                // Ensure the agent's default data bucket — only for AgentHost
                // agents (writers). Auditor / Service / Admin agents don't get
                // an auto-created data bucket.
                if result.attestation.role == memvault_auth::AgentRole::AgentHost {
                    let bucket = client
                        .ensure_agent_bucket_for_pubkey(&agent_pubkey, &agent_id)
                        .await
                        .map_err(|e| anyhow::anyhow!("ensure agent bucket: {e}"))?;
                    println!("  Bucket:       {}", hex::encode(bucket.0));
                }
                println!("  Agent ID:     {agent_id}");
                println!("  Cluster:      {}", hex::encode(client.cluster_id()));
                println!("  Identity dir: {}", identity_dir.display());
                println!("  Public key:   {}", hex::encode(agent_pubkey));
                println!("  Attestation:  {}", hex::encode(&result.attestation_cid));
            }
            Commands::Agent(AgentCommands::List) => {
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
                                    "{} pubkey={}",
                                    id.agent_id.0,
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
            Commands::Agent(AgentCommands::Show { agent_id }) => {
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
                println!(
                    "  Public key:   {}",
                    hex::encode(id.verifying_key.as_bytes())
                );
                println!("  Identity dir: {}", agent_dir.display());
                println!(
                    "  (attestation / role / expiry live on the sigchain — \
                     fetch via `memctl audit --kind agent-attestation` or \
                     the web trust-tree)"
                );
            }
            Commands::Seed {
                docs,
                entities,
                files,
                links,
            } => {
                let store = make_store()?;
                let client = create_client(store)?;
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

    /// Write a 32-byte secret atomically with 0600 perms (Unix), so it is
    /// never momentarily world/group-readable (no create-then-chmod TOCTOU).
    fn write_secret_file(path: &Path, bytes: &[u8]) -> Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        #[cfg(unix)]
        {
            use std::io::Write;
            use std::os::unix::fs::OpenOptionsExt;
            let mut f = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(path)
                .map_err(|e| anyhow::anyhow!("create secret {path:?}: {e}"))?;
            f.write_all(bytes)
                .map_err(|e| anyhow::anyhow!("write secret {path:?}: {e}"))?;
        }
        #[cfg(not(unix))]
        {
            std::fs::write(path, bytes)
                .map_err(|e| anyhow::anyhow!("write secret {path:?}: {e}"))?;
        }
        Ok(())
    }

    fn read_admin_seed(path: &Path) -> Result<ed25519_dalek::SigningKey> {
        let bytes = std::fs::read(path)
            .map_err(|e| anyhow::anyhow!("read admin key {path:?}: {e}"))?;
        if bytes.len() < 32 {
            anyhow::bail!("admin key file {path:?} is too short (need 32 bytes)");
        }
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&bytes[..32]);
        Ok(ed25519_dalek::SigningKey::from_bytes(&seed))
    }

    fn parse_hex32(s: &str, what: &str) -> Result<[u8; 32]> {
        let v = hex::decode(s).map_err(|e| anyhow::anyhow!("{what} not hex: {e}"))?;
        v.as_slice()
            .try_into()
            .map_err(|_| anyhow::anyhow!("{what} must be 32 bytes (64 hex chars)"))
    }

    async fn run_admin(sub: AdminCommands, store: Arc<MemvaultStore>) -> Result<()> {
        match sub {
            AdminCommands::GenKey { out } => {
                use rand::RngCore;
                let mut seed = [0u8; 32];
                rand::thread_rng().fill_bytes(&mut seed);
                let sk = ed25519_dalek::SigningKey::from_bytes(&seed);
                write_secret_file(&out, &seed)?;
                println!("admin pubkey: {}", hex::encode(sk.verifying_key().to_bytes()));
                println!("seed written to {out:?} (0600, keep it secret)");
            }
            AdminCommands::Pop { key, ttl } => {
                let sk = read_admin_seed(&key)?;
                let cluster_bytes = store
                    .get_local_cluster_id()
                    .ok()
                    .flatten()
                    .ok_or_else(|| anyhow::anyhow!("no local cluster id; run genesis/join first"))?;
                let cluster = memvault_core::ClusterId(parse_hex32(
                    &hex::encode(&cluster_bytes),
                    "cluster_id",
                )?);
                let pop_not_after_ns = memvault_core::wall_ns()
                    .saturating_add(ttl.saturating_mul(1_000_000_000));
                let pop = memvault_auth::sign_admin_pop(&sk, &cluster, pop_not_after_ns);
                println!("pubkey:           {}", hex::encode(sk.verifying_key().to_bytes()));
                println!("pop:              {}", hex::encode(pop));
                println!("pop_not_after_ns: {pop_not_after_ns}");
            }
            AdminCommands::Admit {
                new_pubkey,
                pop,
                pop_not_after_ns,
            } => {
                let new_pk = parse_hex32(&new_pubkey, "new_pubkey")?;
                let pop_bytes = hex::decode(&pop)
                    .map_err(|e| anyhow::anyhow!("pop not hex: {e}"))?;
                let pop_arr: [u8; 64] = pop_bytes
                    .as_slice()
                    .try_into()
                    .map_err(|_| anyhow::anyhow!("pop must be 64 bytes (128 hex chars)"))?;
                let client = create_client(store)?;
                let cid = client
                    .admit_admin_key(new_pk, pop_arr, pop_not_after_ns, None)
                    .await?;
                println!("admin admitted (admission cid: {})", hex::encode(cid));
            }
            AdminCommands::Retire { pubkey, reason } => {
                let pk = parse_hex32(&pubkey, "pubkey")?;
                let client = create_client(store)?;
                let cid = client.retire_admin_key(pk, reason).await?;
                println!("admin retired (retirement cid: {})", hex::encode(cid));
            }
            AdminCommands::List => {
                let client = create_client(store)?;
                let state = client.admin_key_state();
                let now = memvault_core::wall_ns();
                let anchor = state.anchor;
                for (pk, v) in &state.keys {
                    let is_anchor = Some(*pk) == anchor;
                    let valid = v.valid_at(now);
                    println!(
                        "{}{} valid_from={} valid_until={} {}",
                        hex::encode(pk),
                        if is_anchor { " (anchor)" } else { "" },
                        v.valid_from_ns,
                        if v.valid_until_ns == u64::MAX {
                            "never".to_string()
                        } else {
                            v.valid_until_ns.to_string()
                        },
                        if valid { "[valid now]" } else { "[expired]" },
                    );
                }
            }
        }
        Ok(())
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
            ("html", "text/html"),
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

        // Track all created node refs for linking later. Created in order
        // so docs/files can embed memvault:// references to already-existing
        // entities and earlier docs — this exercises the link reconciler
        // end-to-end alongside operator-asserted edges below.
        let mut all_nodes: Vec<NodeRef> = Vec::new();
        let mut entity_ids: Vec<EntityId> = Vec::new();
        let mut doc_ids: Vec<DocId> = Vec::new();
        // Aliases we expose so wikilinks like `[[Alice]]` resolve via the
        // alias index (entity.props["name"] is what AliasIndex picks up).
        let mut entity_aliases: Vec<String> = Vec::new();
        let allowlisted_relations = ["mentions", "cites", "embeds", "replies-to"];

        // ── Entities (first, so docs/files can link to them) ────────────
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
            props.insert("name".to_string(), serde_json::json!(name.clone()));
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
            all_nodes.push(NodeRef::Entity(eid.clone()));
            entity_ids.push(eid);
            entity_aliases.push(name);
            if (i + 1) % 10 == 0 || i + 1 == n_entities {
                println!("  Entities:  {}/{}", i + 1, n_entities);
            }
        }

        // ── Documents — some bodies embed [[wikilinks]] / markdown links /
        //    `[[Alias]]` references to entities so the link reconciler
        //    populates body-provenance graph edges. ─────────────────────
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

            // Sprinkle memvault links so the reconciler has work to do.
            // 60% of docs reference 1–3 prior nodes via mixed syntaxes.
            if rng.gen_bool(0.6) {
                let n_refs: usize = rng.gen_range(1..4);
                body.push_str("\n## References\n");
                for _ in 0..n_refs {
                    let roll = rng.gen_range(0..4);
                    match roll {
                        // [[doc:hex]] wikilink
                        0 if !doc_ids.is_empty() => {
                            let tgt = &doc_ids[rng.gen_range(0..doc_ids.len())];
                            body.push_str(&format!(
                                "- See [[doc:{}]] for related notes.\n",
                                hex::encode(tgt.0)
                            ));
                        }
                        // [[entity:hex|alias]] wikilink, demoted/kept rel
                        1 if !entity_ids.is_empty() => {
                            let idx = rng.gen_range(0..entity_ids.len());
                            let tgt = &entity_ids[idx];
                            let alias = &entity_aliases[idx];
                            body.push_str(&format!(
                                "- Owned by [[entity:{}|{}]].\n",
                                hex::encode(tgt.0),
                                alias
                            ));
                        }
                        // [Alice](memvault://entity/hex?rel=cites) markdown link
                        2 if !entity_ids.is_empty() => {
                            let idx = rng.gen_range(0..entity_ids.len());
                            let tgt = &entity_ids[idx];
                            let alias = &entity_aliases[idx];
                            let rel = allowlisted_relations
                                [rng.gen_range(0..allowlisted_relations.len())];
                            body.push_str(&format!(
                                "- Per [{}](memvault://entity/{}?rel={}).\n",
                                alias,
                                hex::encode(tgt.0),
                                rel,
                            ));
                        }
                        // bare-alias [[Alice]] (relies on alias index)
                        _ if !entity_aliases.is_empty() => {
                            let alias =
                                &entity_aliases[rng.gen_range(0..entity_aliases.len())];
                            body.push_str(&format!("- Coordinated with [[{alias}]].\n"));
                        }
                        _ => {}
                    }
                }
            }

            let mut fm = BTreeMap::new();
            fm.insert(
                "title".to_string(),
                serde_json::Value::String(title.clone()),
            );
            // 25% of docs declare frontmatter `links:` referencing earlier docs.
            if rng.gen_bool(0.25) && !doc_ids.is_empty() {
                let take: usize = rng.gen_range(1..3.min(doc_ids.len() + 1));
                let links: Vec<serde_json::Value> = (0..take)
                    .map(|_| {
                        let t = &doc_ids[rng.gen_range(0..doc_ids.len())];
                        serde_json::Value::String(format!(
                            "memvault://doc/{}",
                            hex::encode(t.0)
                        ))
                    })
                    .collect();
                fm.insert("links".to_string(), serde_json::Value::Array(links));
            }
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
            doc_ids.push(doc.id.clone());

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

        // ── Files — markdown/html variants embed memvault:// references
        //    so the extractor pipeline produces body-provenance edges
        //    out of the attachment too. ───────────────────────────────────
        for i in 0..n_files {
            let (ext, mime) = file_exts[rng.gen_range(0..file_exts.len())];
            let topic = topics[rng.gen_range(0..topics.len())];
            let filename = format!("{}-report-{}.{}", topic, rng.gen_range(1..999u32), ext);

            // Generate plausible file content. Markdown and HTML variants
            // embed memvault:// references so the extractor pipeline
            // emits body-provenance edges out of the attachment node too.
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
                "md" => {
                    let mut md = format!("# {} report\n\n", topic);
                    for _ in 0..rng.gen_range(2..5) {
                        let a = adjectives[rng.gen_range(0..adjectives.len())];
                        md.push_str(&format!("- {} {} analysis.\n", a, topic));
                    }
                    md.push_str("\n## Related\n");
                    if !doc_ids.is_empty() {
                        let t = &doc_ids[rng.gen_range(0..doc_ids.len())];
                        md.push_str(&format!(
                            "- [[doc:{}]]\n",
                            hex::encode(t.0)
                        ));
                    }
                    if !entity_ids.is_empty() {
                        let idx = rng.gen_range(0..entity_ids.len());
                        let e = &entity_ids[idx];
                        let alias = &entity_aliases[idx];
                        md.push_str(&format!(
                            "- See [{}](memvault://entity/{}?rel=cites).\n",
                            alias,
                            hex::encode(e.0),
                        ));
                    }
                    md.into_bytes()
                }
                "html" => {
                    let mut html = format!(
                        "<!doctype html><html><body><h1>{} report</h1>",
                        topic
                    );
                    for _ in 0..rng.gen_range(2..5) {
                        let a = adjectives[rng.gen_range(0..adjectives.len())];
                        html.push_str(&format!("<p>{} {} analysis.</p>", a, topic));
                    }
                    html.push_str("<h2>Related</h2><ul>");
                    if !doc_ids.is_empty() {
                        let t = &doc_ids[rng.gen_range(0..doc_ids.len())];
                        html.push_str(&format!(
                            "<li><a href=\"memvault://doc/{}\">related doc</a></li>",
                            hex::encode(t.0)
                        ));
                    }
                    if !entity_ids.is_empty() {
                        let idx = rng.gen_range(0..entity_ids.len());
                        let e = &entity_ids[idx];
                        let alias = &entity_aliases[idx];
                        html.push_str(&format!(
                            "<li><a href=\"memvault://entity/{}?rel=cites\">{}</a></li>",
                            hex::encode(e.0),
                            alias
                        ));
                    }
                    html.push_str("</ul></body></html>");
                    html.into_bytes()
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

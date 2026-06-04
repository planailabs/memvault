//! LocalClient — implements MemvaultClient directly against the store.

use std::collections::VecDeque;
use std::sync::Arc;

use async_trait::async_trait;
use tokio::sync::RwLock;

use memvault_attach::{self, AttachmentManifest};
use memvault_auth::TokenRole;
use memvault_core::{BucketId, DocId, EdgeId, EntityId, NodeRef, Visibility, cid_from_bytes};
use memvault_doc::{Document, Edge, Entity, Op, TextPatch};
use memvault_core::RetractionMode;
use memvault_query::{AuditQuery, AuditRecord, QuotaManager, SearchHit, TantivyIndex, query_audit};
use memvault_store::{EnvelopeMeta, MemvaultStore};

use crate::client::MemvaultClient;
use crate::error::{ApiError, Result};
use crate::subscription::{EventBus, MemvaultEvent};
use crate::types::{
    DocSummary, GrantInfo, NodeStatus, RotationInfo, ShareProposalInfo, TokenStatus, TraversalHit,
};

/// Generate sync + async variants of a method from a single body.
/// The body uses helper macros that the outer macro defines differently:
/// - `idx_read!()` → RwLock read guard
/// - `idx_write!()` → RwLock write guard
/// - `get_doc!(id)` → get_doc call
/// - `get_entity!(id)` → get_entity call
macro_rules! dual_impl {
    (
        $(#[$meta:meta])*
        ($sync_name:ident, $async_name:ident)
        fn(&$self:ident $(, $pname:ident : $pty:ty)*) -> $ret:ty
        $body:block
    ) => {
        $(#[$meta])*
        #[allow(unused_macros)]
        pub fn $sync_name(&$self $(, $pname: $pty)*) -> $ret {
            macro_rules! idx_read  { () => { $self.index.try_read().map_err(
                |_| crate::error::ApiError::Other("index lock".into()))? }; }
            macro_rules! idx_write { () => { $self.index.try_write().map_err(
                |_| crate::error::ApiError::Other("index lock".into()))? }; }
            macro_rules! get_doc    { ($id:expr) => { $self.get_doc_sync($id, false) }; }
            macro_rules! get_entity { ($id:expr) => { $self.get_entity_sync($id, false) }; }
            $body
        }

        $(#[$meta])*
        #[allow(unused_macros)]
        pub async fn $async_name(&$self $(, $pname: $pty)*) -> $ret {
            macro_rules! idx_read  { () => { $self.index.read().await }; }
            macro_rules! idx_write { () => { $self.index.write().await }; }
            macro_rules! get_doc    { ($id:expr) => { $self.get_doc_async($id, false).await }; }
            macro_rules! get_entity { ($id:expr) => { $self.get_entity_async($id, false).await }; }
            $body
        }
    };
}

/// Extract the target node's tag label from an EdgeAdd op.
/// Extract text from file content, catching panics from buggy extractors (e.g. pdf-extract).
/// Result of text extraction — either the text (with any discovered links)
/// or an error message to cache.
enum ExtractionResult {
    Ok {
        text: String,
        links: Vec<memvault_extract_abi::ExtractedLink>,
    },
    Failed(String),
    Unsupported,
}

/// A reconstructed node ready to be written into the Tantivy index. Produced by
/// `LocalClient::prepare_reindex` (no index lock held) and applied by
/// `flush_index` under the index write lock, so reconstruction and indexing
/// don't contend for the same lock.
enum PreparedIndex {
    Doc {
        id: DocId,
        body: String,
        title: Option<String>,
        tags: Vec<(String, String)>,
        bucket_hex: Option<String>,
    },
    Entity {
        id: EntityId,
        kind: String,
        props: std::collections::BTreeMap<String, serde_json::Value>,
        tags: Vec<(String, String)>,
        bucket_hex: Option<String>,
    },
    Attachment {
        manifest_cid: Vec<u8>,
        filename: Option<String>,
        mime: String,
        text: Option<String>,
        tags: Vec<(String, String)>,
        bucket_hex: Option<String>,
    },
}

impl PreparedIndex {
    /// Write this node into the index. `index_*` replace by node id, so
    /// re-applying an already-indexed node is idempotent.
    fn apply(self, idx: &mut TantivyIndex) {
        match self {
            PreparedIndex::Doc {
                id,
                body,
                title,
                tags,
                bucket_hex,
            } => {
                let _ = idx.index_doc(
                    &id,
                    &body,
                    title.as_deref(),
                    &tags,
                    bucket_hex.as_deref(),
                    0,
                );
            }
            PreparedIndex::Entity {
                id,
                kind,
                props,
                tags,
                bucket_hex,
            } => {
                let _ = idx.index_entity(&id, &kind, &props, &tags, bucket_hex.as_deref(), 0);
            }
            PreparedIndex::Attachment {
                manifest_cid,
                filename,
                mime,
                text,
                tags,
                bucket_hex,
            } => {
                let _ = idx.index_attachment(
                    &manifest_cid,
                    filename.as_deref(),
                    &mime,
                    text.as_deref(),
                    &tags,
                    bucket_hex.as_deref(),
                    0,
                );
            }
        }
    }
}

/// Describes the entity an extraction request is about — either an attachment
/// (immutable manifest) or a document (mutable head snapshot). Both flow
/// through the same extractor registry; only the annotation target differs.
pub enum ExtractionSource<'a> {
    Attachment {
        manifest_cid: &'a [u8],
        mime: &'a str,
        data: &'a [u8],
    },
    /// Document head — wired up by the head-change reconciler in Phase 5+.
    #[allow(dead_code)]
    Document {
        doc_id: memvault_core::DocId,
        head_cid: &'a [u8],
        mime: &'a str,
        body: &'a [u8],
    },
}

impl<'a> ExtractionSource<'a> {
    /// Annotation target string, e.g. `"file:<hex>"` or `"doc:<hex>"`.
    fn annotation_target(&self) -> String {
        match self {
            Self::Attachment { manifest_cid, .. } => {
                format!("file:{}", hex::encode(manifest_cid))
            }
            Self::Document { head_cid, .. } => format!("doc:{}", hex::encode(head_cid)),
        }
    }

    /// Bytes-for-lookup — the source CID (manifest CID or doc head CID).
    fn cache_key(&self) -> &'a [u8] {
        match self {
            Self::Attachment { manifest_cid, .. } => manifest_cid,
            Self::Document { head_cid, .. } => head_cid,
        }
    }

    fn mime(&self) -> &'a str {
        match self {
            Self::Attachment { mime, .. } | Self::Document { mime, .. } => mime,
        }
    }

    fn data(&self) -> &'a [u8] {
        match self {
            Self::Attachment { data, .. } => data,
            Self::Document { body, .. } => body,
        }
    }

    /// For attachments the canonical target uses the `"file:"` prefix; the
    /// store carries a `"attachment:"` prefixed legacy variant we also want
    /// to scan when reading.
    fn legacy_target(&self) -> Option<String> {
        match self {
            Self::Attachment { manifest_cid, .. } => {
                Some(format!("attachment:{}", hex::encode(manifest_cid)))
            }
            Self::Document { .. } => None,
        }
    }
}

/// Pick the MIME for a document body. Markdown is the default; opt-in to
/// HTML via `frontmatter.mime` (full MIME like `text/html`) or
/// `frontmatter.format` (shorthand `"html"` / `"markdown"`).
fn doc_mime_from_frontmatter(
    frontmatter: &std::collections::BTreeMap<String, serde_json::Value>,
) -> &'static str {
    let raw = frontmatter
        .get("mime")
        .and_then(|v| v.as_str())
        .or_else(|| frontmatter.get("format").and_then(|v| v.as_str()))
        .unwrap_or("");
    match raw {
        "html" | "text/html" | "application/xhtml+xml" => "text/html",
        _ => "text/markdown",
    }
}

/// Parse the `links` field of a cached extraction annotation. Returns an
/// empty Vec for legacy entries (which lack the field) or anything that
/// isn't shaped right.
fn parse_cached_links(val: Option<&serde_json::Value>) -> Vec<memvault_extract_abi::ExtractedLink> {
    use memvault_extract_abi::{ExtractedLink, LinkSyntax};
    let Some(arr) = val.and_then(|v| v.as_array()) else {
        return Vec::new();
    };
    let mut out = Vec::with_capacity(arr.len());
    for item in arr {
        let Some(uri) = item.get("uri").and_then(|v| v.as_str()) else {
            continue;
        };
        let display_text = item
            .get("display_text")
            .and_then(|v| v.as_str())
            .map(String::from);
        let span_arr = item.get("byte_span").and_then(|v| v.as_array());
        let byte_span = match span_arr {
            Some(a) if a.len() == 2 => {
                let s = a[0].as_u64().unwrap_or(0) as u32;
                let e = a[1].as_u64().unwrap_or(0) as u32;
                (s, e)
            }
            _ => (0, 0),
        };
        let syntax = match item.get("syntax").and_then(|v| v.as_str()).unwrap_or("") {
            "Wikilink" => LinkSyntax::Wikilink,
            "MarkdownLink" => LinkSyntax::MarkdownLink,
            "HtmlAnchor" => LinkSyntax::HtmlAnchor,
            "FrontmatterRef" => LinkSyntax::FrontmatterRef,
            "EmbeddedHyperlink" => LinkSyntax::EmbeddedHyperlink,
            _ => LinkSyntax::MarkdownLink,
        };
        out.push(ExtractedLink {
            uri: uri.to_string(),
            display_text,
            byte_span,
            syntax,
        });
    }
    out
}

fn safe_extract_text(data: &[u8], mime_type: &str) -> ExtractionResult {
    let registry = memvault_extract::ExtractionRegistry::with_defaults();
    if !registry.can_extract(mime_type) {
        return ExtractionResult::Unsupported;
    }
    let data = data.to_vec();
    let mime = mime_type.to_string();
    match std::panic::catch_unwind(move || {
        let registry = memvault_extract::ExtractionRegistry::with_defaults();
        registry.extract(&data, &mime, &memvault_extract::ExtractionHints::default())
    }) {
        Ok(Ok(extracted)) => ExtractionResult::Ok {
            text: extracted.text,
            links: extracted.links,
        },
        Ok(Err(e)) => {
            tracing::warn!("text extraction failed for {mime_type}: {e}");
            ExtractionResult::Failed(format!("{e}"))
        }
        Err(_) => {
            tracing::warn!("text extraction panicked for {mime_type}");
            ExtractionResult::Failed("extractor panicked".to_string())
        }
    }
}

fn op_edge_target_label(op: &Op) -> Option<String> {
    match op {
        Op::EdgeAdd { edge, .. } => Some(edge.target.tag_label()),
        _ => None,
    }
}

/// Identity bundle for a new write — returned by
/// [`LocalClient::signer_for_writes`]. The node always signs; the agent
/// additionally co-signs iff `agent_signing_key` is `Some` (i.e. an
/// `AgentIdentity` is bound).
///
/// `author` is the node's pubkey-derived peer_id, matching
/// `node_signing_key.verifying_key()` so `Signed::verify(author)` accepts.
/// `agent_attestation` and `agent_signing_key` are `Some` together — they
/// always travel as a pair.
pub(crate) struct WriteSigner<'a> {
    pub node_signing_key: &'a ed25519_dalek::SigningKey,
    pub author: memvault_core::PeerId,
    pub agent_signing_key: Option<&'a ed25519_dalek::SigningKey>,
    pub agent_attestation: Option<Vec<u8>>,
}

/// Resolved bucket-merge alias maps, rebuilt from the `bucket_merge` side
/// blocks (plus deterministic agent aliases). `alias` is the one-hop
/// `source → canonical` edge set; `members` is the flattened, transitive
/// `terminal-canonical → [all sources]` inverse. See `canonical_of`.
#[derive(Debug, Default)]
pub(crate) struct AliasMaps {
    /// One-hop edges: `source → direct canonical`.
    alias: std::collections::HashMap<[u8; 32], [u8; 32]>,
    /// Flattened inverse: `terminal canonical → [every source resolving to it]`.
    members: std::collections::HashMap<[u8; 32], Vec<[u8; 32]>>,
}

impl AliasMaps {
    /// Follow the alias chain from `b` to its terminal canonical, with a
    /// visited-set cycle guard (a cycle drops the closing edge and stops).
    fn canonical_of(&self, b: [u8; 32]) -> [u8; 32] {
        let mut cur = b;
        let mut visited = std::collections::HashSet::new();
        while let Some(&next) = self.alias.get(&cur) {
            if !visited.insert(cur) {
                break; // cycle: stop at the closing edge
            }
            if next == cur {
                break;
            }
            cur = next;
        }
        cur
    }

    /// Build the flattened `members` inverse from the one-hop `alias` map.
    fn build_members(&mut self) {
        let sources: Vec<[u8; 32]> = self.alias.keys().copied().collect();
        for s in sources {
            let term = self.canonical_of(s);
            if term != s {
                self.members.entry(term).or_default().push(s);
            }
        }
    }
}

/// LocalClient implements MemvaultClient by calling directly into the store.
pub struct LocalClient {
    store: Arc<MemvaultStore>,
    index: Arc<RwLock<TantivyIndex>>,
    quotas: Arc<RwLock<QuotaManager>>,
    event_bus: Arc<EventBus>,
    peer_id: Vec<u8>,
    cluster_id: Vec<u8>,
    /// Live trust state — `node_trust` + revocation sets + cached trusted
    /// agents — shared with the web layer's `AppState` and updated in place
    /// by the sigchain watcher. `None` on clients without an auth layer
    /// (tests, headless tooling); when `None`, `verify_envelope_authorship`
    /// reports `NoSidecar` for everything (fail-open).
    trust_state: std::sync::OnceLock<crate::sigchain::LiveTrustState>,
    /// Cluster admin pubkey of record. Established by `memctl genesis` (for
    /// the admin) or `memctl cluster-join` (for peers, extracted from the
    /// join token), and persisted in the keystore under `genesis`. The
    /// daemon loads it from the keystore at startup and installs it here.
    /// `None` until a cluster is established.
    pinned_admin_genesis: std::sync::OnceLock<memvault_auth::AdminGenesis>,
    /// Admin signing secrets this node holds, keyed by pubkey. A node is
    /// usually the genesis admin (one key) but during a founder→cluster
    /// fold or admin rotation it may transiently hold more than one. Used
    /// to *sign* admin operations.
    held_admin_keys:
        std::sync::RwLock<std::collections::HashMap<[u8; 32], ed25519_dalek::SigningKey>>,
    /// Validity windows for every admin key the cluster has ever known
    /// (anchor + admitted + rotated + retired). Used to *verify* that a
    /// signer was a cluster-valid admin at a given time. Rebuilt by
    /// `crate::sigchain::rebuild_admin_key_state` at bootstrap and on
    /// every admin envelope; seeded locally for founder/test nodes.
    admin_key_state: std::sync::RwLock<memvault_auth::AdminKeyState>,
    /// Bumped on every mutation of `admin_key_state` or `held_admin_keys`.
    /// Read by the ACL grant-signature cache to detect staleness — a
    /// cache entry computed under an older generation must be recomputed.
    admin_key_generation: std::sync::atomic::AtomicU64,
    /// Cache of grant-signature verdicts keyed by grant CID. Value is
    /// `(admin_key_generation_at_compute, verdict)`; a generation mismatch
    /// forces recompute (admin set changed). Grants are immutable, so a
    /// same-generation hit is always correct.
    grant_sig_cache: std::sync::RwLock<std::collections::HashMap<Vec<u8>, (u64, bool)>>,
    /// Bumped whenever a `BucketMergeRecord` is written locally or arrives
    /// via sync (the `bucket_merge` notifier arm in `install_sigchain_notifier`).
    /// The alias-map cache records the generation it was built under and
    /// rebuilds on mismatch — the same staleness scheme as `admin_key_generation`.
    alias_generation: std::sync::atomic::AtomicU64,
    /// Cached bucket-merge alias maps as `(generation_at_build, maps)`. A
    /// generation mismatch forces a rebuild from the `bucket_merge` side
    /// blocks (small N). See `bucket_alias_maps` / `canonical_of`.
    alias_cache: std::sync::RwLock<Option<(u64, std::sync::Arc<AliasMaps>)>>,
    /// Optional node signing key — the daemon's libp2p ed25519 private key,
    /// used to sign agent attestations and agent revocations. Distinct from
    /// the admin key on non-genesis-admin daemons. Write-once via `OnceLock`.
    node_signing_key: std::sync::OnceLock<ed25519_dalek::SigningKey>,
    /// Optional agent identity for agent-scoped operations. Write-once
    /// via `OnceLock` so it can be installed through a shared `Arc`.
    agent_identity: std::sync::OnceLock<crate::agent_identity::AgentIdentity>,
    /// Cached attestation CID for the bound agent. Populated by
    /// `enroll_local_agent` after publishing the attestation, so
    /// `signer_for_writes` can embed an inline attribution pointer
    /// without a sigchain scan per write. Empty until that runs;
    /// envelope readers fall back to author-pubkey lookup when absent.
    agent_attestation_cid_cache: std::sync::OnceLock<Vec<u8>>,
    /// Lock-free, redb-bypassing store for tokens + key material (see
    /// `memvault-keystore`). **Always present** — opened from the store's
    /// own directory at construction — because it is the source of truth
    /// for tokens and key material; there is no redb fallback. A second
    /// process (memctl) can issue/list/revoke tokens against the same file
    /// while the daemon holds the blockstore.
    keystore: std::sync::Arc<memvault_keystore::KeyStore>,
    /// Optional live keystore watcher (filesystem-backed). When installed via
    /// `start_keystore_watch`, cross-process writes (e.g. a co-admin key
    /// admitted by another process) are applied to this client live. Held
    /// here so it lives as long as the client.
    keystore_watch: std::sync::OnceLock<memvault_keystore::WatchHandle>,
    start_time: std::time::Instant,
    /// Set when the Tantivy index has uncommitted writes. Writes set it instead
    /// of committing per-op; the next index read flushes one commit (batches
    /// write bursts, esp. bulk creates). The blockstore is authoritative, so a
    /// crash with uncommitted index writes is recoverable via `repair-index`.
    /// `Arc` so the store's index notifier (a `'static` closure owned by the
    /// store) can flag a flush when a synced/seeded block needs indexing.
    index_dirty: Arc<std::sync::atomic::AtomicBool>,
    /// node_ids (`doc:<hex>` / `entity:<hex>` / `file:<hex>`) whose backing
    /// blocks entered the store via a path that does **not** index inline —
    /// RBSR sync (`reindex_block`) and external seeding both go through
    /// `insert_envelope`/`reindex_block`, which only maintain redb's secondary
    /// indexes, not the Tantivy full-text index. The store's index notifier
    /// (installed by `install_sigchain_notifier`) records them here; the next
    /// `flush_index` reconstructs and indexes them, keeping the search index
    /// consistent with the authoritative blockstore. `Arc` so the notifier
    /// closure can hold it.
    reindex_pending: Arc<std::sync::Mutex<std::collections::HashSet<String>>>,
    /// When set, live writes (`put_doc`/`add_entity`/`upload_file`) defer their
    /// Tantivy commit (mark dirty) instead of committing inline — batching
    /// write bursts into fewer commits. A periodic flusher (`start_index_flusher`)
    /// plus the read-path `flush_index` land the commit. Long-running hosts
    /// (daemon, web server) enable it and run a flusher; short-lived CLI
    /// invocations leave it off so a write-then-exit process commits before it
    /// dies (otherwise the deferred write would be lost, since `load_or_rebuild`
    /// skips a non-empty index on the next start).
    defer_index_commits: std::sync::atomic::AtomicBool,
}

impl LocalClient {
    pub fn new(
        store: Arc<MemvaultStore>,
        quotas: Arc<RwLock<QuotaManager>>,
        event_bus: Arc<EventBus>,
        peer_id: Vec<u8>,
        cluster_id: Vec<u8>,
    ) -> Self {
        // The keystore lives beside the blockstore at `<dir>/identity/`.
        // Opening it here (honouring MEMVAULT_KEYSTORE_PASSPHRASE) makes it
        // a required, always-present field. A failure to open it is a fatal
        // environment problem (the same directory already holds redb).
        let keystore = crate::keystore_open::open_token_keystore(store.dir().join("identity"))
            .unwrap_or_else(|e| panic!("open token keystore beside {:?}: {e}", store.dir()));
        Self::with_keystore(store, quotas, event_bus, peer_id, cluster_id, keystore)
    }

    /// Open (or reuse) the Tantivy search index for a store. The index dir is
    /// sited next to the *redb file* (`<redb>.tantivy`), unique per store.
    ///
    /// Tantivy takes an exclusive writer lock on its directory, so two
    /// `LocalClient` handles over the *same* store (e.g. an agent-bound client
    /// built off `Arc::clone(&store)`) must share one `TantivyIndex` rather
    /// than each opening their own. A process-global registry keyed by the
    /// index dir returns the same `Arc<RwLock<TantivyIndex>>` for a given
    /// store — one physical index per store, matching reality.
    fn open_index(store: &MemvaultStore) -> Arc<RwLock<TantivyIndex>> {
        use std::collections::HashMap;
        use std::path::PathBuf;
        use std::sync::{Mutex, OnceLock};
        static REGISTRY: OnceLock<Mutex<HashMap<PathBuf, Arc<RwLock<TantivyIndex>>>>> =
            OnceLock::new();

        let dir = store.path().with_extension("tantivy");
        let registry = REGISTRY.get_or_init(|| Mutex::new(HashMap::new()));
        let mut map = registry.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(existing) = map.get(&dir) {
            return existing.clone();
        }

        // Version guard: a schema/format bump (INDEX_FORMAT_VERSION) makes an
        // existing on-disk index incompatible (stale field handles). Wipe and
        // recreate when the marker doesn't match, so the rebuild repopulates.
        let ver_file = store.path().with_extension("tantivy.version");
        let cur = memvault_query::INDEX_FORMAT_VERSION.to_string();
        let stale = std::fs::read_to_string(&ver_file)
            .map(|v| v.trim() != cur)
            .unwrap_or(false);
        if stale {
            tracing::info!("tantivy index format changed; wiping {dir:?} for rebuild");
            let _ = std::fs::remove_dir_all(&dir);
        }
        let idx = TantivyIndex::open(&dir)
            .unwrap_or_else(|e| panic!("open tantivy index at {dir:?}: {e}"));
        let _ = std::fs::write(&ver_file, &cur);
        let shared = Arc::new(RwLock::new(idx));
        map.insert(dir, shared.clone());
        shared
    }

    /// Construct with an explicitly-provided keystore (the daemon/CLI share
    /// one keystore file across in-process handles this way; tests inject a
    /// scratch keystore). Records node identity so keystore-only tooling
    /// has the issuer peer_id + cluster_id.
    pub fn with_keystore(
        store: Arc<MemvaultStore>,
        quotas: Arc<RwLock<QuotaManager>>,
        event_bus: Arc<EventBus>,
        peer_id: Vec<u8>,
        cluster_id: Vec<u8>,
        keystore: std::sync::Arc<memvault_keystore::KeyStore>,
    ) -> Self {
        let index = Self::open_index(&store);
        // Record node identity (issuer peer_id + cluster_id) so keystore-only
        // tooling can mint tokens without opening redb.
        if peer_id.iter().any(|&b| b != 0) && !keystore.contains(b"peerid") {
            let _ = keystore.put(b"peerid", &peer_id);
        }
        if cluster_id.iter().any(|&b| b != 0)
            && keystore.get(b"clusterid").as_deref() != Some(cluster_id.as_slice())
        {
            let _ = keystore.put(b"clusterid", &cluster_id);
        }

        let client = Self {
            store,
            index,
            quotas,
            event_bus,
            peer_id,
            cluster_id,
            held_admin_keys: std::sync::RwLock::new(std::collections::HashMap::new()),
            admin_key_state: std::sync::RwLock::new(memvault_auth::AdminKeyState::default()),
            admin_key_generation: std::sync::atomic::AtomicU64::new(0),
            grant_sig_cache: std::sync::RwLock::new(std::collections::HashMap::new()),
            alias_generation: std::sync::atomic::AtomicU64::new(0),
            alias_cache: std::sync::RwLock::new(None),
            node_signing_key: std::sync::OnceLock::new(),
            trust_state: std::sync::OnceLock::new(),
            pinned_admin_genesis: std::sync::OnceLock::new(),
            agent_identity: std::sync::OnceLock::new(),
            agent_attestation_cid_cache: std::sync::OnceLock::new(),
            keystore,
            keystore_watch: std::sync::OnceLock::new(),
            start_time: std::time::Instant::now(),
            index_dirty: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            reindex_pending: Arc::new(std::sync::Mutex::new(std::collections::HashSet::new())),
            defer_index_commits: std::sync::atomic::AtomicBool::new(false),
        };

        // Auto-bind any unbound buckets to the cluster (handles the case where
        // buckets were created before genesis/cluster-join, and the store is
        // now re-opened with a cluster_id).
        if client.cluster_id.iter().any(|&b| b != 0) {
            let _ = client.store.bind_unbound_buckets(&client.cluster_id);
        }

        client
    }

    /// Create a LocalClient.  This is the recommended entry point.
    ///
    /// The blockstore rebuild is intentionally **not** run here.  The rebuild
    /// re-signs migrated legacy envelopes with the node signing key, which is
    /// not available at construction time.  Running it here would bail out —
    /// and never stamp the schema version — on any store that carries legacy
    /// pre-bucket data, leaving it to retry-and-fail on every boot.  Callers
    /// load the node key and then call [`install_node_key_and_rebuild`]
    /// once, which is the correct ordering.
    ///
    /// [`install_node_key_and_rebuild`]: Self::install_node_key_and_rebuild
    pub fn open(
        store: Arc<MemvaultStore>,
        quotas: Arc<RwLock<QuotaManager>>,
        event_bus: Arc<EventBus>,
        peer_id: Vec<u8>,
        cluster_id: Vec<u8>,
    ) -> Result<Self> {
        Ok(Self::new(store, quotas, event_bus, peer_id, cluster_id))
    }

    /// Install the node signing key (when available) and then run a deferred
    /// blockstore rebuild — the correct startup ordering.
    ///
    /// The rebuild must re-sign migrated legacy envelopes with the node key,
    /// so the key has to be set *before* the rebuild runs; [`open`] defers the
    /// rebuild to this call for exactly that reason.  Pass `None` when no node
    /// key is available (pre-genesis, or a store with nothing to migrate) —
    /// the rebuild still runs and is a no-op when the schema version is
    /// already current.  A rebuild error is logged and swallowed so a degraded
    /// store still starts; the version stays un-stamped so the next boot
    /// retries.
    ///
    /// [`open`]: Self::open
    pub fn install_node_key_and_rebuild(
        &self,
        key: Option<ed25519_dalek::SigningKey>,
    ) -> Option<crate::rebuild::RebuildReport> {
        if let Some(key) = key {
            self.set_node_signing_key(key);
        }
        match self.rebuild_if_needed() {
            Ok(report) => report,
            Err(e) => {
                tracing::warn!("blockstore rebuild error: {e}");
                None
            }
        }
    }

    /// Register an admin signing secret this node holds. Idempotent per
    /// key. If the cluster's `admin_key_state` has no anchor yet (fresh
    /// node / test harness that doesn't run the full bootstrap rescan),
    /// the key is seeded as the anchor admin so the holder can
    /// immediately sign and verify grants. The authoritative state is
    /// later replaced by `set_admin_key_state` from the chain rescan.
    pub fn set_admin_signing_key(&self, key: ed25519_dalek::SigningKey) {
        let pubkey = key.verifying_key().to_bytes();
        if let Ok(mut held) = self.held_admin_keys.write() {
            held.insert(pubkey, key);
        }
        if let Ok(mut state) = self.admin_key_state.write() {
            if state.anchor.is_none() {
                *state = memvault_auth::AdminKeyState::new_with_bootstrap(pubkey, 0);
            } else if !state.keys.contains_key(&pubkey) {
                // A held key that isn't the anchor — seed it as valid so a
                // node holding a non-anchor admin key (e.g. post-rotation,
                // pre-rescan) can still operate.
                state.keys.insert(
                    pubkey,
                    memvault_auth::KeyValidity {
                        valid_from_ns: 0,
                        valid_until_ns: u64::MAX,
                        introduced_by: None,
                    },
                );
            }
        }
        self.bump_admin_key_generation();
        // Persist the secret to the keystore (encrypted at rest if a cipher
        // is configured) so it survives restart without a plaintext file.
        // Best-effort: in-memory install above is what callers rely on.
        if let Err(e) = self.persist_admin_signing_key(&pubkey) {
            tracing::warn!(error = %e, "could not persist admin key to keystore");
        }
    }

    /// Run the one-off redb→keystore token migration. Idempotent (guarded
    /// by a keystore marker). Called by the daemon/CLI on `open`.
    pub fn migrate_tokens_to_keystore(&self) -> usize {
        crate::tokens::migrate_redb_tokens(&self.store, &self.keystore).unwrap_or_else(|e| {
            tracing::warn!(error = %e, "token migration to keystore failed");
            0
        })
    }

    /// The keystore (always present — see the field docs).
    pub fn keystore(&self) -> &std::sync::Arc<memvault_keystore::KeyStore> {
        &self.keystore
    }

    /// Persist a held admin signing secret to the keystore under
    /// `adminkey:<pubkey-hex>`.
    fn persist_admin_signing_key(&self, pubkey: &[u8; 32]) -> Result<()> {
        let seed = {
            let held = self
                .held_admin_keys
                .read()
                .map_err(|_| ApiError::Other("held_admin_keys lock poisoned".into()))?;
            match held.get(pubkey) {
                Some(k) => k.to_bytes(),
                None => return Ok(()),
            }
        };
        let key = format!("adminkey:{}", hex::encode(pubkey));
        self.keystore
            .put(key.as_bytes(), &seed)
            .map_err(|e| ApiError::Other(format!("keystore put admin key: {e}")))?;
        Ok(())
    }

    /// Load every admin signing secret persisted in the keystore and install
    /// it in memory. Returns the count loaded. Called by the daemon at
    /// startup before the chain rescan. No-op without a keystore.
    pub fn load_admin_keys_from_keystore(&self) -> usize {
        let mut n = 0;
        for k in self.keystore.keys_with_prefix(b"adminkey:") {
            if let Some(seed) = self.keystore.get(&k) {
                if seed.len() == 32 {
                    let mut s = [0u8; 32];
                    s.copy_from_slice(&seed);
                    // set_admin_signing_key re-persists (idempotent put) and
                    // installs in memory + seeds the key state.
                    self.set_admin_signing_key(ed25519_dalek::SigningKey::from_bytes(&s));
                    n += 1;
                }
            }
        }
        n
    }

    /// Persist the pinned cluster `AdminGenesis` (CBOR bytes) under `genesis`.
    pub fn persist_pinned_admin_genesis_bytes(&self, cbor: &[u8]) -> Result<()> {
        self.keystore
            .put(b"genesis", cbor)
            .map_err(|e| ApiError::Other(format!("keystore put genesis: {e}")))
    }

    /// The pinned `AdminGenesis` CBOR bytes from the keystore, if present.
    pub fn pinned_admin_genesis_bytes_from_keystore(&self) -> Option<Vec<u8>> {
        self.keystore.get(b"genesis")
    }

    /// Whether a join-token CID is revoked (keystore is authoritative).
    pub fn token_is_revoked(&self, cid: &[u8]) -> bool {
        crate::tokens::token_revoked(&self.keystore, cid)
    }

    /// How many times a join token has been consumed (keystore authoritative).
    pub fn token_consumption_count(&self, cid: &[u8]) -> u32 {
        crate::tokens::token_consumed(&self.keystore, cid)
    }

    /// Record one consumption of a join token, returning the new count. Uses
    /// the keystore's atomic counter (cross-process safe, preserves
    /// `max_uses`). The `consumer`/`at_ns` audit detail is not retained.
    pub fn record_token_consumption(&self, cid: &[u8], _consumer: &[u8], _at_ns: u64) -> u32 {
        self.keystore
            .fetch_add_u32(&crate::tokens::token_used_key(cid), 1)
            .unwrap_or(0)
    }

    /// Start a live filesystem watch on the keystore so changes made by other
    /// processes are applied to this running client. Currently: when an
    /// `adminkey:` entry appears/changes (e.g. a co-admin key admitted by a
    /// separate `memctl` or by the swarm thread), reload held admin secrets so
    /// the node can sign as that admin without a restart. Idempotent; the
    /// watcher lives as long as the client.
    pub fn start_keystore_watch(self: &std::sync::Arc<Self>) {
        if self.keystore_watch.get().is_some() {
            return;
        }
        let weak = std::sync::Arc::downgrade(self);
        match self.keystore.watch(move |changed| {
            if changed.iter().any(|k| k.starts_with(b"adminkey:")) {
                if let Some(c) = weak.upgrade() {
                    let n = c.load_admin_keys_from_keystore();
                    tracing::info!(count = n, "reloaded admin keys after keystore change");
                }
            }
        }) {
            Ok(h) => {
                let _ = self.keystore_watch.set(h);
            }
            Err(e) => tracing::warn!(error = %e, "could not start keystore watch"),
        }
    }

    /// One-time import of legacy loose identity files into the keystore, then
    /// delete them. Identity now lives only in the keystore (admin keys,
    /// pinned genesis) and the redb store (cluster_id); these files
    /// (`identity/admin.key`, `identity/cluster_admin_genesis.cbor`, and the
    /// root `cluster_id`) are imported once and removed. Idempotent: a node
    /// already on the keystore has no files to import. Call after the keystore
    /// + store are open (e.g. daemon init, memctl client creation).
    pub fn migrate_legacy_identity_files(&self, identity_dir: &std::path::Path) {
        // admin.key → keystore adminkey:<pubkey>
        let admin_path = identity_dir.join("admin.key");
        if let Ok(b) = std::fs::read(&admin_path) {
            if b.len() >= 32 {
                let mut s = [0u8; 32];
                s.copy_from_slice(&b[..32]);
                self.set_admin_signing_key(ed25519_dalek::SigningKey::from_bytes(&s));
            }
            let _ = std::fs::remove_file(&admin_path);
            tracing::info!("migrated admin.key into keystore");
        }

        // libp2p.key → keystore `nodesk` (design A-1: node key = libp2p key).
        // Mirrors the admin.key migration: read the loose seed, store it in the
        // keystore, delete the file. No-op when there is no loose file (e.g. the
        // production daemon, which derives its node key from the host PEM).
        let _ = crate::node_key::node_seed_from_keystore_or_file(&self.keystore, identity_dir);

        // cluster_admin_genesis.cbor → keystore `genesis`
        let gen_path = identity_dir.join("cluster_admin_genesis.cbor");
        if let Ok(b) = std::fs::read(&gen_path) {
            match serde_ipld_dagcbor::from_slice::<memvault_auth::AdminGenesis>(&b) {
                Ok(g) if g.verify_self_signature().is_ok() => {
                    let _ = self.persist_pinned_admin_genesis_bytes(&b);
                    self.set_pinned_admin_genesis(g);
                }
                _ => tracing::warn!("legacy cluster_admin_genesis.cbor invalid; not imported"),
            }
            let _ = std::fs::remove_file(&gen_path);
            tracing::info!("migrated cluster_admin_genesis into keystore");
        }

        // Root cluster_id hex file → redb store (cluster_id is not a secret;
        // it lives in the store, mirrored to the keystore at construction).
        if let Some(data_dir) = identity_dir.parent() {
            let cid_path = data_dir.join("cluster_id");
            if let Ok(hex_str) = std::fs::read_to_string(&cid_path) {
                if let Ok(bytes) = hex::decode(hex_str.trim()) {
                    if bytes.len() == 32 && bytes.iter().any(|&x| x != 0) {
                        let _ = self.store.set_local_cluster_id(&bytes);
                        if self.keystore.get(b"clusterid").as_deref() != Some(bytes.as_slice()) {
                            let _ = self.keystore.put(b"clusterid", &bytes);
                        }
                    }
                }
                let _ = std::fs::remove_file(&cid_path);
                tracing::info!("migrated cluster_id file into store");
            }
        }
    }

    /// Replace the cluster admin-key validity state wholesale. Called by
    /// the bootstrap/rescan path with chain-derived truth.
    pub fn set_admin_key_state(&self, state: memvault_auth::AdminKeyState) {
        let known: Vec<[u8; 32]> = state.keys.keys().copied().collect();
        if let Ok(mut s) = self.admin_key_state.write() {
            *s = state;
        }
        self.bump_admin_key_generation();
        // Activate any admin secret we hold in the keystore that just became
        // a known cluster key — e.g. a co-admin admission that landed live
        // over /join/1.0, so admin capability turns on without a restart.
        self.activate_held_admin_secrets(&known);
    }

    /// Load into memory any admin signing secret stored in the keystore whose
    /// pubkey is in `pubkeys` but not yet held. Does not reseed the anchor
    /// (the key is already in the rebuilt state).
    fn activate_held_admin_secrets(&self, pubkeys: &[[u8; 32]]) {
        for pk in pubkeys {
            let held = self
                .held_admin_keys
                .read()
                .map(|h| h.contains_key(pk))
                .unwrap_or(true);
            if held {
                continue;
            }
            let key = format!("adminkey:{}", hex::encode(pk));
            if let Some(seed) = self.keystore.get(key.as_bytes()) {
                if seed.len() == 32 {
                    let mut s = [0u8; 32];
                    s.copy_from_slice(&seed);
                    if let Ok(mut h) = self.held_admin_keys.write() {
                        h.insert(*pk, ed25519_dalek::SigningKey::from_bytes(&s));
                    }
                    tracing::info!(
                        pubkey = %hex::encode(pk),
                        "activated admitted admin key from keystore (no restart)"
                    );
                }
            }
        }
    }

    /// Snapshot of the current admin-key validity state.
    pub fn admin_key_state(&self) -> memvault_auth::AdminKeyState {
        self.admin_key_state
            .read()
            .map(|s| s.clone())
            .unwrap_or_default()
    }

    /// Monotonic generation counter for admin-key state. Cache layers
    /// store the value they were computed under and recompute on change.
    pub fn admin_key_generation(&self) -> u64 {
        self.admin_key_generation
            .load(std::sync::atomic::Ordering::Acquire)
    }

    fn bump_admin_key_generation(&self) {
        self.admin_key_generation
            .fetch_add(1, std::sync::atomic::Ordering::AcqRel);
        // The grant-signature cache is keyed on the admin set; drop it so
        // stale verdicts don't linger (the generation check would catch
        // them anyway, but this bounds memory).
        if let Ok(mut c) = self.grant_sig_cache.write() {
            c.clear();
        }
    }

    /// Decide whether a bucket grant's signature is acceptable, with
    /// per-CID caching keyed on the admin-key generation.
    ///
    /// Whether the grant's signature cryptographically verifies against
    /// its embedded `admin_pubkey` (the *issuer*: an admin key, a bucket
    /// owner's agent key, or that owner's attesting node key — the field
    /// keeps its historical name). This is pure signature *authenticity*,
    /// independent of *authority* (whether that issuer is allowed to grant
    /// on a given bucket — see `acl::check_bucket_access`).
    ///
    /// The verdict is immutable for a given grant CID (the signed bytes
    /// never change), so it's cached permanently. Legacy grants (all-zero
    /// `admin_pubkey`) are never authentic.
    pub fn grant_signature_authentic(
        &self,
        grant_cid: &[u8],
        grant: &memvault_auth::Grant,
    ) -> bool {
        if let Ok(cache) = self.grant_sig_cache.read() {
            if let Some((_, verdict)) = cache.get(grant_cid) {
                return *verdict;
            }
        }
        let verdict = !grant.is_legacy_unsigned() && grant.verify_admin_signature().is_ok();
        if let Ok(mut cache) = self.grant_sig_cache.write() {
            cache.insert(grant_cid.to_vec(), (0, verdict));
        }
        verdict
    }

    /// Is `issuer_pubkey` authorised to issue/revoke grants on a bucket
    /// owned by `owner_agent_pubkey`, as of `at_ns`? Three authorities:
    ///   1. a cluster-valid admin (can act on any bucket);
    ///   2. the bucket **owner**'s own agent key (self-delegation);
    ///   3. the **node that attested the owner** (host-on-behalf).
    /// Owner/attester paths require the owner agent to be a known,
    /// non-revoked agent; the attester must be a trusted, non-revoked node.
    pub fn grant_issuer_authorized(
        &self,
        issuer_pubkey: &[u8; 32],
        at_ns: u64,
        owner_agent_pubkey: Option<&[u8; 32]>,
        owner_node_pubkey: Option<&[u8; 32]>,
    ) -> bool {
        // 1. Admin authority.
        if self.is_admin_key_valid_at(issuer_pubkey, at_ns) {
            return true;
        }
        // 4. Node-owned bucket (e.g. the per-node legacy bucket): the
        // owning node, still trusted and not revoked, may delegate.
        if let Some(node_pk) = owner_node_pubkey {
            if issuer_pubkey == node_pk
                && self.is_node_trusted(node_pk)
                && !self.is_node_revoked(node_pk)
            {
                return true;
            }
        }
        let Some(owner_pk) = owner_agent_pubkey else {
            return false;
        };
        // The owner agent must currently be a known, non-revoked agent.
        if crate::sigchain::find_agent_attestation(self, owner_pk)
            .ok()
            .flatten()
            .is_none()
            || self.is_agent_revoked(owner_pk)
        {
            return false;
        }
        // 2. Owner self-delegation.
        if issuer_pubkey == owner_pk {
            return true;
        }
        // 3. Host-on-behalf: the owner's *sole* attesting node, still
        // trusted. Ambiguous attestation (two nodes) denies this path, so
        // a trusted node can't seize host authority by minting a rival
        // attestation.
        if let Ok(Some(attester)) = crate::sigchain::sole_attesting_node(self, owner_pk) {
            if *issuer_pubkey == attester
                && self.is_node_trusted(&attester)
                && !self.is_node_revoked(&attester)
            {
                return true;
            }
        }
        false
    }

    fn is_agent_revoked(&self, pubkey: &[u8; 32]) -> bool {
        self.trust_state()
            .and_then(|s| s.revoked_agents.read().ok().map(|r| r.contains(pubkey)))
            .unwrap_or(false)
    }

    fn is_node_revoked(&self, pubkey: &[u8; 32]) -> bool {
        self.trust_state()
            .and_then(|s| s.revoked_nodes.read().ok().map(|r| r.contains(pubkey)))
            .unwrap_or(false)
    }

    fn is_node_trusted(&self, pubkey: &[u8; 32]) -> bool {
        self.trust_state()
            .and_then(|s| s.node_trust.read().ok().map(|m| m.contains_key(pubkey)))
            .unwrap_or(false)
    }

    /// Whether an agent's **attesting node** is trusted to confer that
    /// agent's identity. True iff the attesting node is either:
    ///   * THIS node's own key — self-trust, covering the pre-genesis
    ///     window before an admin has attested us (the daemon's own `_ui`
    ///     admin agent must work immediately); or
    ///   * named as a cluster member by an admin-signed `NodeAttestation`
    ///     in the store.
    ///
    /// Used by ACL to reject **orphaned** agent attestations — ones signed
    /// by an ephemeral, never-attested node identity (e.g. a throwaway
    /// instance that gossiped its `_ui` Admin attestation into the cluster).
    /// Such an attestation must never confer access, not even role=Admin.
    ///
    /// Conservative: with no admin keys known yet (pre-genesis / standalone)
    /// there is nothing to attest against, so the gate is inactive and only
    /// self-trust applies — a standalone node still serves its own agents.
    pub fn is_attesting_node_trusted(&self, node_pubkey: &[u8; 32]) -> bool {
        // Self-trust.
        if self
            .node_verifying_key()
            .map(|k| k.to_bytes())
            .as_ref()
            == Some(node_pubkey)
        {
            return true;
        }
        // A revoked node never confers trust.
        if self.is_node_revoked(node_pubkey) {
            return false;
        }
        let admin_keys = self.admin_verifying_keys();
        if admin_keys.is_empty() {
            // No cluster admin context — nothing to verify attestations
            // against; don't gate (only self-trust, handled above, applies).
            return true;
        }
        // Require an admin-signed NodeAttestation naming this node.
        for cid in self
            .store
            .query_by_tag("sigchain", "node_att", 0, 1024)
            .unwrap_or_default()
        {
            let Ok(Some(bytes)) = self.store.get_block(&cid) else {
                continue;
            };
            let Ok(att) =
                serde_ipld_dagcbor::from_slice::<memvault_auth::NodeAttestation>(&bytes)
            else {
                continue;
            };
            if att.member.0.as_slice() != node_pubkey {
                continue;
            }
            if admin_keys.iter().any(|k| att.verify_signature(k).is_ok()) {
                return true;
            }
        }
        false
    }

    /// Delete orphaned agent attestation blocks — ones whose attesting node
    /// is not trusted (`is_attesting_node_trusted`: neither this node's own
    /// key nor an admin-attested cluster member). Returns the number pruned.
    ///
    /// Safe to run on a SETTLED trust view (e.g. at startup after
    /// `bootstrap_cluster_trust`): orphans are inert (never trusted, ACL- and
    /// JWT-rejected), so removing them only clears cruft. A legitimate agent
    /// whose node attestation hasn't synced yet would re-sync via RBSR, so a
    /// premature prune is self-healing rather than lossy. On a pre-genesis /
    /// standalone node (no admin keys) `is_attesting_node_trusted` returns
    /// true for everything, so nothing is pruned.
    pub fn prune_orphaned_agent_attestations(&self) -> Result<usize> {
        let mut pruned = 0usize;
        for cid in self
            .store
            // Exhaustive: prune must consider every attestation (see standards).
            .query_by_tag("sigchain", "agent_att", 0, usize::MAX)
            .unwrap_or_default()
        {
            let Ok(Some(bytes)) = self.store.get_block(&cid) else {
                continue;
            };
            let Ok(att) =
                serde_ipld_dagcbor::from_slice::<memvault_auth::AgentAttestation>(&bytes)
            else {
                continue;
            };
            if !self.is_attesting_node_trusted(&att.node_pubkey) {
                if self.store.delete_block(&cid).unwrap_or(false) {
                    pruned += 1;
                    tracing::debug!(
                        agent = %att.agent_id.0,
                        node = %hex::encode(att.node_pubkey),
                        "pruned orphaned agent attestation"
                    );
                }
            }
        }
        Ok(pruned)
    }

    /// Pick a signing key this node may legitimately use to issue or
    /// revoke grants on `bucket_id`, with the resulting signer pubkey.
    /// Tries, in order: a held cluster admin key; the held owner-agent
    /// key (when this node hosts the bucket owner); the node key for a
    /// node-owned bucket; the node key when this node attested the bucket
    /// owner (host-on-behalf). `None` if this node has no authority.
    fn pick_grant_signer(
        &self,
        bucket_id: &BucketId,
    ) -> Option<(ed25519_dalek::SigningKey, [u8; 32])> {
        let now = memvault_core::wall_ns();
        // 1. Admin.
        if let Some(admin) = self.admin_signing_key_at_ns(now) {
            let pk = admin.verifying_key().to_bytes();
            return Some((admin, pk));
        }
        let info = self.bucket_info_sync(bucket_id).ok().flatten()?;
        // 2. Held owner-agent identity (this node hosts the owner).
        if let (Some(owner_pk), Some(id)) =
            (info.owner_agent_pubkey, self.agent_identity.get())
        {
            if id.verifying_key.to_bytes() == owner_pk {
                return Some((id.signing_key.clone(), owner_pk));
            }
        }
        let node_sk = self.node_signing_key.get()?;
        let node_pk = node_sk.verifying_key().to_bytes();
        // 3. Node-owned bucket (e.g. the per-node legacy bucket).
        if info.owner_node_pubkey == Some(node_pk) {
            return Some((node_sk.clone(), node_pk));
        }
        // 4. Host-on-behalf: this node attested the owner agent.
        if let Some(owner_pk) = info.owner_agent_pubkey {
            if let Ok(Some(att)) = crate::sigchain::find_agent_attestation(self, &owner_pk) {
                if att.node_pubkey == node_pk {
                    return Some((node_sk.clone(), node_pk));
                }
            }
        }
        None
    }

    /// Stamp this node as the owner of its per-node legacy bucket, if a
    /// legacy bucket exists and isn't already node-owned. The daemon calls
    /// this once the node signing key is available (the legacy bucket is
    /// created during rebuild, before the key is set), so the node can
    /// then delegate access to its own legacy data with its node key.
    pub fn ensure_legacy_bucket_node_owner(&self) -> Result<()> {
        let Some(bucket) = self.find_legacy_bucket() else {
            return Ok(());
        };
        let Some(node_sk) = self.node_signing_key.get() else {
            return Ok(());
        };
        let node_pk = node_sk.verifying_key().to_bytes();
        if let Ok(Some(info)) = self.bucket_info_sync(&bucket) {
            if info.owner_node_pubkey == Some(node_pk) {
                return Ok(()); // already stamped
            }
        }
        // Re-emit the legacy bucket decl with owner_node_pubkey set. The
        // decl is a deterministic, content-addressed block; re-emitting
        // updates the bucket→decl pointer.
        self.create_bucket_with_id(
            bucket,
            "legacy",
            Some("auto-created for adoption of pre-bucket data"),
            Visibility::Internal,
            memvault_core::classification::Classification::Internal,
            memvault_doc::BucketRole::Legacy,
            Some(node_pk),
        )
    }

    /// True if `pubkey` was a cluster-valid admin at `time_ns`.
    pub fn is_admin_key_valid_at(&self, pubkey: &[u8; 32], time_ns: u64) -> bool {
        self.admin_key_state
            .read()
            .map(|s| s.is_key_valid_at(pubkey, time_ns))
            .unwrap_or(false)
    }

    /// Every admin verifying key the cluster has ever known (anchor +
    /// admitted + rotated + retired), as parsed `VerifyingKey`s. Node
    /// attestations / revocations are verified against this full set
    /// (they carry no issue timestamp); the anchor sorts first.
    /// Empty pre-genesis.
    pub fn admin_verifying_keys(&self) -> Vec<ed25519_dalek::VerifyingKey> {
        let state = match self.admin_key_state.read() {
            Ok(s) => s,
            Err(_) => return Vec::new(),
        };
        let mut out = Vec::with_capacity(state.keys.len());
        if let Some(anchor) = state.anchor {
            if let Ok(vk) = ed25519_dalek::VerifyingKey::from_bytes(&anchor) {
                out.push(vk);
            }
        }
        for k in state.keys.keys() {
            if Some(*k) == state.anchor {
                continue;
            }
            if let Ok(vk) = ed25519_dalek::VerifyingKey::from_bytes(k) {
                out.push(vk);
            }
        }
        // NB: local founder keys are deliberately NOT included here.
        // `admin_verifying_keys` gates node-attestation and JWT trust;
        // founder keys are a *local, grant-only* trust extension (see
        // `is_admin_key_valid_at`). Excluding them bounds the blast radius
        // of a leaked `founder_admin.key` to grant-signing on this node's
        // own private buckets — it cannot mint trusted node attestations
        // or JWTs. Pre-genesis, the founder key is the chain anchor (via
        // `set_admin_signing_key`) and is already present above through
        // `state.anchor`, so pre-genesis self-attestation still verifies.
        out
    }

    /// Ensure `anchor` is present in `admin_key_state` as the anchor admin
    /// key, without requiring the secret. Used on peer nodes that pin the
    /// admin pubkey at join but hold no admin secret, so verification has
    /// a key set to work with before the full chain rescan runs.
    pub fn seed_admin_anchor(&self, anchor: [u8; 32]) {
        if let Ok(mut state) = self.admin_key_state.write() {
            if state.anchor.is_none() {
                *state = memvault_auth::AdminKeyState::new_with_bootstrap(anchor, 0);
            } else if !state.keys.contains_key(&anchor) {
                state.keys.insert(
                    anchor,
                    memvault_auth::KeyValidity {
                        valid_from_ns: 0,
                        valid_until_ns: u64::MAX,
                        introduced_by: None,
                    },
                );
            }
        }
        self.bump_admin_key_generation();
    }

    /// Publish the live trust state on this client. Write-once.
    /// Subsequent reads via [`Self::verify_envelope_authorship`] consult it
    /// instead of returning `NoSidecar` by default.
    pub fn set_trust_state(&self, state: crate::sigchain::LiveTrustState) {
        let _ = self.trust_state.set(state);
    }

    /// Borrow the live trust state, if installed. `None` on clients that
    /// haven't gone through [`crate::bootstrap::bootstrap_cluster_trust`]
    /// (tests, headless tooling).
    pub fn trust_state(&self) -> Option<&crate::sigchain::LiveTrustState> {
        self.trust_state.get()
    }

    /// Install the cluster's pinned `AdminGenesis`. Write-once. Also mirrors
    /// it into the keystore (under `genesis`) so keystore-only tooling — e.g.
    /// `memctl token issue` with no redb/daemon running — can embed it in
    /// issued join tokens without reading a loose file.
    pub fn set_pinned_admin_genesis(&self, genesis: memvault_auth::AdminGenesis) {
        if !self.keystore.contains(b"genesis") {
            if let Ok(bytes) = serde_ipld_dagcbor::to_vec(&genesis) {
                if let Err(e) = self.persist_pinned_admin_genesis_bytes(&bytes) {
                    tracing::warn!(error = %e, "could not persist genesis to keystore");
                }
            }
        }
        let _ = self.pinned_admin_genesis.set(genesis);
    }

    fn cluster_id_arr(&self) -> Result<[u8; 32]> {
        self.cluster_id
            .clone()
            .try_into()
            .map_err(|_| ApiError::Other("cluster_id must be 32 bytes".into()))
    }

    /// Re-derive and reinstall `admin_key_state` from the chain, anchored
    /// at the pinned/known anchor. Call after publishing an admission or
    /// retirement so the local view updates without waiting for the
    /// watcher.
    fn refresh_admin_key_state(&self) -> Result<()> {
        let anchor = self
            .admin_key_state()
            .anchor
            .and_then(|a| ed25519_dalek::VerifyingKey::from_bytes(&a).ok());
        if let Some(anchor) = anchor {
            crate::sigchain::rebuild_admin_key_state(self, &anchor)?;
        }
        Ok(())
    }

    /// Admit a new co-equal admin key to the cluster (multi-admin).
    ///
    /// Signed by a held admin key that is currently valid; carries the
    /// incoming admin's proof-of-possession (`pop`, produced offline via
    /// [`memvault_auth::sign_admin_pop`]). The admission is published to
    /// the sigchain and the local admin-key state is rebuilt immediately.
    ///
    /// `valid_from_ns` defaults to now when `None`. `pop_not_after_ns` is
    /// the expiry the incoming admin bound into their POP; the admission
    /// is rejected at rebuild if it was issued after that.
    pub async fn admit_admin_key(
        &self,
        new_pubkey: [u8; 32],
        pop: [u8; 64],
        pop_not_after_ns: u64,
        valid_from_ns: Option<u64>,
    ) -> Result<Vec<u8>> {
        let now_ns = memvault_core::wall_ns();
        let admitting = self.admin_signing_key_at_ns(now_ns).ok_or_else(|| {
            ApiError::Other("no valid admin signing key — cannot admit admin".into())
        })?;
        let cluster = memvault_core::ClusterId(self.cluster_id_arr()?);

        // Verify the POP (and that it hasn't expired) before publishing —
        // fail fast on a bad/stale handoff.
        memvault_auth::verify_admin_pop(&cluster, &new_pubkey, pop_not_after_ns, &pop)
            .map_err(|e| ApiError::Other(format!("admin POP invalid: {e}")))?;
        if now_ns > pop_not_after_ns {
            return Err(ApiError::Other("admin POP has expired".into()));
        }

        let admission = memvault_auth::sign_admin_admission(
            &admitting,
            new_pubkey,
            cluster,
            valid_from_ns.unwrap_or(now_ns),
            now_ns,
            pop_not_after_ns,
            None,
            pop,
        )
        .map_err(|e| ApiError::Other(format!("sign admin admission: {e}")))?;

        let cid = crate::sigchain::publish_admin_admission(self, &admission)?;
        self.refresh_admin_key_state()?;
        tracing::info!(
            new_admin = %hex::encode(new_pubkey),
            cid = %hex::encode(&cid),
            "admin key admitted"
        );
        Ok(cid)
    }

    /// Retire an admin key. Signed by a *different* held admin key that is
    /// currently valid. Grants the retired key signed before now stay
    /// valid; it can no longer sign new operations.
    pub async fn retire_admin_key(
        &self,
        retired_pubkey: [u8; 32],
        reason: impl Into<String>,
    ) -> Result<Vec<u8>> {
        let now_ns = memvault_core::wall_ns();
        let cluster = memvault_core::ClusterId(self.cluster_id_arr()?);

        // Pick a held, currently-valid admin key that is NOT the one being
        // retired (no self-retirement).
        let retiring = {
            let held = self
                .held_admin_keys
                .read()
                .map_err(|_| ApiError::Other("held_admin_keys lock poisoned".into()))?;
            let state = self
                .admin_key_state
                .read()
                .map_err(|_| ApiError::Other("admin_key_state lock poisoned".into()))?;
            held.iter()
                .find(|(pk, _)| **pk != retired_pubkey && state.is_key_valid_at(pk, now_ns))
                .map(|(_, sk)| sk.clone())
        }
        .ok_or_else(|| {
            ApiError::Other(
                "no held admin key (other than the target) is valid — cannot retire".into(),
            )
        })?;

        // Local no-lockout pre-check (the rebuild re-checks authoritatively).
        let others_valid = self
            .admin_key_state()
            .valid_keys_at(now_ns)
            .into_iter()
            .any(|k| k != retired_pubkey);
        if !others_valid {
            return Err(ApiError::Other(
                "refusing to retire the last valid admin key (cluster lockout)".into(),
            ));
        }

        let retirement = memvault_auth::sign_admin_retirement(
            &retiring,
            retired_pubkey,
            cluster,
            now_ns,
            reason,
            None,
        )
        .map_err(|e| ApiError::Other(format!("sign admin retirement: {e}")))?;

        let cid = crate::sigchain::publish_admin_retirement(self, &retirement)?;
        self.refresh_admin_key_state()?;
        tracing::info!(
            retired = %hex::encode(retired_pubkey),
            cid = %hex::encode(&cid),
            "admin key retired"
        );
        Ok(cid)
    }

    /// Rotate the cluster admin key: admit `new_signing_key` (proof of
    /// possession generated locally since we hold it) effective now, then
    /// schedule retirement of the current signing key after an overlap
    /// window. The new key is registered as held so this node keeps admin
    /// capability across the rotation.
    pub async fn rotate_admin_key(
        &self,
        new_signing_key: ed25519_dalek::SigningKey,
        overlap_secs: u64,
    ) -> Result<Vec<u8>> {
        let now_ns = memvault_core::wall_ns();
        let cluster = memvault_core::ClusterId(self.cluster_id_arr()?);
        let old = self.admin_signing_key_at_ns(now_ns).ok_or_else(|| {
            ApiError::Other("no valid admin signing key — cannot rotate".into())
        })?;
        let old_pubkey = old.verifying_key().to_bytes();
        let new_pubkey = new_signing_key.verifying_key().to_bytes();
        if new_pubkey == old_pubkey {
            return Err(ApiError::Other("rotation target equals current key".into()));
        }

        // Admit the new key (we hold it, so generate its POP locally). The
        // POP is consumed immediately, so its expiry is now (admitted at
        // the same instant — passes the `admitted_at <= pop_not_after` check).
        let pop = memvault_auth::sign_admin_pop(&new_signing_key, &cluster, now_ns);
        let adm = memvault_auth::sign_admin_admission(
            &old, new_pubkey, cluster.clone(), now_ns, now_ns, now_ns, None, pop,
        )
        .map_err(|e| ApiError::Other(format!("sign rotation admission: {e}")))?;
        let cid = crate::sigchain::publish_admin_admission(self, &adm)?;

        // Register the new secret and rebuild so the new key is usable.
        self.set_admin_signing_key(new_signing_key);
        self.refresh_admin_key_state()?;

        // Retire the old key after the overlap window. Signed by the new
        // key (now valid). retired_at in the future keeps the old key
        // valid during overlap.
        let retired_at_ns = now_ns.saturating_add(overlap_secs.saturating_mul(1_000_000_000));
        let new_held = self
            .admin_signing_key_at_ns(now_ns)
            .ok_or_else(|| ApiError::Other("new admin key not usable after admission".into()))?;
        let ret = memvault_auth::sign_admin_retirement(
            &new_held,
            old_pubkey,
            cluster,
            retired_at_ns,
            "admin key rotation",
            None,
        )
        .map_err(|e| ApiError::Other(format!("sign rotation retirement: {e}")))?;
        crate::sigchain::publish_admin_retirement(self, &ret)?;
        self.refresh_admin_key_state()?;

        tracing::info!(
            old = %hex::encode(old_pubkey),
            new = %hex::encode(new_pubkey),
            overlap_secs,
            "admin key rotated"
        );
        Ok(cid)
    }

    /// Borrow the pinned `AdminGenesis` — the cluster's root of trust.
    /// `None` when no pin has been installed (truly pre-genesis, or
    /// legacy data dir).
    pub fn pinned_admin_genesis(&self) -> Option<&memvault_auth::AdminGenesis> {
        self.pinned_admin_genesis.get()
    }

    /// Verify an envelope's authorship sidecar against the currently-trusted
    /// agent set. Read paths call this for envelopes whose authorship must
    /// be enforced; data paths can ignore it (fail-open for backwards
    /// compatibility).
    ///
    /// Returns [`memvault_api::sigchain::AuthorshipStatus::NoSidecar`] when
    /// no trust state is installed (tests, headless tooling).
    pub fn verify_envelope_authorship(
        &self,
        envelope_cid: &[u8],
    ) -> Result<crate::sigchain::AuthorshipStatus> {
        let Some(state) = self.trust_state.get() else {
            return Ok(crate::sigchain::AuthorshipStatus::NoSidecar);
        };
        let trusted_atts = state
            .trusted_attestations
            .read()
            .map(|m| m.clone())
            .unwrap_or_default();
        let trusted_nodes = state
            .node_trust
            .read()
            .map(|m| m.keys().copied().collect::<std::collections::HashSet<_>>())
            .unwrap_or_default();
        crate::sigchain::verify_envelope_authorship(
            self,
            envelope_cid,
            &trusted_atts,
            &trusted_nodes,
        )
    }

    /// Register the store's index notifier to bridge to the client's event
    /// bus. Once installed, every block indexed (including blocks arriving
    /// via RBSR sync, which go through `reindex_block`) fires a
    /// [`MemvaultEvent::SigchainBlock`] when tagged `sigchain/<label>`.
    ///
    /// Call this once at daemon startup, before sync begins.
    pub fn install_sigchain_notifier(&self) {
        let bus = Arc::clone(&self.event_bus);
        let pending = Arc::clone(&self.reindex_pending);
        let dirty = Arc::clone(&self.index_dirty);
        self.store
            .set_index_notifier(std::sync::Arc::new(move |scope, label, cid| {
                if scope == "sigchain" {
                    bus.publish(MemvaultEvent::SigchainBlock {
                        label: label.to_string(),
                        cid: cid.to_vec(),
                    });
                }
                // Bridge blocks that enter the store without inline full-text
                // indexing — RBSR sync (`reindex_block`) and external seeding —
                // into the Tantivy index. The notifier fires once per tag; map
                // the node-kind tag to a node_id and queue it for the next
                // `flush_index` (which reconstructs from the blockstore and
                // indexes). Without this, synced docs/entities/files land in
                // redb (so counts and the graph update) but never become
                // searchable or appear in the scoped table view.
                let node_id = match scope {
                    "doc" => Some(format!("doc:{label}")),
                    "entity" => Some(format!("entity:{label}")),
                    // Attachments carry the `_manifest` reverse tag whose label
                    // is the hex manifest CID — the file node's surrogate id.
                    "_manifest" => Some(format!("file:{label}")),
                    _ => None,
                };
                if let Some(node_id) = node_id {
                    if let Ok(mut p) = pending.lock() {
                        p.insert(node_id);
                    }
                    dirty.store(true, std::sync::atomic::Ordering::Release);
                }
            }));
    }

    /// Set the node signing key (the daemon's libp2p ed25519 key, used to
    /// sign agent attestations and revocations). Distinct from the admin
    /// key on non-genesis-admin daemons. Write-once.
    pub fn set_node_signing_key(&self, key: ed25519_dalek::SigningKey) {
        let _ = self.node_signing_key.set(key);
    }

    /// Get the node signing key, if configured.
    pub fn node_signing_key(&self) -> Option<&ed25519_dalek::SigningKey> {
        self.node_signing_key.get()
    }

    /// Get the node verifying key, derived from the node signing key.
    pub fn node_verifying_key(&self) -> Option<ed25519_dalek::VerifyingKey> {
        self.node_signing_key.get().map(|k| k.verifying_key())
    }

    /// Set the agent identity (enables agent-scoped operations).
    /// Write-once; subsequent calls are silently ignored.
    pub fn set_agent_identity(&self, identity: crate::agent_identity::AgentIdentity) {
        let _ = self.agent_identity.set(identity);
    }

    /// Issue a `NodeAttestation` for a peer's pubkey, signed by this
    /// node's admin signing key. Used to admit a peer node into the
    /// cluster after they've completed `cluster-join`. Returns the
    /// attestation block's CID.
    ///
    /// Errors if no admin signing key is set on this client.
    pub fn attest_node(&self, peer_pubkey: [u8; 32]) -> Result<Vec<u8>> {
        use ed25519_dalek::Signer;
        let admin_sk = self
            .admin_signing_key()
            .ok_or_else(|| ApiError::Other("no admin signing key configured".into()))?;
        let cluster_id_arr: [u8; 32] = self
            .cluster_id
            .clone()
            .try_into()
            .map_err(|_| ApiError::Other("cluster_id must be 32 bytes".into()))?;
        let mut node_att = memvault_auth::NodeAttestation {
            cluster_id: memvault_core::ClusterId(cluster_id_arr),
            member: memvault_core::PeerId(peer_pubkey.to_vec()),
            not_after_ns: u64::MAX,
            issued_via: memvault_auth::AttestationOrigin::Direct,
            signature: [0u8; 64],
        };
        let bytes = node_att
            .signing_bytes()
            .map_err(|e| ApiError::Other(format!("node attestation signing bytes: {e}")))?;
        node_att.signature = admin_sk.sign(&bytes).to_bytes();
        crate::sigchain::publish_node_attestation(self, &node_att)
    }

    /// Revoke an agent that this node previously attested. Signs the
    /// revocation with the node signing key and persists it as a sigchain
    /// block (picked up by peers via RBSR sync).
    pub fn revoke_agent(
        &self,
        agent_pubkey: [u8; 32],
        reason: impl Into<String>,
    ) -> Result<Vec<u8>> {
        let node_sk = self
            .node_signing_key
            .get()
            .ok_or_else(|| ApiError::Other("no node signing key configured".into()))?;
        let rev = memvault_auth::sign_agent_revocation(node_sk, agent_pubkey, reason)
            .map_err(|e| ApiError::Other(format!("sign agent revocation: {e}")))?;
        crate::sigchain::publish_agent_revocation(self, &rev)
    }

    /// Revoke a node. Requires the admin signing key. Persists as a sigchain
    /// block; on next scan, downstream verifiers transitively reject every
    /// JWT chained through that node.
    pub fn revoke_node(
        &self,
        node_pubkey: [u8; 32],
        reason: impl Into<String>,
    ) -> Result<Vec<u8>> {
        let admin_sk = self
            .admin_signing_key()
            .ok_or_else(|| ApiError::Other("no admin signing key configured".into()))?;
        let rev = memvault_auth::sign_node_revocation(&admin_sk, node_pubkey, reason)
            .map_err(|e| ApiError::Other(format!("sign node revocation: {e}")))?;
        crate::sigchain::publish_node_revocation(self, &rev)
    }

    dual_impl! {
    /// Signed `bucket_create` with an explicit `bucket_id` and optional
    /// `owner_agent_override`. Does no async work, so it's exposed as a
    /// sync/async pair (via `dual_impl!`) — agent enrollment can ensure the
    /// bucket from sync contexts (connectors, `init_ui_agent`) as well as
    /// async handlers. Public-facing `bucket_create` calls it with a random
    /// ID + a `None` override; `ensure_agent_bucket_*` with a deterministic
    /// ID + explicit owner so the bucket is locatable on later runs.
    #[allow(clippy::too_many_arguments)]
    (bucket_create_inner_sync, bucket_create_inner_async)
    fn(&self, bucket_id: memvault_core::BucketId, name: &str, description: Option<&str>, default_visibility: Visibility, default_classification: memvault_core::classification::Classification, role: memvault_doc::BucketRole, owner_agent_override: Option<memvault_core::AgentName>, owner_agent_pubkey: Option<[u8; 32]>) -> Result<memvault_core::BucketId>
    {
        use memvault_doc::BucketDecl;

        let now_ns = memvault_core::wall_ns();

        // Auto-attach to cluster if the node has one (non-zero cluster_id).
        // Buckets are only private when created before genesis (no cluster yet).
        let has_cluster = self.cluster_id.iter().any(|&b| b != 0);
        let owner_agent = owner_agent_override
            .or_else(|| self.agent_identity.get().map(|i| i.agent_id.clone()));
        // Owner pubkey: explicit arg wins; else fall back to the bound
        // agent identity's pubkey when that is the owner.
        let owner_agent_pubkey = owner_agent_pubkey.or_else(|| {
            self.agent_identity
                .get()
                .map(|i| i.verifying_key.to_bytes())
        });
        let decl = BucketDecl {
            bucket_id: bucket_id.clone(),
            name: name.to_string(),
            description: description.map(|s| s.to_string()),
            owner_agent,
            owner_agent_pubkey,
            owner_node_pubkey: None,
            default_visibility,
            default_classification,
            created_ns: now_ns,
            private_to_peer: if has_cluster {
                None
            } else {
                Some(memvault_core::PeerId(self.peer_id.clone()))
            },
            role,
        };

        let tags = vec![
            ("kind".to_string(), "bucket-decl".to_string()),
            ("bucket".to_string(), bucket_id.to_string()),
        ];
        let payload = serde_json::json!({
            "BucketCreate": decl,
        });
        let (cid_bytes, envelope_bytes) = self.build_signed_envelope(
            payload,
            &tags,
            Visibility::Internal,
            now_ns,
            Some(&bucket_id.0),
        )?;

        let meta = memvault_store::insert::EnvelopeMeta {
            author: self.effective_author(),
            tags,
            wall_ns: now_ns,
            causal: vec![],
            provenance: vec![],
            cluster_id: Some(self.cluster_id.clone()),
            bucket_id: Some(bucket_id.0.to_vec()),
                    ..Default::default()
        };
        self.store
            .insert_envelope(&cid_bytes, &envelope_bytes, &meta)?;
        self.store.put_bucket(&bucket_id.0, &cid_bytes)?;

        if has_cluster {
            let _ = self
                .store
                .bind_bucket(&bucket_id.0, &self.cluster_id);
        }

        self.event_bus.publish(MemvaultEvent::BucketCreated {
            bucket_id: bucket_id.clone(),
            cid: cid_bytes,
        });

        tracing::info!(bucket = %bucket_id, name, has_cluster, "bucket created");
        Ok(bucket_id)
    }
    }

    /// Create a bucket on behalf of a specific agent, recording them as
    /// `owner_agent`. The HTTP `POST /buckets` handler uses this so the
    /// requesting agent — not the daemon — owns the new bucket and
    /// therefore passes [`crate::acl::check_bucket_access`] without
    /// needing a follow-up grant.
    pub async fn bucket_create_as(
        &self,
        owner_agent: memvault_core::AgentName,
        owner_agent_pubkey: Option<[u8; 32]>,
        name: &str,
        description: Option<&str>,
        default_visibility: Visibility,
        default_classification: memvault_core::classification::Classification,
        role: memvault_doc::BucketRole,
    ) -> Result<memvault_core::BucketId> {
        self.bucket_create_inner_async(
            memvault_core::BucketId::random(),
            name,
            description,
            default_visibility,
            default_classification,
            role,
            Some(owner_agent),
            owner_agent_pubkey,
        )
        .await
    }

    /// Core agent-bucket ensure path keyed by the agent's **pubkey**
    /// (cryptographically unique). The `name_hint` is only used as the
    /// display label on the BucketDecl — collisions in name don't
    /// matter, the bucket id derives from the pubkey alone.
    pub async fn ensure_agent_bucket_for_pubkey(
        &self,
        agent_pubkey: &[u8],
        name_hint: &str,
    ) -> Result<memvault_core::BucketId> {
        self.ensure_agent_bucket_for_pubkey_sync(agent_pubkey, name_hint)
    }

    /// Synchronous twin of [`Self::ensure_agent_bucket_for_pubkey`] — the
    /// bucket-create path does no async work, so sync callers (connectors,
    /// `init_ui_agent`) can ensure an agent's bucket without a runtime.
    pub fn ensure_agent_bucket_for_pubkey_sync(
        &self,
        agent_pubkey: &[u8],
        name_hint: &str,
    ) -> Result<memvault_core::BucketId> {
        let agent_id_for_owner = memvault_core::AgentName(name_hint.to_string());
        self.ensure_agent_bucket_inner(agent_pubkey, name_hint, agent_id_for_owner)
    }

    /// Back-compat wrapper: resolves the agent's pubkey on-chain by
    /// name, then delegates to the pubkey-keyed path. Errors if no
    /// attestation matching this `agent_id` exists (silent fallback
    /// would re-introduce the duplicate-bucket bug). For callers that
    /// already have the pubkey in hand, prefer
    /// `ensure_agent_bucket_for_pubkey`.
    pub async fn ensure_agent_bucket_for(
        &self,
        agent_id: &memvault_core::AgentName,
    ) -> Result<memvault_core::BucketId> {
        let attestations = crate::sigchain::scan_agent_attestations(self)?;
        let attestation = attestations
            .into_iter()
            .find(|a| a.agent_id == *agent_id)
            .ok_or_else(|| {
                ApiError::Other(format!(
                    "no on-chain attestation found for agent_id {:?} — \
                     enroll the agent before ensuring its bucket, or pass \
                     the agent pubkey directly via \
                     ensure_agent_bucket_for_pubkey",
                    agent_id.0
                ))
            })?;
        self.ensure_agent_bucket_inner(&attestation.agent_pubkey, &agent_id.0, agent_id.clone())
    }

    fn ensure_agent_bucket_inner(
        &self,
        agent_pubkey: &[u8],
        name_hint: &str,
        owner_agent: memvault_core::AgentName,
    ) -> Result<memvault_core::BucketId> {
        let bucket_id = crate::rebuild::deterministic_agent_bucket_id(agent_pubkey);
        let has_cluster = self.cluster_id.iter().any(|&b| b != 0);
        if self
            .store
            .get_bucket(&bucket_id.0)
            .ok()
            .flatten()
            .is_some()
        {
            // Bucket already exists. Make sure it's bound to the current
            // cluster — covers the pre-genesis-then-genesis case where
            // the BucketDecl landed before cluster_id was set, and
            // nothing has rebound it since.
            if has_cluster {
                let _ = self.store.bind_bucket(&bucket_id.0, &self.cluster_id);
            }
            return Ok(bucket_id);
        }

        let name = format!("agent:{name_hint}");
        let bid = self.bucket_create_inner_sync(
            bucket_id,
            &name,
            Some("auto-created agent bucket"),
            Visibility::Internal,
            memvault_core::classification::Classification::Internal,
            memvault_doc::BucketRole::Agent,
            Some(owner_agent.clone()),
            <[u8; 32]>::try_from(agent_pubkey).ok(),
        )?;
        // bucket_create_inner already auto-binds when has_cluster, but
        // surface bind errors here (the inner path swallows them since
        // a fresh bucket without a cluster is a valid pre-genesis
        // state). For an explicitly-named agent bucket we want hard
        // failure if the bind step refuses.
        if has_cluster {
            self.store
                .bind_bucket(&bid.0, &self.cluster_id)
                .map_err(|e| {
                    ApiError::Other(format!(
                        "bind agent bucket {} to cluster: {e}",
                        hex::encode(bid.0)
                    ))
                })?;
        }
        tracing::info!(
            agent = %name_hint,
            agent_pubkey = %hex::encode(agent_pubkey),
            bucket = %bid,
            "created and bound agent bucket"
        );
        Ok(bid)
    }

    /// Get the cluster ID.
    pub fn cluster_id(&self) -> &[u8] {
        &self.cluster_id
    }

    /// Shared event bus — used by sigchain helpers to notify watchers, and
    /// by the watcher to subscribe.
    pub fn event_bus(&self) -> &Arc<EventBus> {
        &self.event_bus
    }

    /// Get the peer ID.
    pub fn peer_id(&self) -> &[u8] {
        &self.peer_id
    }

    /// Create a bucket with a specific pre-determined ID.
    ///
    /// The envelope is fully deterministic: uses cluster_id as author and
    /// wall_ns=0 so every node in the cluster produces the same block.
    ///
    /// **Sole remaining unsigned-envelope producer.** Called only from
    /// `rebuild_store` when no legacy bucket exists yet, so we need to
    /// mint one before any node signing key is necessarily available
    /// (and the cluster as a whole — not any single node — is the
    /// nominal author). Every other write path goes through
    /// `build_signed_envelope`, which now refuses to fall back to an
    /// unsigned envelope. See `resign_legacy_envelope` in rebuild.rs
    /// for how legacy data adopted into this bucket is re-signed.
    #[allow(clippy::too_many_arguments)]
    pub fn create_bucket_with_id(
        &self,
        bucket_id: BucketId,
        name: &str,
        description: Option<&str>,
        default_visibility: Visibility,
        default_classification: memvault_core::classification::Classification,
        role: memvault_doc::BucketRole,
        owner_node_pubkey: Option<[u8; 32]>,
    ) -> Result<()> {
        use memvault_doc::BucketDecl;

        let has_cluster = self.cluster_id.iter().any(|&b| b != 0);
        let decl = BucketDecl {
            bucket_id: bucket_id.clone(),
            name: name.to_string(),
            description: description.map(|s| s.to_string()),
            owner_agent: None,
            owner_agent_pubkey: None,
            owner_node_pubkey,
            default_visibility,
            default_classification,
            created_ns: 0,
            private_to_peer: None,
            role,
        };

        let tags = vec![
            ("kind".to_string(), "bucket-decl".to_string()),
            ("bucket".to_string(), bucket_id.to_string()),
        ];
        // Deterministic: cluster_id as author, wall_ns=0.
        let envelope = serde_json::json!({
            "version": 1,
            "payload": { "BucketCreate": decl },
            "author": self.cluster_id,
            "tags": tags,
            "wall_ns": 0u64,
            "bucket_id": bucket_id.0,
        });
        let envelope_bytes = serde_ipld_dagcbor::to_vec(&envelope)
            .map_err(|e| ApiError::Serialization(e.to_string()))?;
        let cid = memvault_core::cid_from_bytes(&envelope_bytes);
        let cid_bytes = cid.to_bytes();

        let meta = memvault_store::insert::EnvelopeMeta {
            author: self.cluster_id.clone(),
            tags,
            wall_ns: 0,
            causal: vec![],
            provenance: vec![],
            cluster_id: Some(self.cluster_id.clone()),
            bucket_id: Some(bucket_id.0.to_vec()),
                    ..Default::default()
        };
        self.store
            .insert_envelope(&cid_bytes, &envelope_bytes, &meta)?;
        self.store.put_bucket(&bucket_id.0, &cid_bytes)?;

        if has_cluster {
            let _ = self.store.bind_bucket(&bucket_id.0, &self.cluster_id);
        }
        Ok(())
    }

    /// Get the agent ID if set.
    /// The admin signing key, if this daemon holds one (i.e. is the cluster
    /// admin). Used by callers that need to derive the admin verifying key
    /// or sign admin-only operations.
    /// A held admin signing secret, preferring one that is currently
    /// valid as an admin (anchor first). Returns a clone — the secret
    /// lives behind a lock and cannot be borrowed past the guard.
    /// `None` on peer daemons that hold no admin key.
    pub fn admin_signing_key(&self) -> Option<ed25519_dalek::SigningKey> {
        self.admin_signing_key_at_ns(memvault_core::wall_ns())
    }

    /// A held admin signing secret that is valid *at* `now_ns`, preferring
    /// the anchor key. Used when signing new admin operations so we never
    /// sign with a key that's outside its validity window.
    pub fn admin_signing_key_at_ns(
        &self,
        now_ns: u64,
    ) -> Option<ed25519_dalek::SigningKey> {
        let held = self.held_admin_keys.read().ok()?;
        let state = self.admin_key_state.read().ok()?;
        // Prefer the anchor if we hold it and it's valid.
        if let Some(anchor) = state.anchor {
            if state.is_key_valid_at(&anchor, now_ns) {
                if let Some(sk) = held.get(&anchor) {
                    return Some(sk.clone());
                }
            }
        }
        // Otherwise any held key valid right now.
        for (pk, sk) in held.iter() {
            if state.is_key_valid_at(pk, now_ns) {
                return Some(sk.clone());
            }
        }
        // Last resort ONLY when the admin-key state is empty (truly
        // pre-bootstrap / fresh test harness with a registered secret but
        // no rescanned state). Once the state is populated we never sign
        // with a key it considers invalid (e.g. retired) — that would
        // produce signatures honest peers reject and risks signing with a
        // revoked/retired key.
        if state.keys.is_empty() {
            return held.values().next().cloned();
        }
        None
    }

    /// The admin verifying key for a held, currently-valid admin secret.
    /// `None` on peer daemons that don't hold an admin key.
    pub fn admin_verifying_key(&self) -> Option<ed25519_dalek::VerifyingKey> {
        self.admin_signing_key().map(|sk| sk.verifying_key())
    }

    /// True if this node holds at least one admin signing secret.
    pub fn holds_admin_key(&self) -> bool {
        self.held_admin_keys
            .read()
            .map(|h| !h.is_empty())
            .unwrap_or(false)
    }

    pub fn agent_id(&self) -> Option<&memvault_core::AgentName> {
        self.agent_identity.get().map(|i| &i.agent_id)
    }

    /// CID of the bound agent's attestation block, if a recent
    /// enrollment pass cached it via `set_agent_attestation_cid`. The
    /// cache is purely an optimization — when absent, envelope
    /// builders fall back to the on-chain lookup by author pubkey
    /// that the JWT verifier already does, so writes still attribute
    /// correctly.
    pub fn agent_attestation_cid(&self) -> Option<&[u8]> {
        self.agent_attestation_cid_cache
            .get()
            .map(|v| v.as_slice())
    }

    /// Cache the bound agent's attestation CID. Called by
    /// `enroll_local_agent` (which has the freshly-published CID in
    /// scope) so subsequent writes embed the inline attribution
    /// pointer without re-scanning the sigchain on every write.
    pub fn set_agent_attestation_cid(&self, cid: Vec<u8>) {
        let _ = self.agent_attestation_cid_cache.set(cid);
    }

    /// The effective author identity for write operations.
    /// Uses the agent's peer ID (derived from its public key) if an agent
    /// identity is set, otherwise falls back to the raw peer_id.
    fn effective_author(&self) -> Vec<u8> {
        if let Some(identity) = self.agent_identity.get() {
            identity.verifying_key.as_bytes().to_vec()
        } else {
            self.peer_id.clone()
        }
    }

    /// Identity to sign a new write with. The node always signs; the
    /// agent additionally co-signs when an agent identity is bound.
    /// Returns `None` only when no node SK is configured (pre-genesis
    /// bootstrap), in which case the caller must use an unsigned write
    /// path.
    ///
    /// `author` is always the node's pubkey-derived peer_id — matches
    /// `node_signing_key.verifying_key()`. `agent_attestation` and
    /// `agent_signing_key` are `Some` together iff an agent identity is
    /// bound; the verifier resolves the cid to the same pubkey the
    /// co-signature verifies against.
    pub(crate) fn signer_for_writes(&self) -> Option<WriteSigner<'_>> {
        let node_signing_key = self.node_signing_key.get()?;
        let agent = self.agent_identity.get();
        Some(WriteSigner {
            node_signing_key,
            author: memvault_core::PeerId(self.peer_id.clone()),
            agent_signing_key: agent.map(|a| &a.signing_key),
            // Inline attribution CID is sourced from the post-enroll
            // cache; absent until the daemon publishes the
            // attestation. Readers fall back to author-pubkey lookup
            // on the sigchain when this is None.
            agent_attestation: agent.and(self.agent_attestation_cid_cache.get().cloned()),
        })
    }

    /// Build a `Signed<Value>` envelope for an agent-attributable write
    /// and return its `(cid_bytes, envelope_bytes)`. The node always
    /// signs; when an agent identity is bound, the agent additionally
    /// co-signs the same payload bytes.
    ///
    /// `payload` is the kind-specific JSON content (e.g. the op for ops,
    /// the annotation body for annotations, …). The helper wraps it in
    /// the canonical envelope shape — author, tags, visibility, wall_ns,
    /// bucket_id, attestation cids — and signs.
    ///
    /// `tags` is the existing `(scope, label)` shape used at call sites;
    /// it's converted to `Vec<Tag>` here so callers don't repeat the
    /// boilerplate.
    fn build_signed_envelope(
        &self,
        payload: serde_json::Value,
        tags: &[(String, String)],
        visibility: Visibility,
        wall_ns: u64,
        bucket_id: Option<&[u8]>,
    ) -> Result<(Vec<u8>, Vec<u8>)> {
        let tags_typed: Vec<memvault_core::tags::Tag> = tags
            .iter()
            .map(|(s, l)| memvault_core::tags::Tag::new(s.clone(), l.clone()))
            .collect();
        let bucket_id_typed: Option<BucketId> = bucket_id.and_then(|b| {
            let arr: [u8; 32] = b.try_into().ok()?;
            Some(BucketId(arr))
        });

        // When a signer is available, produce a fully-signed Signed<T>
        // envelope (node always signs, agent co-signs when bound).
        if let Some(signer) = self.signer_for_writes() {
            let envelope = memvault_core::Signed::sign(
                payload,
                signer.node_signing_key,
                signer.author,
                vec![], // causal — not tracked in the JSON envelope era
                vec![], // provenance — likewise
                tags_typed,
                visibility,
                0, // lamport — not tracked yet
                wall_ns,
                None, // capability
                bucket_id_typed,
                None, // node_attestation — wire up once trust_state has the cid
                signer.agent_attestation,
                signer.agent_signing_key,
            )
            .map_err(|e| ApiError::Other(format!("sign envelope: {e}")))?;

            let envelope_bytes = serde_ipld_dagcbor::to_vec(&envelope)
                .map_err(|e| ApiError::Serialization(e.to_string()))?;
            let cid_bytes = memvault_core::cid_from_bytes(&envelope_bytes).to_bytes();
            return Ok((cid_bytes, envelope_bytes));
        }

        // No node signing key configured. Previously we silently fell
        // back to an unsigned JSON envelope with a different `tags`
        // serialization, which let smoke tests pass while production
        // (signed) envelopes carried a different shape — that's how the
        // EdgeAdd "? → ?" audit bug went undetected for so long. The
        // node key is now load-bearing: refuse the write outright so
        // misconfigured callers get a clear error instead of a divergent
        // envelope shape.
        Err(ApiError::Other(
            "node_signing_key not configured on LocalClient; call \
             set_node_signing_key before issuing writes"
                .into(),
        ))
    }

    /// Synchronous lookup of a bucket's info by id. Mirrors the async
    /// `bucket_get` trait method but avoids the executor — used by
    /// callers that already hold a `LocalClient` reference inside a
    /// sync context (e.g. ACL checks).
    pub fn bucket_info_sync(
        &self,
        id: &BucketId,
    ) -> Result<Option<crate::types::BucketInfo>> {
        let decl_cid = match self.store.get_bucket(&id.0)? {
            Some(c) => c,
            None => return Ok(None),
        };
        self.build_bucket_info(&id.0, &decl_cid)
    }

    /// Build a BucketInfo from a bucket_id and its decl CID.
    fn build_bucket_info(
        &self,
        bucket_id_bytes: &[u8],
        decl_cid: &[u8],
    ) -> Result<Option<crate::types::BucketInfo>> {
        let block = match self.store.get_block(decl_cid)? {
            Some(b) => b,
            None => return Ok(None),
        };

        let decl = match Self::parse_bucket_decl(&block) {
            Some(d) => d,
            None => return Ok(None),
        };

        let cluster_bytes = self.store.get_bucket_cluster(bucket_id_bytes)?;
        let cluster_id = cluster_bytes.and_then(|b| {
            let arr: [u8; 32] = b.try_into().ok()?;
            Some(memvault_core::ClusterId(arr))
        });

        let envelope_count = self
            .store
            .query_by_bucket(bucket_id_bytes, 0, usize::MAX)?
            .len() as u64;

        // If this bucket has been merged into a canonical, record the target
        // (a self-resolution means it's not a merged source).
        let merged_into = <[u8; 32]>::try_from(bucket_id_bytes).ok().and_then(|arr| {
            let canonical = self.canonical_of(&arr);
            (canonical != arr).then_some(memvault_core::BucketId(canonical))
        });

        Ok(Some(crate::types::BucketInfo {
            id: decl.bucket_id,
            name: decl.name,
            description: decl.description,
            owner_agent: decl.owner_agent,
            owner_agent_pubkey: decl.owner_agent_pubkey,
            owner_node_pubkey: decl.owner_node_pubkey,
            cluster_id,
            is_attached: decl.private_to_peer.is_none(),
            default_visibility: decl.default_visibility,
            default_classification: decl.default_classification,
            created_ns: decl.created_ns,
            envelope_count,
            role: decl.role,
            merged_into,
        }))
    }

    /// Load the TextIndex from a cache file, or rebuild from the blockstore if
    /// the cache is missing/stale. Saves the rebuilt index afterward.
    /// Call this after construction to make search work for pre-existing data.
    pub async fn load_or_rebuild_index(
        &self,
        cache_path: &std::path::Path,
    ) -> Result<(usize, usize, usize)> {
        // The Tantivy index persists itself on disk (beside the blockstore at
        // `<dir>/tantivy/`) and was opened at construction with a version
        // guard (`open_index`). So "load" just means: if it already holds
        // documents, it's loaded; otherwise rebuild from the blockstore.
        let _ = cache_path; // legacy JSON cache path — no longer used
        let existing = { self.index.read().await.num_docs() as usize };
        if existing > 0 {
            tracing::info!("tantivy index already populated ({existing} docs)");
            return Ok((existing, 0, 0));
        }
        tracing::info!("tantivy index empty, rebuilding from blockstore...");
        // A full index rebuild invalidates the derived scope member-sets;
        // drop them so they rebuild lazily against fresh state.
        if let Err(e) = self.store.scope_clear_all() {
            tracing::warn!("failed to clear scope member-sets on rebuild: {e}");
        }
        let counts = self.populate_index().await?;
        {
            let mut idx = self.index.write().await;
            idx.commit()
                .map_err(|e| ApiError::Other(format!("tantivy commit: {e}")))?;
        }
        Ok(counts)
    }

    // ── dual_impl! generated method pairs ────────────────────────────

    dual_impl! {
        /// Reconstruct a document from the blockstore. When
        /// `include_retracted` is true the retraction gate is skipped
        /// (auditor/admin view).
        (get_doc_sync, get_doc_async)
        fn(&self, id: &DocId, include_retracted: bool) -> Result<Option<Document>>
        {
            let node_id = format!("doc:{}", hex::encode(id.0));
            {
                let idx = idx_read!();
                if !include_retracted && idx.is_retracted(&node_id) {
                    return Ok(None);
                }
            }
            let (_, label) = Self::doc_tag(id);
            let cids = self.store.query_by_tag("doc", &label, 0, usize::MAX)?;
            if cids.is_empty() {
                return Ok(None);
            }
            let mut ops = Vec::new();
            for cid in &cids {
                if let Some(data) = self.store.get_block(cid)? {
                    if let Some(val) = memvault_store::deserialize_block(&data) {
                        if let Some(payload) = val.get("payload") {
                            if let Ok(op) = serde_json::from_value::<Op>(payload.clone()) {
                                ops.push(op);
                            }
                        }
                    }
                }
            }
            if ops.is_empty() {
                return Ok(None);
            }
            let doc = memvault_doc::apply_doc_ops(&ops)?;
            Ok(Some(doc))
        }
    }

    dual_impl! {
        /// Reconstruct an entity from the blockstore. When
        /// `include_retracted` is true the retraction gate is skipped
        /// (auditor/admin view).
        (get_entity_sync, get_entity_async)
        fn(&self, id: &EntityId, include_retracted: bool) -> Result<Option<Entity>>
        {
            let node_id = format!("entity:{}", hex::encode(id.0));
            {
                let idx = idx_read!();
                if !include_retracted && idx.is_retracted(&node_id) {
                    return Ok(None);
                }
            }
            let label: String = id.0.iter().map(|b| format!("{b:02x}")).collect();
            let cids = self.store.query_by_tag("entity", &label, 0, usize::MAX)?;
            if cids.is_empty() {
                return Ok(None);
            }
            let mut ops = Vec::new();
            for cid in &cids {
                if let Some(data) = self.store.get_block(cid)? {
                    if let Some(val) = memvault_store::deserialize_block(&data) {
                        if let Some(payload) = val.get("payload") {
                            if let Ok(op) = serde_json::from_value::<Op>(payload.clone()) {
                                ops.push(op);
                            }
                        }
                    }
                }
            }
            Ok(memvault_doc::apply_graph_ops(&ops)
                .ok()
                .and_then(|gs| gs.entities.into_values().next()))
        }
    }

    dual_impl! {
        /// Populate the in-memory TextIndex from the blockstore.
        (populate_index_sync, populate_index)
        fn(&self) -> Result<(usize, usize, usize)>
        {
            tracing::info!("populating text index from blockstore...");
            let mut doc_count = 0usize;
            let mut entity_count = 0usize;
            let mut attachment_count = 0usize;

            // Reliable cid→bucket map from the authoritative BY_BUCKET index.
            // Envelope-parse-based inference (inferred_*_bucket) misses nodes
            // whose bucket_id lives only in the store index, not the envelope
            // body — which would skip them here and leave the search index
            // empty even though the blockstore is full.
            let mut cid_bucket: std::collections::HashMap<Vec<u8>, [u8; 32]> =
                std::collections::HashMap::new();
            for (bid, _) in self.store.list_buckets().unwrap_or_default() {
                if let Ok(arr) = <[u8; 32]>::try_from(bid.as_slice()) {
                    for cid in self.store.query_by_bucket(&bid, 0, usize::MAX).unwrap_or_default() {
                        cid_bucket.entry(cid).or_insert(arr);
                    }
                }
            }

            // Index documents
            let doc_labels = self
                .store
                .query_unique_labels("doc", usize::MAX)
                .map_err(|e| ApiError::Serialization(e.to_string()))?;
            for label in &doc_labels {
                let id_bytes = hex::decode(label).unwrap_or_default();
                if id_bytes.len() != 32 {
                    continue;
                }
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&id_bytes);
                let doc_id = DocId(arr);
                // Best-effort bucket: BY_BUCKET (reliable) → envelope inference
                // → none. Index the doc regardless so it's searchable; the
                // stored bucket_id only matters for explicit bucket scoping.
                let doc_cids = self
                    .store
                    .query_by_tag("doc", label, 0, usize::MAX)
                    .unwrap_or_default();
                let bucket_hex = doc_cids
                    .iter()
                    .find_map(|c| cid_bucket.get(c))
                    .map(hex::encode)
                    .or_else(|| self.inferred_doc_bucket(&doc_id).map(hex::encode));
                if let Ok(Some(doc)) = get_doc!(&doc_id) {
                    let title = doc.frontmatter.get("title").and_then(|v| v.as_str());
                    // Recover creation-time tags from the envelope metadata.
                    let creation_tags = self.extract_creation_tags("doc", label);
                    let mut idx = idx_write!();
                    let _ = idx.index_doc(
                        &doc_id,
                        &doc.body,
                        title,
                        &creation_tags,
                        bucket_hex.as_deref(),
                        0,
                    );
                    doc_count += 1;
                }
            }

            // Index entities
            let entity_labels = self
                .store
                .query_unique_labels("entity", usize::MAX)
                .map_err(|e| ApiError::Serialization(e.to_string()))?;
            for label in &entity_labels {
                let id_bytes = hex::decode(label).unwrap_or_default();
                if id_bytes.len() != 32 {
                    continue;
                }
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&id_bytes);
                let eid = EntityId(arr);
                // Best-effort bucket (BY_BUCKET → inference → none); index regardless.
                let entity_cids = self
                    .store
                    .query_by_tag("entity", label, 0, usize::MAX)
                    .unwrap_or_default();
                let bucket_hex = entity_cids
                    .iter()
                    .find_map(|c| cid_bucket.get(c))
                    .map(hex::encode)
                    .or_else(|| self.inferred_entity_bucket(&eid).map(hex::encode));
                if let Ok(Some(entity)) = get_entity!(&eid) {
                    let creation_tags = self.extract_creation_tags("entity", label);
                    let mut idx = idx_write!();
                    let _ = idx.index_entity(
                        &eid,
                        &entity.kind,
                        &entity.props,
                        &creation_tags,
                        bucket_hex.as_deref(),
                        0,
                    );
                    entity_count += 1;
                }
            }

            // Index attachments
            let blocks = self
                .store
                .iter_blocks()
                .map_err(|e| ApiError::Serialization(e.to_string()))?;
            for (cid, data) in &blocks {
                if let Some(view) = memvault_store::EnvelopeView::parse(data) {
                    if view.str_field("kind") == Some("attachment") {
                        // Best-effort bucket: envelope body → BY_BUCKET map
                        // (keyed by the envelope's own cid) → none. Index
                        // regardless so the file is searchable.
                        let bucket_hex = view
                            .get_as::<Vec<u8>>("bucket_id")
                            .or_else(|| cid_bucket.get(cid).map(|b| b.to_vec()))
                            .map(hex::encode);
                        let manifest_cid: Option<Vec<u8>> = view.get_as("manifest_cid");
                        let filename = view.str_field("filename");
                        let mime_type = view
                            .str_field("mime_type")
                            .unwrap_or("application/octet-stream");
                        if let Some(mcid) = manifest_cid {
                            // Only use cached extraction during index rebuild.
                            let text = self.load_cached_extraction(&mcid)
                                .and_then(|r| match r {
                                    ExtractionResult::Ok { text, .. } => Some(text),
                                    _ => None,
                                });
                            let att_tags: Vec<(String, String)> =
                                view.get_as("tags").unwrap_or_default();
                            let mut idx = idx_write!();
                            let _ = idx.index_attachment(
                                &mcid,
                                filename,
                                mime_type,
                                text.as_deref(),
                                &att_tags,
                                bucket_hex.as_deref(),
                                0,
                            );
                            attachment_count += 1;
                        }
                    }
                }
            }

            // Replay tag updates and retractions
            for (_, data) in &blocks {
                if let Some(view) = memvault_store::EnvelopeView::parse(data) {
                    let val = view.raw();
                    let kind = view.str_field("kind");

                    // Unified annotation format
                    if kind == Some("annotation") {
                        let target = view.str_field("target").unwrap_or("");
                        let ann_type = view.str_field("type").unwrap_or("");
                        let ann_data = view
                            .field("data")
                            .cloned()
                            .unwrap_or(serde_json::Value::Null);
                        if !target.is_empty() {
                            let mut idx = idx_write!();
                            match ann_type {
                                "tag_update" => {
                                    let add: Vec<(String, String)> = ann_data
                                        .get("add")
                                        .and_then(|v| serde_json::from_value(v.clone()).ok())
                                        .unwrap_or_default();
                                    let remove: Vec<(String, String)> = ann_data
                                        .get("remove")
                                        .and_then(|v| serde_json::from_value(v.clone()).ok())
                                        .unwrap_or_default();
                                    let _ = idx.apply_tag_update(target, &add, &remove);
                                }
                                "retraction" => {
                                    let _ = idx.retract(target);
                                }
                                _ => {} // extraction annotations handled during attachment indexing
                            }
                        }
                    }
                    // Legacy formats (backward compat)
                    else if kind == Some("tag_update") {
                        let node_id = val.get("node_id").and_then(|v| v.as_str()).unwrap_or("");
                        let add: Vec<(String, String)> = val
                            .get("add")
                            .and_then(|v| serde_json::from_value(v.clone()).ok())
                            .unwrap_or_default();
                        let remove: Vec<(String, String)> = val
                            .get("remove")
                            .and_then(|v| serde_json::from_value(v.clone()).ok())
                            .unwrap_or_default();
                        if !node_id.is_empty() {
                            let mut idx = idx_write!();
                            let _ = idx.apply_tag_update(node_id, &add, &remove);
                        }
                    } else if kind == Some("node_retraction") {
                        let node_id = val.get("node_id").and_then(|v| v.as_str()).unwrap_or("");
                        if !node_id.is_empty() {
                            let mut idx = idx_write!();
                            let _ = idx.retract(node_id);
                        }
                    }
                }
            }

            Ok((doc_count, entity_count, attachment_count))
        }
    }

    /// Commit pending writes to the on-disk Tantivy index. (The `cache_path`
    /// argument is retained for API compatibility but unused — Tantivy manages
    /// its own directory.)
    pub async fn save_index(&self, _cache_path: &std::path::Path) -> Result<()> {
        let mut idx = self.index.write().await;
        idx.commit()
            .map_err(|e| ApiError::Serialization(e.to_string()))
    }

    /// Access the quota manager.
    /// Store an annotation block in the blockstore. All sidecars (tag updates,
    /// extraction results, retractions) use this unified format.
    /// Tagged with `_ann:<target>` for discovery.
    fn store_annotation(
        &self,
        target: &str,
        ann_type: &str,
        data: serde_json::Value,
    ) -> Result<()> {
        let tags = vec![("_ann".to_string(), target.to_string())];
        let bucket_id = self.inferred_bucket_for_node_id(target);

        // Skip annotations for non-bucketed targets (legacy data).
        if bucket_id.is_none() && !self.store.list_buckets().unwrap_or_default().is_empty() {
            return Ok(());
        }

        let wall_ns = memvault_core::wall_ns();
        let payload = serde_json::json!({
            "kind": "annotation",
            "target": target,
            "type": ann_type,
            "data": data,
            "cluster_id": self.cluster_id.clone(),
        });
        let (cid_bytes, envelope_bytes) = self.build_signed_envelope(
            payload,
            &tags,
            Visibility::Internal,
            wall_ns,
            bucket_id.as_deref(),
        )?;
        let meta = EnvelopeMeta {
            author: self.effective_author(),
            tags: vec![("_ann".to_string(), target.to_string())],
            wall_ns,
            causal: vec![],
            provenance: vec![],
            cluster_id: Some(self.cluster_id.clone()),
            bucket_id,
                    ..Default::default()
        };
        self.store.insert_envelope(&cid_bytes, &envelope_bytes, &meta)?;
        Ok(())
    }

    fn store_tag_update(
        &self,
        node_id: &str,
        add: &[(String, String)],
        remove: &[(String, String)],
    ) -> Result<()> {
        self.store_annotation(
            node_id,
            "tag_update",
            serde_json::json!({ "add": add, "remove": remove }),
        )
    }

    /// Extract text + links from a source (attachment or document), cache
    /// the result in the blockstore as an `"extraction"` annotation, and
    /// return the extracted text if successful.
    pub(crate) fn extract_source_and_cache(
        &self,
        source: ExtractionSource<'_>,
    ) -> Option<String> {
        let mime_type = source.mime();
        tracing::debug!(mime_type, target = %source.annotation_target(), "extracting text");
        // Check cache first.
        match self.load_cached_extraction_for(&source) {
            Some(ExtractionResult::Ok { text, .. }) => {
                tracing::debug!(mime_type, "extraction cache hit");
                return Some(text);
            }
            Some(ExtractionResult::Failed(_)) => {
                tracing::debug!(mime_type, "extraction cache hit");
                return None;
            }
            _ => {}
        }

        // Extract fresh.
        let result = safe_extract_text(source.data(), mime_type);

        // Cache the result.
        match &result {
            ExtractionResult::Ok { text, links } => {
                self.store_extraction_annotation(&source, Some(text), Some(links), None);
                tracing::debug!(
                    mime_type,
                    text_len = text.len(),
                    link_count = links.len(),
                    "extraction succeeded, cached in annotation"
                );
            }
            ExtractionResult::Failed(err) => {
                tracing::debug!(mime_type, error = %err, "extraction failed, cached failure");
                self.store_extraction_annotation(&source, None, None, Some(err));
            }
            ExtractionResult::Unsupported => {}
        }

        match result {
            ExtractionResult::Ok { text, .. } => Some(text),
            _ => None,
        }
    }

    /// Backwards-compatible wrapper used by the attachment write path.
    fn extract_and_cache(
        &self,
        manifest_cid: &[u8],
        data: &[u8],
        mime_type: &str,
    ) -> Option<String> {
        self.extract_source_and_cache(ExtractionSource::Attachment {
            manifest_cid,
            mime: mime_type,
            data,
        })
    }

    /// Extract text + links from a document body and cache the result as an
    /// `"extraction"` annotation keyed by the head op CID. MIME defaults to
    /// `text/markdown`; opt into `text/html` via `frontmatter.mime` or
    /// `frontmatter.format`.
    pub(crate) fn extract_doc_and_cache(
        &self,
        doc_id: &DocId,
        head_cid: &[u8],
        body: &str,
        frontmatter: &std::collections::BTreeMap<String, serde_json::Value>,
    ) -> Option<String> {
        let mime = doc_mime_from_frontmatter(frontmatter);
        let source = ExtractionSource::Document {
            doc_id: doc_id.clone(),
            head_cid,
            mime,
            body: body.as_bytes(),
        };
        let text = self.extract_source_and_cache(source);

        // Reconcile cached links into graph edges. Failures here are
        // non-fatal — the body itself is already saved.
        if let Err(e) = self.reconcile_doc_link_edges(doc_id, head_cid, mime, body) {
            tracing::warn!(
                doc_id = %hex::encode(doc_id.0),
                error = %e,
                "doc-link reconciliation failed"
            );
        }

        text
    }

    /// Read the cached links for the doc's head, reconcile against the
    /// existing body-provenance edges, and commit the diff as graph ops.
    fn reconcile_doc_link_edges(
        &self,
        doc_id: &DocId,
        head_cid: &[u8],
        mime: &str,
        body: &str,
    ) -> Result<()> {
        let alias_index = crate::link_reconcile::AliasIndex::build(&self.store);

        let source = ExtractionSource::Document {
            doc_id: doc_id.clone(),
            head_cid,
            mime,
            body: body.as_bytes(),
        };
        let current_links = self.load_cached_links_for_source(&source);

        // Reload existing body-provenance edges out of this doc using the
        // sync read path (inline mirror of edges_of).
        let doc_node = NodeRef::Doc(doc_id.clone());
        let existing = self.edges_of_sync(&doc_node)?;
        let body_edges = crate::link_reconcile::filter_body_provenance(existing);

        // We treat existing body edges as the "prev" baseline; the diff
        // gives us removes for vanished targets and adds for new ones.
        let input = crate::link_reconcile::ReconcileInput {
            doc_id,
            current_links: &current_links,
            previous_links: &[],
            existing_body_edges: &body_edges,
            alias_index: &alias_index,
        };
        let mut ops = crate::link_reconcile::compute_reconcile_ops(&input);

        // Also remove body-provenance edges whose target is absent in the
        // current resolved set — the pure-add diff above wouldn't catch
        // these. Build a key set from current resolved links.
        let resolved_keys: std::collections::HashSet<(NodeRef, String)> = current_links
            .iter()
            .filter_map(|l| crate::link_reconcile::resolve_extracted_link(l, &alias_index))
            .map(|r| (r.target, r.relation))
            .collect();
        for edge in &body_edges {
            if !resolved_keys.contains(&(edge.target.clone(), edge.relation.clone())) {
                ops.push(Op::EdgeRemove {
                    source: doc_node.clone(),
                    edge_id: edge.id.clone(),
                });
            }
        }

        if ops.is_empty() {
            return Ok(());
        }
        crate::link_reconcile::apply_reconcile_ops(self, &ops)
    }

    /// Synchronous equivalent of `MemvaultClient::edges_of` — used by the
    /// link reconciler which runs inside a sync write path. Mirrors the
    /// implementation in the async method.
    fn edges_of_sync(&self, node: &NodeRef) -> Result<Vec<(NodeRef, Edge)>> {
        let label = node.tag_label();
        let mut results = Vec::new();
        let mut removed_ids: std::collections::HashSet<EdgeId> =
            std::collections::HashSet::new();

        let source_cids = self
            .store
            .query_by_tag("edge_source", &label, 0, usize::MAX)?;
        let target_cids = self
            .store
            .query_by_tag("edge_target", &label, 0, usize::MAX)?;

        let mut all_cids = source_cids;
        all_cids.extend(target_cids);

        for cid in &all_cids {
            if let Some(data) = self.store.get_block(cid)? {
                if let Some(val) = memvault_store::deserialize_block(&data) {
                    if let Some(payload) = val.get("payload") {
                        match serde_json::from_value::<Op>(payload.clone()) {
                            Ok(Op::EdgeAdd { source, edge }) => {
                                results.push((source, edge));
                            }
                            Ok(Op::EdgeRemove { edge_id, .. }) => {
                                removed_ids.insert(edge_id);
                            }
                            _ => {}
                        }
                    }
                }
            }
        }

        results.retain(|(_, edge)| !removed_ids.contains(&edge.id));
        let mut seen = std::collections::HashSet::new();
        results.retain(|(_, edge)| seen.insert(edge.id.clone()));
        Ok(results)
    }

    fn store_extraction_annotation(
        &self,
        source: &ExtractionSource<'_>,
        text: Option<&str>,
        links: Option<&[memvault_extract_abi::ExtractedLink]>,
        error: Option<&str>,
    ) {
        let target = source.annotation_target();
        let links_json = links.map(|ls| {
            ls.iter()
                .map(|l| {
                    serde_json::json!({
                        "uri": l.uri,
                        "display_text": l.display_text,
                        "byte_span": [l.byte_span.0, l.byte_span.1],
                        "syntax": format!("{:?}", l.syntax),
                    })
                })
                .collect::<Vec<_>>()
        });
        let _ = self.store_annotation(
            &target,
            "extraction",
            serde_json::json!({
                "extracted_text_inline": text,
                "extraction_error": error,
                "links": links_json,
                "extractor": "memvault-extract",
                "extracted_at_ns": memvault_core::wall_ns(),
            }),
        );
    }

    /// Load cached extraction result for a generic source. Returns
    /// `Some(ExtractionResult::Ok { text, links })` on cached success,
    /// `Some(ExtractionResult::Failed(err))` on cached failure, `None` if
    /// no cache exists. The result's `links` field is populated from the
    /// `links` annotation field (empty for legacy entries).
    fn load_cached_extraction_for(
        &self,
        source: &ExtractionSource<'_>,
    ) -> Option<ExtractionResult> {
        let target = source.annotation_target();
        let legacy_target = source.legacy_target();
        self.load_cached_extraction_by_targets(&target, legacy_target.as_deref(), source.cache_key())
    }

    /// Load cached extraction result.
    /// Returns `Some(ExtractionResult::Ok { text, links })` on cached
    /// success, `Some(ExtractionResult::Failed(err))` on cached failure,
    /// `None` if no cache exists.
    fn load_cached_extraction(&self, manifest_cid: &[u8]) -> Option<ExtractionResult> {
        let target = format!("file:{}", hex::encode(manifest_cid));
        let legacy_target = format!("attachment:{}", hex::encode(manifest_cid));
        self.load_cached_extraction_by_targets(&target, Some(&legacy_target), manifest_cid)
    }

    fn load_cached_extraction_by_targets(
        &self,
        target: &str,
        legacy_target_attachment: Option<&str>,
        manifest_cid: &[u8],
    ) -> Option<ExtractionResult> {
        // Kept for diff continuity — original implementation below.
        let legacy_target = legacy_target_attachment.map(|s| s.to_string()).unwrap_or_default();

        // Try new unified annotation format first, then legacy manifest_update.
        let mut ann_cids = self.store.query_by_tag("_ann", &target, 0, 10).ok()?;
        // Also check legacy "attachment:" annotations for backward compat.
        if let Ok(legacy_ann) = self.store.query_by_tag("_ann", &legacy_target, 0, 10) {
            ann_cids.extend(legacy_ann);
        }
        let legacy_label = hex::encode(manifest_cid);
        let legacy_cids = self
            .store
            .query_by_tag("manifest_update", &legacy_label, 0, 10)
            .ok()?;

        for cid in ann_cids.iter().chain(legacy_cids.iter()) {
            let block_data = self.store.get_block(cid).ok()??;
            // EnvelopeView normalises top-level vs Signed<T>-nested
            // field access, so the `data` field is reached regardless of
            // whether the annotation came from the legacy raw-JSON or
            // the new Signed<T> envelope path.
            let view = memvault_store::EnvelopeView::parse(&block_data)?;
            let val: serde_json::Value = view.raw().clone();

            // Unified annotation format — pull `data` via the view first;
            // fall back to the legacy top-level layout if the field is
            // absent.
            let data_field_owned = view
                .field("data")
                .cloned()
                .unwrap_or_else(|| val.clone());
            let data_field = &data_field_owned;

            if let Some(err) = data_field.get("extraction_error").and_then(|v| v.as_str()) {
                if !err.is_empty() {
                    return Some(ExtractionResult::Failed(err.to_string()));
                }
            }

            let links = parse_cached_links(data_field.get("links"));

            // New inline format: text embedded directly in annotation.
            if let Some(text) = data_field
                .get("extracted_text_inline")
                .and_then(|v| v.as_str())
            {
                return Some(ExtractionResult::Ok {
                    text: text.to_string(),
                    links,
                });
            }

            // Legacy format: text stored as separate block via CID ref.
            if let Some(et_cid) = data_field
                .get("extracted_text")
                .and_then(|v| serde_json::from_value::<Vec<u8>>(v.clone()).ok())
            {
                let et_bytes = self.store.get_block(&et_cid).ok()??;
                let et: serde_json::Value = memvault_store::deserialize_block(&et_bytes)?;
                let text = et.get("text").and_then(|v| v.as_str())?.to_string();
                return Some(ExtractionResult::Ok { text, links });
            }
        }
        None
    }

    /// Public read accessor — returns the cached extracted links for a
    /// source, or empty if nothing cached. Used by the link reconciler.
    pub fn load_cached_links_for_source(
        &self,
        source: &ExtractionSource<'_>,
    ) -> Vec<memvault_extract_abi::ExtractedLink> {
        match self.load_cached_extraction_for(source) {
            Some(ExtractionResult::Ok { links, .. }) => links,
            _ => Vec::new(),
        }
    }

    /// Access the underlying store.
    pub fn store(&self) -> &MemvaultStore {
        &self.store
    }

    /// Rebuild all derived state if the blockstore version is outdated.
    /// Rebuild derived state if blockstore version is outdated (sync).
    pub fn rebuild_if_needed(
        &self,
    ) -> Result<Option<crate::rebuild::RebuildReport>> {
        crate::rebuild::rebuild_if_needed(self)
    }

    /// Access the search index (for direct queries in local backend).
    pub fn index_ref(&self) -> &Arc<RwLock<TantivyIndex>> {
        &self.index
    }

    /// Record that the index has an uncommitted write (a write deferred its
    /// commit). The next index read flushes it.
    fn mark_index_dirty(&self) {
        self.index_dirty
            .store(true, std::sync::atomic::Ordering::Release);
    }

    /// Enable/disable deferred (batched) index commits. See the
    /// `defer_index_commits` field. Long-running hosts enable this and run
    /// [`Self::start_index_flusher`]; short-lived CLI invocations leave it off.
    pub fn set_defer_index_commits(&self, defer: bool) {
        self.defer_index_commits
            .store(defer, std::sync::atomic::Ordering::Release);
    }

    /// Land a just-written index op: commit it now, or mark the index dirty for
    /// the next flush, per [`Self::set_defer_index_commits`].
    fn commit_or_defer(&self, idx: &mut TantivyIndex) {
        if self
            .defer_index_commits
            .load(std::sync::atomic::Ordering::Acquire)
        {
            self.mark_index_dirty();
        } else if let Err(e) = idx.commit() {
            tracing::warn!("tantivy commit after index write failed: {e}");
        }
    }

    /// Spawn a background task that commits deferred index writes about once a
    /// second. Bounds how long a deferred live write — or a synced/seeded block
    /// queued by the index notifier — stays uncommitted, so a long-running host
    /// makes recent writes durable + searchable without waiting for the next
    /// index read. Dropping the returned handle does **not** stop the task
    /// (tokio detaches it); call on a tokio runtime.
    pub fn start_index_flusher(self: &Arc<Self>) -> tokio::task::JoinHandle<()> {
        let client = Arc::clone(self);
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(std::time::Duration::from_secs(1));
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                tick.tick().await;
                client.flush_index().await;
            }
        })
    }

    /// Commit any pending index write, and full-text index any blocks that
    /// entered the store without inline indexing (RBSR sync / external
    /// seeding). Called before every index read so read-your-writes holds and
    /// synced data becomes searchable on the next query.
    pub(crate) async fn flush_index(&self) {
        if !self
            .index_dirty
            .swap(false, std::sync::atomic::Ordering::AcqRel)
        {
            return;
        }
        // Drain the queue and reconstruct each node *before* taking the index
        // write lock: reconstruction (`get_doc_sync`/`get_entity_sync`) reads
        // the index via `try_read`, which would fail/deadlock against a held
        // write lock.
        let pending: Vec<String> = {
            let mut q = self
                .reindex_pending
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            q.drain().collect()
        };
        let prepared: Vec<PreparedIndex> = pending
            .iter()
            .filter_map(|node_id| self.prepare_reindex(node_id))
            .collect();

        {
            let mut idx = self.index.write().await;
            for p in prepared {
                p.apply(&mut idx);
            }
            if let Err(e) = idx.commit() {
                tracing::warn!("tantivy flush commit failed: {e}");
                // Retry on a later read. The in-memory writer already holds any
                // adds applied above; only the commit needs to land.
                self.index_dirty
                    .store(true, std::sync::atomic::Ordering::Release);
            }
        }

        // Maintain the scoped member-sets for nodes that entered via sync /
        // RBSR / external seeding (the `reindex_block` → notifier path). This
        // is the load-bearing wiring from the per-bucket-member-index plan:
        // without it a per-bucket / view×bucket set built locally would go
        // stale on sync and silently drop peer-ingested content. Driving it
        // from the *same* chokepoint that reindexes keeps "indexed" and "in
        // member-set" updated together. Runs after the Tantivy write lock is
        // released (it read-locks the freshly-committed index) and only touches
        // already-registered partitions, so it is cheap when none are built.
        if !pending.is_empty() {
            let views: Vec<(Vec<u8>, Vec<(String, String)>)> = self
                .list_views()
                .await
                .unwrap_or_default()
                .into_iter()
                .map(|v| (hex::decode(&v.cid).unwrap_or_default(), v.tags))
                .collect();
            for node_id in &pending {
                self.sync_node_scopes_with(node_id, &views).await;
            }
        }
    }

    /// Reconstruct a queued node from the blockstore into an applicable index
    /// write. Returns `None` if the node is unknown or can't be rebuilt. Does
    /// **not** touch the index write lock (uses `*_sync` getters that only
    /// `try_read` the index), so it is safe to call before acquiring it.
    fn prepare_reindex(&self, node_id: &str) -> Option<PreparedIndex> {
        let decode32 = |hex_id: &str| -> Option<[u8; 32]> {
            let bytes = hex::decode(hex_id).ok()?;
            <[u8; 32]>::try_from(bytes.as_slice()).ok()
        };

        if let Some(hex_id) = node_id.strip_prefix("doc:") {
            let id = DocId(decode32(hex_id)?);
            // include_retracted = true: the index retains retracted entries
            // (flag-only), so a synced doc is indexed regardless of retraction.
            let doc = self.get_doc_sync(&id, true).ok().flatten()?;
            let title = doc
                .frontmatter
                .get("title")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());
            let tags = self.extract_creation_tags("doc", hex_id);
            let bucket_hex = self.inferred_doc_bucket(&id).map(hex::encode);
            Some(PreparedIndex::Doc {
                id,
                body: doc.body,
                title,
                tags,
                bucket_hex,
            })
        } else if let Some(hex_id) = node_id.strip_prefix("entity:") {
            let id = EntityId(decode32(hex_id)?);
            let entity = self.get_entity_sync(&id, true).ok().flatten()?;
            let tags = self.extract_creation_tags("entity", hex_id);
            let bucket_hex = self.inferred_entity_bucket(&id).map(hex::encode);
            Some(PreparedIndex::Entity {
                id,
                kind: entity.kind,
                props: entity.props,
                tags,
                bucket_hex,
            })
        } else if let Some(hex_id) = node_id.strip_prefix("file:") {
            // The file node's surrogate id is the hex manifest CID. Recover the
            // attachment envelope via the `_manifest` reverse tag.
            let manifest_cid = hex::decode(hex_id).ok()?;
            let env_cids = self
                .store
                .query_by_tag("_manifest", hex_id, 0, usize::MAX)
                .ok()?;
            let (filename, mime, tags, bucket_hex) = env_cids.iter().rev().find_map(|cid| {
                let data = self.store.get_block(cid).ok()??;
                let view = memvault_store::EnvelopeView::parse(&data)?;
                if view.str_field("kind") != Some("attachment") {
                    return None;
                }
                let filename = view.str_field("filename").map(|s| s.to_string());
                let mime = view
                    .str_field("mime_type")
                    .unwrap_or("application/octet-stream")
                    .to_string();
                let tags: Vec<(String, String)> = view.get_as("tags").unwrap_or_default();
                let bucket_hex = view.get_as::<Vec<u8>>("bucket_id").map(hex::encode);
                Some((filename, mime, tags, bucket_hex))
            })?;
            // Cached extraction only (no re-extraction on the read path).
            let text = self.load_cached_extraction(&manifest_cid).and_then(|r| match r {
                ExtractionResult::Ok { text, .. } => Some(text),
                _ => None,
            });
            Some(PreparedIndex::Attachment {
                manifest_cid,
                filename,
                mime,
                text,
                tags,
                bucket_hex,
            })
        } else {
            None
        }
    }

    // ── Scoped indexes (scoped-indexes Phases 3/4) ─────────────────
    //
    // Listings/search are computed from the live TextIndex (the source of
    // truth, which now retains retracted entries) filtered by the bucket set
    // and view tags. The redb member-sets are maintained live as the
    // persistent realization + O(1) count cache; queries don't depend on them
    // for correctness.

    /// True if the node satisfies every dimension of the scope: retraction
    /// mode, bucket set, and (if set) the view's tag conjunction. Used by the
    /// `get_*_scoped` by-id getters to verify a fetched object is in scope.
    pub(crate) async fn node_in_scope(
        &self,
        node_id: &str,
        scope: &memvault_core::QueryScope,
    ) -> Result<bool> {
        self.flush_index().await;
        // Retraction.
        let retracted = { self.index.read().await.is_retracted(node_id) };
        if !scope.retraction.admits(retracted) {
            return Ok(false);
        }
        // View tag conjunction.
        if let Some(view_name) = &scope.view {
            if let Some((_, tags)) = self.resolve_view_coord(view_name).await? {
                let node_tags = { self.index.read().await.get_tags(node_id) };
                let in_view = tags
                    .iter()
                    .all(|(s, l)| node_tags.iter().any(|(ts, tl)| ts == s && tl == l));
                if !in_view {
                    return Ok(false);
                }
            }
        }
        // Bucket set. For a by-id fetch, only an *explicit* set narrows the
        // result — `Accessible` means "any accessible bucket" (authorization
        // is enforced separately by the ACL layer), so it doesn't drop the
        // node the way scoped listing does.
        if let memvault_core::BucketSelector::Only(_) = &scope.buckets {
            let known = self.all_bucket_id_arrays();
            let eff = self.effective_bucket_set(&scope.buckets, &known);
            if matches!(&eff, Some(s) if s.is_empty()) {
                return Ok(false);
            }
            if !self.node_passes_bucket(node_id, &known, &eff) {
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// Fetch a document by id only if it satisfies `scope`. Returns `Ok(None)`
    /// if the doc is absent OR out of scope (so handlers 404 rather than 500).
    pub(crate) async fn get_doc_scoped(
        &self,
        id: &DocId,
        scope: &memvault_core::QueryScope,
    ) -> Result<Option<Document>> {
        let node_id = format!("doc:{}", hex::encode(id.0));
        if !self.node_in_scope(&node_id, scope).await? {
            return Ok(None);
        }
        self.get_doc_async(id, scope.retraction.includes_retracted())
            .await
    }

    /// Fetch an entity by id only if it satisfies `scope`. Returns `Ok(None)`
    /// if absent OR out of scope.
    pub(crate) async fn get_entity_scoped(
        &self,
        id: &EntityId,
        scope: &memvault_core::QueryScope,
    ) -> Result<Option<Entity>> {
        let node_id = format!("entity:{}", hex::encode(id.0));
        if !self.node_in_scope(&node_id, scope).await? {
            return Ok(None);
        }
        self.get_entity_async(id, scope.retraction.includes_retracted())
            .await
    }

    /// Resolve a node's label only if it satisfies `scope`.
    pub(crate) async fn resolve_label_scoped(
        &self,
        node_id: &str,
        scope: &memvault_core::QueryScope,
    ) -> Result<Option<String>> {
        if !self.node_in_scope(node_id, scope).await? {
            return Ok(None);
        }
        let idx = self.index.read().await;
        Ok(idx.resolve_label_mode(node_id, scope.retraction))
    }

    /// Resolve a view name to `(view_cid_bytes, required_tags)`.
    pub(crate) async fn resolve_view_coord(
        &self,
        name: &str,
    ) -> Result<Option<(Vec<u8>, Vec<(String, String)>)>> {
        for v in self.list_views().await? {
            if v.name == name {
                let cid = hex::decode(&v.cid).unwrap_or_default();
                return Ok(Some((cid, v.tags)));
            }
        }
        Ok(None)
    }

    /// All 32-byte bucket ids known to the store.
    fn all_bucket_id_arrays(&self) -> std::collections::HashSet<[u8; 32]> {
        self.store
            .list_buckets()
            .unwrap_or_default()
            .into_iter()
            .filter_map(|(id, _)| id.try_into().ok())
            .collect()
    }

    /// Resolve a `BucketSelector` to the effective explicit id set, intersected
    /// with known buckets. `None` = no explicit restriction (all buckets).
    fn effective_bucket_set(
        &self,
        sel: &memvault_core::BucketSelector,
        known: &std::collections::HashSet<[u8; 32]>,
    ) -> Option<std::collections::HashSet<[u8; 32]>> {
        match sel {
            memvault_core::BucketSelector::Accessible => None,
            memvault_core::BucketSelector::Only(req) => {
                // Expand each requested (canonical) bucket with the sources
                // merged into it, so a query scoped to the canonical pulls
                // source-tagged blocks too (§5). Blocks keep their original
                // signed bucket_id; nothing is rewritten. Intersect with the
                // known set so a merge can never widen access beyond what
                // this node actually holds.
                let mut out = std::collections::HashSet::new();
                for b in req {
                    out.insert(b.0);
                    for m in self.bucket_merge_members(&b.0) {
                        out.insert(m);
                    }
                }
                out.retain(|b| known.contains(b));
                Some(out)
            }
        }
    }

    /// Whether a node passes the bucket filter given the known set and the
    /// effective explicit set (`None` = no narrowing / all accessible).
    fn node_passes_bucket(
        &self,
        node_id: &str,
        known: &std::collections::HashSet<[u8; 32]>,
        eff: &Option<std::collections::HashSet<[u8; 32]>>,
    ) -> bool {
        match eff {
            // Accessible: the search index only holds this node's own bucketed
            // content (populate keys on BY_BUCKET), so don't drop anything —
            // ACL is enforced separately at the handler layer. Dropping here on
            // envelope-parse-based bucket inference (which is unreliable) was
            // hiding most results.
            None => true,
            Some(set) => {
                if set.is_empty() {
                    return false;
                }
                if known.is_empty() {
                    return true; // pre-genesis: no bucket scoping yet
                }
                self.inferred_bucket_for_node_id(node_id)
                    .and_then(|b| <[u8; 32]>::try_from(b).ok())
                    .map(|a| set.contains(&a))
                    .unwrap_or(false)
            }
        }
    }

    /// Scoped listing: nodes matching the `(view, buckets, retracted)` triplet.
    pub(crate) async fn scoped_list(
        &self,
        scope: &memvault_core::QueryScope,
        limit: usize,
    ) -> Result<Vec<crate::types::NodeSummary>> {
        self.flush_index().await;
        let known = self.all_bucket_id_arrays();
        let eff = self.effective_bucket_set(&scope.buckets, &known);
        if matches!(&eff, Some(s) if s.is_empty()) {
            return Ok(Vec::new()); // explicit empty set → empty result
        }

        // O(bucket) fast path: an explicit, non-empty bucket set enumerates the
        // per-bucket member-sets instead of scanning every index row and
        // re-deriving each node's bucket. Gated on `entity_kind` being unset —
        // the member-sets aren't partitioned by fine-grained entity kind, so a
        // kind-filtered query keeps the index-scan path (which pushes the kind
        // clause into Tantivy). The `Accessible` (None) case also scans, since
        // it spans all buckets and never narrows by membership.
        if let Some(set) = &eff {
            if !set.is_empty() && scope.entity_kind.is_none() {
                return self.scoped_list_members(scope, set, limit).await;
            }
        }
        self.scoped_list_scan(scope, limit).await
    }

    /// Member-set enumeration backing [`Self::scoped_list`] for an explicit
    /// bucket set. Enumerates the union of the buckets' `ScopeKind::Bucket`
    /// member-sets, then applies the view-tag conjunction, node-kind, and
    /// retraction filters from the live index. O(sum of bucket members).
    async fn scoped_list_members(
        &self,
        scope: &memvault_core::QueryScope,
        set: &std::collections::HashSet<[u8; 32]>,
        limit: usize,
    ) -> Result<Vec<crate::types::NodeSummary>> {
        let view_tags = match &scope.view {
            Some(n) => self.resolve_view_coord(n).await?.map(|(_, t)| t),
            None => None,
        };
        // Union the buckets' members (dedup across buckets).
        let mut node_ids: std::collections::HashSet<String> = std::collections::HashSet::new();
        for b in set {
            self.ensure_bucket_partition(&BucketId(*b)).await?;
            let bsid = memvault_core::bucket_scope_id(&BucketId(*b));
            for (nid, _) in self.store.scope_members(
                &bsid,
                scope.retraction.includes_active(),
                scope.retraction.includes_retracted(),
                0,
            )? {
                node_ids.insert(nid);
            }
        }

        let mut out = Vec::new();
        {
            let idx = self.index.read().await;
            for node_id in &node_ids {
                let node_type = match node_id.split_once(':').map(|(p, _)| p) {
                    Some("doc") => "doc",
                    Some("entity") => "entity",
                    Some("file") | Some("attachment") => "file",
                    _ => continue,
                };
                if let Some(kind) = scope.kind {
                    if !kind.matches(node_type) {
                        continue;
                    }
                }
                // Resolve under the retraction mode — also drops nodes the index
                // doesn't hold under this mode (keeps parity with the scan).
                let Some(label) = idx.resolve_label_mode(node_id, scope.retraction) else {
                    continue;
                };
                let tags = idx.get_tags(node_id);
                // View tag conjunction.
                if let Some(vt) = &view_tags {
                    let in_view = vt
                        .iter()
                        .all(|(s, l)| tags.iter().any(|(ts, tl)| ts == s && tl == l));
                    if !in_view {
                        continue;
                    }
                }
                let retracted = idx.is_retracted(node_id);
                let detail = if scope.detail == memvault_core::DetailLevel::Full {
                    self.node_detail(node_id, node_type).await
                } else {
                    None
                };
                out.push(crate::types::NodeSummary {
                    node_id: node_id.clone(),
                    node_type: node_type.to_string(),
                    label,
                    tags,
                    retracted,
                    detail,
                });
                if out.len() >= limit {
                    break;
                }
            }
        }

        #[cfg(debug_assertions)]
        {
            // Parity: every node the authoritative index scan returns for this
            // scope must be reachable via the member-set enumeration. Catches a
            // bucket set that drifted out of sync with the index.
            let scan = self.scoped_list_scan(scope, usize::MAX).await?;
            let member_ids: std::collections::HashSet<&str> =
                node_ids.iter().map(|s| s.as_str()).collect();
            let missing: Vec<&String> = scan
                .iter()
                .map(|n| &n.node_id)
                .filter(|id| !member_ids.contains(id.as_str()))
                .collect();
            debug_assert!(
                missing.is_empty(),
                "scoped_list member-set is missing nodes the authoritative scan \
                 returned — maintenance drift: {missing:?}"
            );
        }

        Ok(out)
    }

    /// Authoritative index-scan listing backing [`Self::scoped_list`]. Used for
    /// the `Accessible` (all-buckets) case, `entity_kind`-filtered queries, and
    /// as the source of truth the member-set fast path is validated against.
    async fn scoped_list_scan(
        &self,
        scope: &memvault_core::QueryScope,
        limit: usize,
    ) -> Result<Vec<crate::types::NodeSummary>> {
        let view_tags = match &scope.view {
            Some(n) => self.resolve_view_coord(n).await?.map(|(_, t)| t),
            None => None,
        };
        let known = self.all_bucket_id_arrays();
        let eff = self.effective_bucket_set(&scope.buckets, &known);
        if matches!(&eff, Some(s) if s.is_empty()) {
            return Ok(Vec::new()); // explicit empty set → empty result
        }

        // When scoped to specific buckets, scan all index rows: a global cap
        // would drop items of a bucket whose nodes fall outside the global
        // first-N (same flaw as list_docs_ex/list_entities_ex). The result is
        // capped at `limit` in the loop below. See standards/bucket-scoping.md.
        let fetch = if limit == usize::MAX || eff.is_some() {
            usize::MAX
        } else {
            limit.saturating_mul(4).max(limit)
        };
        let rows = {
            let idx = self.index.read().await;
            idx.list_all_mode(
                view_tags.as_deref(),
                scope.entity_kind.as_deref(),
                scope.retraction,
                fetch,
            )
        };
        let mut out = Vec::new();
        for (node_id, node_type, label, tags, retracted) in rows {
            if let Some(kind) = scope.kind {
                if !kind.matches(&node_type) {
                    continue;
                }
            }
            if !self.node_passes_bucket(&node_id, &known, &eff) {
                continue;
            }
            let detail = if scope.detail == memvault_core::DetailLevel::Full {
                self.node_detail(&node_id, &node_type).await
            } else {
                None
            };
            out.push(crate::types::NodeSummary {
                node_id,
                node_type,
                label,
                tags,
                retracted,
                detail,
            });
            if out.len() >= limit {
                break;
            }
        }
        Ok(out)
    }

    /// A document's `(updated_ns, attachment_count)`. `updated_ns` is the
    /// latest envelope wall-clock for the doc; `attachment_count` mirrors
    /// `list_docs` (currently 0 — not separately tracked).
    fn doc_detail(&self, doc_id: &DocId) -> (u64, usize) {
        let (_, label) = Self::doc_tag(doc_id);
        let cids = self
            .store
            .query_by_tag("doc", &label, 0, usize::MAX)
            .unwrap_or_default();
        let mut updated_ns = 0u64;
        for cid in &cids {
            if let Ok(Some(data)) = self.store.get_block(cid) {
                if let Some(val) = memvault_store::deserialize_block(&data) {
                    if let Some(w) = val.get("wall_ns").and_then(|v| v.as_u64()) {
                        updated_ns = updated_ns.max(w);
                    }
                }
            }
        }
        (updated_ns, 0)
    }

    /// Build the type-specific [`NodeDetail`] for a node (DetailLevel::Full).
    /// Best-effort: returns `None` if the underlying data can't be loaded.
    async fn node_detail(
        &self,
        node_id: &str,
        node_type: &str,
    ) -> Option<crate::types::NodeDetail> {
        match node_type {
            "doc" => {
                let hex = node_id.strip_prefix("doc:")?;
                let bytes = hex::decode(hex).ok()?;
                let arr: [u8; 32] = bytes.try_into().ok()?;
                let doc_id = DocId(arr);
                let (updated_ns, attachment_count) = self.doc_detail(&doc_id);
                Some(crate::types::NodeDetail::Doc {
                    updated_ns,
                    attachment_count,
                })
            }
            "entity" => {
                let hex = node_id.strip_prefix("entity:")?;
                let bytes = hex::decode(hex).ok()?;
                let arr: [u8; 32] = bytes.try_into().ok()?;
                let entity = self.get_entity_async(&EntityId(arr), true).await.ok()??;
                Some(crate::types::NodeDetail::Entity {
                    entity_kind: entity.kind,
                    props: entity.props,
                })
            }
            "file" | "attachment" => {
                let hex = node_id
                    .strip_prefix("file:")
                    .or_else(|| node_id.strip_prefix("attachment:"))?;
                let manifest_cid = hex::decode(hex).ok()?;
                let bytes = self.get_file_manifest(&manifest_cid).await.ok()??;
                let m: serde_json::Value =
                    memvault_store::deserialize_block(&bytes).unwrap_or_default();
                Some(crate::types::NodeDetail::File {
                    filename: m
                        .get("filename")
                        .and_then(|v| v.as_str())
                        .unwrap_or("unnamed")
                        .to_string(),
                    mime_type: m
                        .get("mime_type")
                        .and_then(|v| v.as_str())
                        .unwrap_or("application/octet-stream")
                        .to_string(),
                    size: m.get("content_size").and_then(|v| v.as_u64()).unwrap_or(0),
                })
            }
            _ => None,
        }
    }

    /// Scoped unified search.
    pub(crate) async fn scoped_search(
        &self,
        scope: &memvault_core::QueryScope,
        query: &str,
        limit: usize,
    ) -> Result<Vec<memvault_query::UnifiedHit>> {
        self.flush_index().await;
        let view_tags = match &scope.view {
            Some(n) => self.resolve_view_coord(n).await?.map(|(_, t)| t),
            None => None,
        };
        let known = self.all_bucket_id_arrays();
        let eff = self.effective_bucket_set(&scope.buckets, &known);
        if matches!(&eff, Some(s) if s.is_empty()) {
            return Ok(Vec::new());
        }

        let fetch = limit.saturating_mul(4).max(limit);
        let (hits, view_set) = {
            let idx = self.index.read().await;
            let view_set: Option<std::collections::HashSet<String>> = view_tags
                .as_ref()
                .map(|t| idx.members_of_view_mode(t, scope.retraction).into_iter().collect());
            let hits =
                idx.search_unified_mode(query, scope.entity_kind.as_deref(), scope.retraction, fetch);
            (hits, view_set)
        };
        let mut out = Vec::new();
        for h in hits {
            if let Some(kind) = scope.kind {
                if !kind.matches(&h.node_type) {
                    continue;
                }
            }
            if let Some(set) = &view_set {
                if !set.contains(&h.node_id) {
                    continue;
                }
            }
            if !self.node_passes_bucket(&h.node_id, &known, &eff) {
                continue;
            }
            out.push(h);
            if out.len() >= limit {
                break;
            }
        }
        Ok(out)
    }

    /// Scoped active/retracted counts.
    ///
    /// For a view + explicit bucket set we use the materialized view×bucket
    /// member-sets — lazily built on first call, then maintained live — so the
    /// count is O(1) per bucket. All other shapes compute from the live index.
    pub(crate) async fn scoped_count(
        &self,
        scope: &memvault_core::QueryScope,
    ) -> Result<crate::types::ScopeCount> {
        if let (Some(view_name), memvault_core::BucketSelector::Only(bs)) =
            (&scope.view, &scope.buckets)
        {
            // The view×bucket member-sets don't partition by node kind, so a
            // kind-filtered count must take the compute path.
            if !bs.is_empty() && scope.kind.is_none() {
                if let Some((vcid, vtags)) = self.resolve_view_coord(view_name).await? {
                    let known = self.all_bucket_id_arrays();
                    let mut total = crate::types::ScopeCount::default();
                    for b in bs {
                        if !known.contains(&b.0) {
                            continue; // not an accessible bucket
                        }
                        self.ensure_view_bucket_partition(&vcid, &vtags, b).await?;
                        let sid = memvault_core::view_bucket_scope_id(&vcid, b);
                        if let Some(reg) = self.store.scope_registry_get(&sid)? {
                            total.active += reg.active_count;
                            total.retracted += reg.retracted_count;
                        }
                    }
                    return Ok(apply_retraction_mode(total, scope.retraction));
                }
            }
        }

        // Compute: one include-retracted pass, tally active vs retracted.
        let counting = memvault_core::QueryScope {
            view: scope.view.clone(),
            buckets: scope.buckets.clone(),
            retraction: memvault_core::RetractionMode::IncludeRetracted,
            kind: scope.kind,
            entity_kind: scope.entity_kind.clone(),
            // Counting never needs per-node detail.
            detail: memvault_core::DetailLevel::Summary,
        };
        let rows = self.scoped_list(&counting, usize::MAX).await?;
        let mut c = crate::types::ScopeCount::default();
        for r in rows {
            if r.retracted {
                c.retracted += 1;
            } else {
                c.active += 1;
            }
        }
        Ok(apply_retraction_mode(c, scope.retraction))
    }

    /// Lazily build + register a view×bucket member-set partition on first
    /// access. No-op if already registered (thereafter maintained live by
    /// [`sync_node_scopes`]).
    pub(crate) async fn ensure_view_bucket_partition(
        &self,
        view_cid: &[u8],
        view_tags: &[(String, String)],
        bucket: &BucketId,
    ) -> Result<()> {
        let vbsid = memvault_core::view_bucket_scope_id(view_cid, bucket);
        if self.store.scope_is_registered(&vbsid).unwrap_or(false) {
            return Ok(());
        }
        self.flush_index().await;
        let (members, retracted_set): (Vec<String>, std::collections::HashSet<String>) = {
            let idx = self.index.read().await;
            let all = idx
                .members_of_view_mode(view_tags, memvault_core::RetractionMode::IncludeRetracted);
            let retr = idx
                .members_of_view_mode(view_tags, memvault_core::RetractionMode::RetractedOnly)
                .into_iter()
                .collect();
            (all, retr)
        };
        for nid in members {
            let nb: Option<[u8; 32]> = self
                .inferred_bucket_for_node_id(&nid)
                .and_then(|b| b.try_into().ok());
            if nb == Some(bucket.0) {
                let _ = self
                    .store
                    .scope_member_upsert(&vbsid, &nid, retracted_set.contains(&nid), 0);
            }
        }
        self.store.scope_register(
            &vbsid,
            memvault_store::scope_members::ScopeKind::ViewBucket,
            view_cid,
            &bucket.0,
            0,
        )?;
        Ok(())
    }

    /// Lazily build + register a per-bucket member-set (`ScopeKind::Bucket`) on
    /// first access. No-op if already registered (thereafter maintained live by
    /// [`Self::update_view_partitions`] on local writes and by [`Self::flush_index`]
    /// for synced nodes).
    ///
    /// The set holds **every** node — document, entity, and file — whose blocks
    /// land in the bucket, each with its current retracted flag. Membership is
    /// derived from the authoritative, uncapped blockstore scan (the same
    /// inference the scan-based listings use), so the set is a faithful cache
    /// over the store (see `standards/derived-indexes.md`). Read paths filter
    /// by node-id prefix and page at their own limit.
    pub(crate) async fn ensure_bucket_partition(&self, bucket: &BucketId) -> Result<()> {
        let bsid = memvault_core::bucket_scope_id(bucket);
        if self.store.scope_is_registered(&bsid).unwrap_or(false) {
            return Ok(());
        }
        self.flush_index().await;
        // Authoritative membership universe: every CID bound to the bucket.
        // Uncapped — a recent node whose CIDs fall outside a capped window must
        // not be dropped (see `standards/exhaustive-lookups.md`).
        let bucket_cids: std::collections::HashSet<Vec<u8>> = self
            .store
            .query_by_bucket(&bucket.0, 0, usize::MAX)?
            .into_iter()
            .collect();
        // Enumerate every doc / entity / file label and keep the ones with at
        // least one CID in the bucket. The `_manifest` tag's label is the hex
        // manifest CID — the file node's surrogate id.
        let mut members: Vec<String> = Vec::new();
        for (scope, prefix) in [("doc", "doc:"), ("entity", "entity:"), ("_manifest", "file:")] {
            for label in self.store.query_unique_labels(scope, usize::MAX)? {
                let cids = self
                    .store
                    .query_by_tag(scope, &label, 0, usize::MAX)
                    .unwrap_or_default();
                if cids.iter().any(|c| bucket_cids.contains(c)) {
                    members.push(format!("{prefix}{label}"));
                }
            }
        }
        // Resolve retracted flags from the committed index in one read pass.
        let flags: Vec<(String, bool)> = {
            let idx = self.index.read().await;
            members
                .into_iter()
                .map(|nid| {
                    let retracted = idx.is_retracted(&nid);
                    (nid, retracted)
                })
                .collect()
        };
        for (nid, retracted) in &flags {
            let _ = self.store.scope_member_upsert(&bsid, nid, *retracted, 0);
        }
        self.store.scope_register(
            &bsid,
            memvault_store::scope_members::ScopeKind::Bucket,
            &[],
            &bucket.0,
            0,
        )?;
        Ok(())
    }

    /// Build a [`DocSummary`] for a document from its creation envelope.
    /// Returns `None` if no `DocCreate` envelope can be recovered. Used by the
    /// per-bucket member-set read path to hydrate enumerated doc ids.
    fn doc_summary(&self, doc_id: &DocId) -> Option<DocSummary> {
        let (_, label) = Self::doc_tag(doc_id);
        let cids = self.store.query_by_tag("doc", &label, 0, usize::MAX).ok()?;
        for cid in &cids {
            let Ok(Some(data)) = self.store.get_block(cid) else {
                continue;
            };
            let Some(val) = memvault_store::deserialize_block(&data) else {
                continue;
            };
            let Some(dc) = val.get("payload").and_then(|p| p.get("DocCreate")) else {
                continue;
            };
            let title = dc
                .get("frontmatter")
                .and_then(|fm| fm.get("title"))
                .and_then(|t| t.as_str())
                .map(|s| s.to_string());
            let tags: Vec<(String, String)> = val
                .get("tags")
                .and_then(|t| serde_json::from_value(t.clone()).ok())
                .unwrap_or_default();
            let wall_ns = val.get("wall_ns").and_then(|v| v.as_u64()).unwrap_or(0);
            return Some(DocSummary {
                id: doc_id.clone(),
                cid: cid.clone(),
                title,
                tags,
                updated_ns: wall_ns,
                attachment_count: 0,
            });
        }
        None
    }

    /// Authoritative scan-based document listing (pre-member-set behavior).
    /// Retained as the fallback for tagged / cross-bucket queries and as the
    /// source of truth the member-set is validated against.
    async fn list_docs_scan(
        &self,
        tag_filter: Option<(String, String)>,
        limit: usize,
        bucket: Option<&BucketId>,
        include_retracted: bool,
    ) -> Result<Vec<DocSummary>> {
        // Explicit bucket → scope to that bucket.
        // None → scope to all accessible buckets (or unscoped pre-genesis).
        // Exhaustive membership universe: the set we test labels against must
        // cover every block in the bucket, or a recent doc/entity (whose CIDs
        // fall outside a capped window) is silently dropped from the listing.
        // The RESULT is still capped at `limit` below (pagination). See
        // standards: exhaustive-lookups.
        let scan_cap = usize::MAX;
        let bucket_cid_set: Option<std::collections::HashSet<Vec<u8>>> =
            if let Some(bid) = bucket {
                let bucket_cids = self.store.query_by_bucket(&bid.0, 0, scan_cap)?;
                Some(bucket_cids.into_iter().collect())
            } else {
                let all = self.accessible_bucket_cids(scan_cap)?;
                if all.is_empty() { None } else { Some(all) }
            };

        let cids = if let Some((ref scope, ref label)) = tag_filter {
            self.store.query_by_tag(scope, label, 0, limit * 5)?
        } else {
            // Scan all doc labels when bucket-scoped: a global cap would drop
            // docs of any bucket outside the global first-N (same flaw as
            // list_entities_ex). The result is capped at `limit` below.
            let label_cap = if bucket_cid_set.is_some() {
                usize::MAX
            } else {
                limit * 5
            };
            self.store
                .query_unique_labels("doc", label_cap)?
                .into_iter()
                .flat_map(|label| {
                    self.store
                        // Exhaustive membership: any of this doc's CIDs may be
                        // the bucket-matching one (see standards).
                        .query_by_tag("doc", &label, 0, usize::MAX)
                        .unwrap_or_default()
                })
                .collect()
        };

        let mut summaries = Vec::new();
        let mut seen_docs: std::collections::HashSet<DocId> = std::collections::HashSet::new();

        for cid in &cids {
            if summaries.len() >= limit {
                break;
            }
            // Skip CIDs not in the active bucket (when filtered).
            if let Some(ref bset) = bucket_cid_set {
                if !bset.contains(cid) {
                    continue;
                }
            }
            if let Some(data) = self.store.get_block(cid)? {
                if let Some(val) = memvault_store::deserialize_block(&data) {
                    if let Some(payload) = val.get("payload") {
                        if let Some(dc) = payload.get("DocCreate") {
                            if let Ok(doc_id) =
                                serde_json::from_value::<DocId>(dc["doc_id"].clone())
                            {
                                if seen_docs.insert(doc_id.clone()) {
                                    let node_id = format!("doc:{}", hex::encode(doc_id.0));
                                    if !include_retracted {
                                        let idx = self.index.read().await;
                                        if idx.is_retracted(&node_id) {
                                            continue;
                                        }
                                        drop(idx);
                                    }
                                    let title = dc
                                        .get("frontmatter")
                                        .and_then(|fm| fm.get("title"))
                                        .and_then(|t| t.as_str())
                                        .map(|s| s.to_string());
                                    let tags: Vec<(String, String)> = val
                                        .get("tags")
                                        .and_then(|t| serde_json::from_value(t.clone()).ok())
                                        .unwrap_or_default();
                                    let wall_ns =
                                        val.get("wall_ns").and_then(|v| v.as_u64()).unwrap_or(0);

                                    summaries.push(DocSummary {
                                        id: doc_id,
                                        cid: cid.clone(),
                                        title,
                                        tags,
                                        updated_ns: wall_ns,
                                        attachment_count: 0,
                                    });
                                }
                            }
                        }
                    }
                }
            }
        }

        Ok(summaries)
    }

    /// Authoritative scan-based entity listing (pre-member-set behavior).
    /// Retained as the fallback for cross-bucket queries and as the source of
    /// truth the member-set is validated against.
    async fn list_entities_scan(
        &self,
        limit: usize,
        bucket: Option<&BucketId>,
        include_retracted: bool,
    ) -> Result<Vec<Entity>> {
        // Explicit bucket → scope to that bucket.
        // None → scope to all accessible buckets (or unscoped pre-genesis).
        // Exhaustive membership universe: the set we test labels against must
        // cover every block in the bucket, or a recent doc/entity (whose CIDs
        // fall outside a capped window) is silently dropped from the listing.
        // The RESULT is still capped at `limit` below (pagination). See
        // standards: exhaustive-lookups.
        let scan_cap = usize::MAX;
        let bucket_cid_set: Option<std::collections::HashSet<Vec<u8>>> =
            if let Some(bid) = bucket {
                let bucket_cids = self.store.query_by_bucket(&bid.0, 0, scan_cap)?;
                Some(bucket_cids.into_iter().collect())
            } else {
                let all = self.accessible_bucket_cids(scan_cap)?;
                if all.is_empty() { None } else { Some(all) }
            };

        // When scoped to a bucket, the global `limit` cap on labels would
        // wrongly drop entities (including the per-bucket VFS root, which
        // breaks `ensure_root` → mkdir/resolve) of any bucket whose entities
        // fall outside the global first-`limit`. Scan all entity labels and
        // cap the *filtered* result at `limit` instead.
        let label_cap = if bucket_cid_set.is_some() {
            usize::MAX
        } else {
            limit
        };
        let labels = self.store.query_unique_labels("entity", label_cap)?;
        let mut entities = Vec::new();
        for label in labels {
            if entities.len() >= limit {
                break;
            }
            // When bucket-filtered, check if any of this entity's CIDs are in the bucket.
            if let Some(ref bset) = bucket_cid_set {
                let entity_cids = self
                    .store
                    // Exhaustive membership (see standards: exhaustive-lookups).
                    .query_by_tag("entity", &label, 0, usize::MAX)
                    .unwrap_or_default();
                if !entity_cids.iter().any(|c| bset.contains(c)) {
                    continue;
                }
            }
            let id_bytes = hex::decode(&label).unwrap_or_default();
            if id_bytes.len() != 32 {
                continue;
            }
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&id_bytes);
            let entity_id = EntityId(arr);
            if let Ok(Some(entity)) = self
                .get_entity_async(&entity_id, include_retracted)
                .await
            {
                entities.push(entity);
            }
        }
        Ok(entities)
    }

    /// Debug-only invariant: every node the authoritative bucket scan returns
    /// must be present in the per-bucket member-set. Catches maintenance drift
    /// (a sync/write path that failed to update the set) before it can silently
    /// drop content from a listing. `prefix` selects the node kind ("doc:",
    /// "entity:", "file:"). Stripped from release builds.
    #[cfg(debug_assertions)]
    async fn debug_assert_bucket_parity(
        &self,
        bucket: &BucketId,
        include_retracted: bool,
        prefix: &str,
    ) {
        let bsid = memvault_core::bucket_scope_id(bucket);
        let members: std::collections::HashSet<String> = self
            .store
            .scope_members(&bsid, true, include_retracted, 0)
            .unwrap_or_default()
            .into_iter()
            .map(|(nid, _)| nid)
            .filter(|nid| nid.starts_with(prefix))
            .collect();
        let scan: std::collections::HashSet<String> = match prefix {
            "doc:" => self
                .list_docs_scan(None, usize::MAX, Some(bucket), include_retracted)
                .await
                .unwrap_or_default()
                .into_iter()
                .map(|s| format!("doc:{}", hex::encode(s.id.0)))
                .collect(),
            "entity:" => self
                .list_entities_scan(usize::MAX, Some(bucket), include_retracted)
                .await
                .unwrap_or_default()
                .into_iter()
                .map(|e| format!("entity:{}", hex::encode(e.id.0)))
                .collect(),
            _ => return,
        };
        let missing: Vec<&String> = scan.difference(&members).collect();
        debug_assert!(
            missing.is_empty(),
            "per-bucket member-set ({prefix}) is missing nodes the authoritative \
             scan returned — maintenance drift: {missing:?}"
        );
    }

    /// Live member-set maintenance for a single node: refreshes its membership
    /// in every already-registered view×bucket partition from the current
    /// index state. Cheap (only touches built partitions) and best-effort.
    pub(crate) async fn sync_node_scopes(&self, node_id: &str) {
        let views = self.list_views().await.unwrap_or_default();
        let views: Vec<(Vec<u8>, Vec<(String, String)>)> = views
            .into_iter()
            .map(|v| (hex::decode(&v.cid).unwrap_or_default(), v.tags))
            .collect();
        self.sync_node_scopes_with(node_id, &views).await;
    }

    /// As [`sync_node_scopes`] but with a precomputed view list (avoids a
    /// `list_views` scan per node during bulk rebuilds). Reads the node's
    /// current tags/retracted from the index, so the caller must have flushed
    /// any pending index write first.
    pub(crate) async fn sync_node_scopes_with(
        &self,
        node_id: &str,
        views: &[(Vec<u8>, Vec<(String, String)>)],
    ) {
        let (tags, retracted, exists) = {
            let idx = self.index.read().await;
            let exists = idx
                .resolve_label_mode(node_id, memvault_core::RetractionMode::IncludeRetracted)
                .is_some();
            (idx.get_tags(node_id), idx.is_retracted(node_id), exists)
        };
        if !exists {
            return;
        }
        self.update_view_partitions(node_id, &tags, retracted, views);
    }

    /// Member-set maintenance for a freshly-created node using explicit state
    /// (tags from the write, retracted=false) — does NOT read the Tantivy
    /// index, so the write's commit can stay deferred (enables batching on the
    /// bulk-create hot path). The node's bucket is resolved from the
    /// blockstore (already written), not the index.
    pub(crate) async fn sync_node_created(&self, node_id: &str, tags: &[(String, String)]) {
        let views = self.list_views().await.unwrap_or_default();
        let views: Vec<(Vec<u8>, Vec<(String, String)>)> = views
            .into_iter()
            .map(|v| (hex::decode(&v.cid).unwrap_or_default(), v.tags))
            .collect();
        self.update_view_partitions(node_id, tags, false, &views);
    }

    /// Update every registered view×bucket partition's membership for a node,
    /// given its tags + retracted state. The node's bucket is inferred from the
    /// blockstore (no index read).
    fn update_view_partitions(
        &self,
        node_id: &str,
        tags: &[(String, String)],
        retracted: bool,
        views: &[(Vec<u8>, Vec<(String, String)>)],
    ) {
        let bucket: Option<[u8; 32]> = self
            .inferred_bucket_for_node_id(node_id)
            .and_then(|b| b.try_into().ok());
        let Some(b) = bucket else {
            return; // unbucketed node: not part of any view×bucket partition
        };
        // Per-bucket member-set (`ScopeKind::Bucket`): the node always belongs
        // to its inferred bucket regardless of tags, so just refresh its
        // active/retracted flag. Gated on registration like the view×bucket
        // sets — only maintain a set that has been lazily built (see
        // `ensure_bucket_partition`).
        let bsid = memvault_core::bucket_scope_id(&BucketId(b));
        if self.store.scope_is_registered(&bsid).unwrap_or(false) {
            let _ = self.store.scope_member_upsert(&bsid, node_id, retracted, 0);
        }
        for (vcid, vtags) in views {
            let vbsid = memvault_core::view_bucket_scope_id(vcid, &BucketId(b));
            if !self.store.scope_is_registered(&vbsid).unwrap_or(false) {
                continue; // only maintain partitions that have been built (lazy)
            }
            let matches = vtags.is_empty()
                || vtags
                    .iter()
                    .all(|(s, l)| tags.iter().any(|(ts, tl)| ts == s && tl == l));
            if matches {
                let _ = self.store.scope_member_upsert(&vbsid, node_id, retracted, 0);
            } else {
                let _ = self.store.scope_member_remove(&vbsid, node_id);
            }
        }
    }

    /// Access the quota manager.
    pub fn quotas(&self) -> &Arc<RwLock<QuotaManager>> {
        &self.quotas
    }

    /// Extract user-facing tags from the creation envelope for a given node.
    /// Scans envelopes tagged (tag_key, label) and returns all non-internal tags.
    fn extract_creation_tags(&self, tag_key: &str, label: &str) -> Vec<(String, String)> {
        let cids = self
            .store
            .query_by_tag(tag_key, label, 0, 1)
            .unwrap_or_default();
        for cid in &cids {
            if let Ok(Some(data)) = self.store.get_block(cid) {
                if let Some(env) = memvault_store::deserialize_block(&data) {
                    if let Some(tags_arr) = env.get("tags").and_then(|v| v.as_array()) {
                        return tags_arr
                            .iter()
                            .filter_map(|v| {
                                let pair = v.as_array()?;
                                let scope = pair.first()?.as_str()?;
                                let lbl = pair.get(1)?.as_str()?;
                                // Skip internal tags (doc/entity ID tags).
                                if scope == "doc"
                                    || scope == "entity"
                                    || scope == "edge_source"
                                    || scope == "edge_target"
                                {
                                    return None;
                                }
                                Some((scope.to_string(), lbl.to_string()))
                            })
                            .collect();
                    }
                }
            }
        }
        vec![]
    }

    /// Resolve a bucket_id: explicit only, no fallback.
    fn resolve_bucket(&self, explicit: Option<&BucketId>) -> Option<Vec<u8>> {
        explicit.map(|b| b.0.to_vec())
    }

    /// Require an explicit bucket for write operations.
    ///
    /// Returns the bucket bytes or an error.  Pre-genesis (no buckets in
    /// the store) is tolerated — returns `None` so the write proceeds
    /// without a bucket.
    fn require_bucket(&self, explicit: Option<&BucketId>) -> Result<Option<Vec<u8>>> {
        if let Some(b) = explicit {
            return Ok(Some(b.0.to_vec()));
        }
        // Pre-genesis: no buckets exist yet, allow unbucketed writes.
        let buckets = self.store.list_buckets().unwrap_or_default();
        if buckets.is_empty() {
            return Ok(None);
        }
        Err(ApiError::Other(
            "bucket required: pass an explicit bucket_id".into(),
        ))
    }

    /// Find the legacy bucket (BucketRole::Legacy) for adoption of
    /// pre-bucket data. Sync, internal — the `MemvaultClient::legacy_bucket_id`
    /// trait method is the public async / `Result`-returning version.
    pub fn find_legacy_bucket(&self) -> Option<BucketId> {
        if let Ok(buckets) = self.store.list_buckets() {
            for (_bucket_id_bytes, decl_cid) in &buckets {
                if let Ok(Some(block)) = self.store.get_block(decl_cid) {
                    if let Some(decl) = Self::parse_bucket_decl(&block) {
                        if decl.role == memvault_doc::BucketRole::Legacy {
                            return Some(decl.bucket_id);
                        }
                    }
                }
            }
        }
        None
    }

    /// Collect all CIDs across all accessible buckets (for cross-bucket search).
    /// Currently returns all cluster-bound buckets — grant-based filtering
    /// can be layered on top when per-credential ACLs are enforced.
    fn accessible_bucket_cids(
        &self,
        per_bucket_limit: usize,
    ) -> Result<std::collections::HashSet<Vec<u8>>> {
        let buckets = self.store.list_buckets().unwrap_or_default();
        let mut all_cids = std::collections::HashSet::new();
        for (bucket_id, _) in &buckets {
            if let Ok(cids) = self.store.query_by_bucket(bucket_id, 0, per_bucket_limit) {
                all_cids.extend(cids);
            }
        }
        Ok(all_cids)
    }

    /// Parse a BucketDecl from a block: handles both the new envelope format
    /// (payload.BucketCreate) and the legacy raw BucketDecl JSON.
    pub fn parse_bucket_decl_static(block: &[u8]) -> Option<memvault_doc::BucketDecl> {
        Self::parse_bucket_decl(block)
    }

    fn parse_bucket_decl(block: &[u8]) -> Option<memvault_doc::BucketDecl> {
        let val: serde_json::Value = memvault_store::deserialize_block(block)?;
        if let Some(bc) = val.get("payload").and_then(|p| p.get("BucketCreate")) {
            serde_json::from_value(bc.clone()).ok()
        } else {
            serde_json::from_value(val).ok()
        }
    }

    fn bucket_id_from_envelope_bytes(data: &[u8]) -> Option<Vec<u8>> {
        let val: serde_json::Value = memvault_store::deserialize_block(data)?;
        val.get("bucket_id")
            .and_then(|v| serde_json::from_value(v.clone()).ok())
    }

    /// Top-level `agent_attestation` CID from an envelope, if present.
    /// Returns `None` for legacy envelopes (pre-Signed<T> v3) and for
    /// system writes that weren't agent-attributed.
    fn agent_attestation_from_envelope_bytes(data: &[u8]) -> Option<Vec<u8>> {
        let val: serde_json::Value = memvault_store::deserialize_block(data)?;
        val.get("agent_attestation")
            .and_then(|v| serde_json::from_value(v.clone()).ok())
    }

    fn author_from_envelope_bytes(data: &[u8]) -> Option<Vec<u8>> {
        let val: serde_json::Value = memvault_store::deserialize_block(data)?;
        val.get("author")
            .and_then(|v| serde_json::from_value(v.clone()).ok())
    }

    fn latest_bucket_from_cids(&self, cids: &[Vec<u8>]) -> Option<Vec<u8>> {
        let mut bucket_id = None;
        for cid in cids {
            if let Ok(Some(data)) = self.store.get_block(cid) {
                if let Some(found) = Self::bucket_id_from_envelope_bytes(&data) {
                    bucket_id = Some(found);
                }
            }
        }
        bucket_id
    }

    fn inferred_doc_bucket(&self, id: &DocId) -> Option<Vec<u8>> {
        let (_, label) = Self::doc_tag(id);
        let cids = self.store.query_by_tag("doc", &label, 0, usize::MAX).ok()?;
        self.latest_bucket_from_cids(&cids)
    }

    fn inferred_entity_bucket(&self, id: &EntityId) -> Option<Vec<u8>> {
        let label: String = id.0.iter().map(|b| format!("{b:02x}")).collect();
        let cids = self
            .store
            .query_by_tag("entity", &label, 0, usize::MAX)
            .ok()?;
        self.latest_bucket_from_cids(&cids)
    }

    /// Returns true if at least one block in `cids` was authored by
    /// the local node or, when an agent identity is bound, by that
    /// agent. Handles both legacy raw-JSON envelopes (author == agent
    /// pubkey or peer_id at write time) and post-migration Signed<T>
    /// envelopes (author == node peer_id; agent identity carried in
    /// `agent_attestation`).
    fn has_local_author(&self, cids: &[Vec<u8>]) -> bool {
        let local_effective = self.effective_author();
        let local_peer_id = &self.peer_id;
        let local_agent_att = self.agent_attestation_cid().map(|c| c.to_vec());
        for cid in cids {
            if let Ok(Some(data)) = self.store.get_block(cid) {
                // Signed<T> v3: agent attribution lives in `agent_attestation`.
                if let Some(att) = Self::agent_attestation_from_envelope_bytes(&data) {
                    if local_agent_att.as_ref() == Some(&att) {
                        return true;
                    }
                }
                if let Some(author) = Self::author_from_envelope_bytes(&data) {
                    // Match legacy (author == effective_author at write
                    // time) and Signed<T> node-only writes (author == peer_id).
                    if author == local_effective || &author == local_peer_id {
                        return true;
                    }
                }
            }
        }
        false
    }

    /// Returns true if at least one block for this entity was authored locally.
    pub fn entity_has_local_author(&self, id: &EntityId) -> bool {
        let label: String = id.0.iter().map(|b| format!("{b:02x}")).collect();
        let cids = self
            .store
            .query_by_tag("entity", &label, 0, usize::MAX)
            .unwrap_or_default();
        self.has_local_author(&cids)
    }

    fn inferred_attachment_bucket(&self, manifest_cid: &[u8]) -> Option<Vec<u8>> {
        let manifest_hex = hex::encode(manifest_cid);
        let mut cids = self
            .store
            .query_by_tag("_manifest", &manifest_hex, 0, usize::MAX)
            .ok()?;
        if cids.is_empty() {
            cids = self
                .store
                .query_by_tag("attachment", &manifest_hex, 0, usize::MAX)
                .ok()?;
        }
        self.latest_bucket_from_cids(&cids)
    }

    fn inferred_node_bucket(&self, node: &NodeRef) -> Option<Vec<u8>> {
        match node {
            NodeRef::Doc(id) => self.inferred_doc_bucket(id),
            NodeRef::Entity(id) => self.inferred_entity_bucket(id),
            NodeRef::Attachment(cid) => self.inferred_attachment_bucket(cid),
        }
    }

    fn inferred_bucket_for_node_id(&self, node_id: &str) -> Option<Vec<u8>> {
        if let Some(node) = NodeRef::from_tag_label(node_id) {
            if let Some(bucket) = self.inferred_node_bucket(&node) {
                return Some(bucket);
            }
            // Document extraction annotations are keyed by the head op CID
            // (`doc:<cid>`) rather than the stable DocId, so `NodeRef`
            // parsing alone cannot find their bucket. Fall through and try
            // the hex suffix as an envelope CID before treating it as
            // unbucketed legacy data.
        }
        if let Some(hex_part) = node_id.strip_prefix("doc:") {
            let cid = hex::decode(hex_part).ok()?;
            if let Ok(Some(data)) = self.store.get_block(&cid) {
                return Self::bucket_id_from_envelope_bytes(&data);
            }
            return None;
        }
        if let Some(hex_part) = node_id.strip_prefix("file:") {
            let cid = hex::decode(hex_part).ok()?;
            return self.inferred_attachment_bucket(&cid);
        }
        if let Some(hex_part) = node_id.strip_prefix("attachment:") {
            let cid = hex::decode(hex_part).ok()?;
            return self.inferred_attachment_bucket(&cid);
        }
        None
    }

    /// Public wrapper around [`Self::inferred_node_bucket`] for the
    /// link reconciler module.
    pub fn inferred_node_bucket_pub(&self, node: &NodeRef) -> Option<Vec<u8>> {
        self.inferred_node_bucket(node)
    }

    /// Resolve the bucket a document currently lives in by walking its
    /// envelope history. `None` means either the doc doesn't exist or it
    /// is pre-bucket / unscoped legacy data — callers (e.g. the ACL
    /// layer) should treat that as "no enforcement target" and let the
    /// downstream lookup decide.
    pub fn bucket_for_doc(&self, id: &DocId) -> Option<BucketId> {
        let bytes = self.inferred_doc_bucket(id)?;
        let arr: [u8; 32] = bytes.try_into().ok()?;
        Some(BucketId(arr))
    }

    /// Resolve the bucket an entity lives in. See [`Self::bucket_for_doc`]
    /// for the `None` semantics.
    pub fn bucket_for_entity(&self, id: &EntityId) -> Option<BucketId> {
        let bytes = self.inferred_entity_bucket(id)?;
        let arr: [u8; 32] = bytes.try_into().ok()?;
        Some(BucketId(arr))
    }

    /// Resolve the bucket a file attachment lives in (keyed by its
    /// manifest CID).
    pub fn bucket_for_file(&self, manifest_cid: &[u8]) -> Option<BucketId> {
        let bytes = self.inferred_attachment_bucket(manifest_cid)?;
        let arr: [u8; 32] = bytes.try_into().ok()?;
        Some(BucketId(arr))
    }

    /// Resolve the bucket for any node id string (`doc:<hex>`,
    /// `entity:<hex>`, `file:<hex>`, `attachment:<hex>`).
    pub fn bucket_for_node_id(&self, node_id: &str) -> Option<BucketId> {
        let bytes = self.inferred_bucket_for_node_id(node_id)?;
        let arr: [u8; 32] = bytes.try_into().ok()?;
        Some(BucketId(arr))
    }

    /// Find the most recent op CID for a document (its "head").
    pub fn latest_doc_head_cid(&self, doc_id: &DocId) -> Option<Vec<u8>> {
        let label: String = doc_id.0.iter().map(|b| format!("{b:02x}")).collect();
        let cids = self.store.query_by_tag("doc", &label, 0, usize::MAX).ok()?;
        // query_by_tag returns insertion order; the most recent is last.
        cids.into_iter().last()
    }

    /// Cached out-links for a document (read from the latest extraction
    /// annotation). Returns an empty vec if nothing is cached.
    pub fn doc_outlinks(&self, doc_id: &DocId) -> Vec<memvault_extract_abi::ExtractedLink> {
        let Some(head_cid) = self.latest_doc_head_cid(doc_id) else {
            return Vec::new();
        };
        let source = ExtractionSource::Document {
            doc_id: doc_id.clone(),
            head_cid: &head_cid,
            mime: "text/markdown",
            body: &[],
        };
        self.load_cached_links_for_source(&source)
    }

    /// In-links pointing at `node` — graph edges whose target is `node`
    /// and whose provenance is body/frontmatter (operator-asserted edges
    /// are returned too).
    pub fn doc_backlinks(&self, node: &NodeRef) -> Result<Vec<(NodeRef, Edge)>> {
        let all = self.edges_of_sync(node)?;
        Ok(all
            .into_iter()
            .filter(|(_, edge)| edge.target == *node)
            .collect())
    }

    /// Body-provenance edges whose target is an alias placeholder. Each
    /// entry is `(source_node, alias_string)`. `bucket` filters by inferred
    /// source bucket when provided.
    pub fn dangling_link_edges(
        &self,
        bucket_filter: Option<&BucketId>,
    ) -> Result<Vec<(NodeRef, String)>> {
        // Scan all body-provenance edges across docs by walking the
        // `edge_source` tag space — we know every doc-sourced edge gets
        // tagged with `edge_source: doc:<hex>`.
        let labels = self
            .store
            .query_unique_labels("edge_source", usize::MAX)
            .unwrap_or_default();
        let mut out = Vec::new();
        for label in labels {
            // Only docs are interesting as link sources here.
            let Some(node) = NodeRef::from_tag_label(&label) else {
                continue;
            };
            if !matches!(node, NodeRef::Doc(_)) {
                continue;
            }
            if let Some(bf) = bucket_filter {
                let Some(inferred) = self.inferred_node_bucket(&node) else {
                    continue;
                };
                if inferred != bf.0.to_vec() {
                    continue;
                }
            }
            let edges = self.edges_of_sync(&node)?;
            for (src, edge) in edges {
                if src != node {
                    continue;
                }
                if memvault_doc::link::LinkProvenance::of(&edge)
                    != Some(memvault_doc::link::LinkProvenance::BodyMarkdown)
                {
                    continue;
                }
                if let Some(alias) = edge
                    .props
                    .get("pending_alias")
                    .and_then(|v| v.as_str())
                {
                    out.push((node.clone(), alias.to_string()));
                }
            }
        }
        Ok(out)
    }

    /// Re-parse and re-reconcile a single document's body. Returns the
    /// op CID of the head that was re-extracted, or `Ok(None)` if there's
    /// no body to extract.
    pub async fn reindex_doc_links(&self, doc_id: &DocId) -> Result<Option<Vec<u8>>> {
        let head_cid = match self.latest_doc_head_cid(doc_id) {
            Some(c) => c,
            None => return Ok(None),
        };
        let Some(doc) = self.get_doc_async(doc_id, false).await? else {
            return Ok(None);
        };
        let _ = self.extract_doc_and_cache(doc_id, &head_cid, &doc.body, &doc.frontmatter);
        Ok(Some(head_cid))
    }

    /// Re-parse and re-reconcile every document's body. Returns the
    /// number of docs visited.
    pub async fn reindex_all_doc_links(&self) -> Result<usize> {
        let labels = self
            .store
            .query_unique_labels("doc", usize::MAX)
            .unwrap_or_default();
        let mut count = 0usize;
        for label in labels {
            let Ok(bytes) = hex::decode(&label) else {
                continue;
            };
            if bytes.len() != 32 {
                continue;
            }
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            let doc_id = DocId(arr);
            if self.reindex_doc_links(&doc_id).await?.is_some() {
                count += 1;
            }
        }
        Ok(count)
    }

    /// Public wrapper around [`Self::store_op`] for the link reconciler.
    pub fn store_op_pub(
        &self,
        op: &Op,
        tags: &[(String, String)],
        vis: &Visibility,
        bucket: Option<&BucketId>,
    ) -> Result<Vec<u8>> {
        self.store_op(op, tags, vis, bucket)
    }

    fn store_op(
        &self,
        op: &Op,
        tags: &[(String, String)],
        vis: &Visibility,
        bucket: Option<&BucketId>,
    ) -> Result<Vec<u8>> {
        let wall_ns = memvault_core::wall_ns();
        let bucket_id = self.require_bucket(bucket)?;

        // The op IS the payload — preserves `payload.<OpKind>` access for
        // existing readers (`list_docs` extracting `DocCreate`, etc.).
        // `cluster_id` is conveyed via `meta` for indexing rather than
        // a top-level envelope field.
        let payload = serde_json::to_value(op)
            .map_err(|e| ApiError::Serialization(e.to_string()))?;
        let (cid_bytes, envelope_bytes) = self.build_signed_envelope(
            payload,
            tags,
            vis.clone(),
            wall_ns,
            bucket_id.as_deref(),
        )?;

        let meta = EnvelopeMeta {
            author: self.effective_author(),
            tags: tags.to_vec(),
            wall_ns,
            causal: vec![],
            provenance: vec![],
            cluster_id: Some(self.cluster_id.clone()),
            bucket_id,
        };

        self.store
            .insert_envelope(&cid_bytes, &envelope_bytes, &meta)?;

        Ok(cid_bytes)
    }

    fn doc_tag(doc_id: &DocId) -> (String, String) {
        let label: String = doc_id.0.iter().map(|b| format!("{b:02x}")).collect();
        ("doc".to_string(), label)
    }

    /// List entities without bucket scoping.  Used only by repair-index
    /// which needs to see unbucketed items for adoption.
    pub async fn list_entities_unscoped(&self, limit: usize) -> Result<Vec<Entity>> {
        let labels = self.store.query_unique_labels("entity", limit)?;
        let mut entities = Vec::new();
        for label in labels {
            let id_bytes = hex::decode(&label).unwrap_or_default();
            if id_bytes.len() != 32 {
                continue;
            }
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&id_bytes);
            let entity_id = EntityId(arr);
            if let Ok(Some(entity)) = self.get_entity(&entity_id).await {
                entities.push(entity);
            }
        }
        Ok(entities)
    }

    /// Issue a join token carrying the opt-in **admit-as-admin**
    /// capability: redeeming it may also admit the joiner's supplied admin
    /// key as a co-equal cluster admin (if the join request includes a
    /// valid POP), in addition to the node attestation. Normal
    /// `issue_token` tokens never confer admin authority.
    pub async fn issue_admin_admit_token(
        &self,
        ttl_secs: u64,
        max_uses: u32,
        label: Option<String>,
    ) -> Result<String> {
        let now_ns = memvault_core::wall_ns();
        let admin_key = self.admin_signing_key_at_ns(now_ns).ok_or_else(|| {
            ApiError::Other("no valid admin signing key — cannot issue tokens".into())
        })?;
        let peer_id = memvault_core::PeerId(self.peer_id.clone());
        let cluster_id = memvault_core::ClusterId(self.cluster_id_arr()?);
        crate::tokens::issue_token(
            &peer_id,
            &cluster_id,
            &admin_key,
            memvault_auth::TokenRole::Node(memvault_auth::NodeRole::Admin),
            ttl_secs,
            max_uses,
            label,
            self.pinned_admin_genesis().cloned(),
            vec![],
            &self.keystore,
        )
    }

    // ── Bucket grants (ACL) ──────────────────────────────────────────

    /// Issue a grant scoped to a bucket.  The grant is signed by the admin
    /// key and stored as a tagged block for lookup.
    pub async fn issue_bucket_grant(
        &self,
        bucket_id: &BucketId,
        audience: memvault_auth::GrantAudience,
        actions: Vec<memvault_auth::Action>,
        ttl_secs: u64,
    ) -> Result<Vec<u8>> {
        let now_ns = memvault_core::wall_ns();
        // Pick the best signing authority this node holds for the bucket:
        // a cluster admin key, the held owner-agent key, or the node key
        // (for node-owned buckets or buckets owned by an agent this node
        // attested). The signer pubkey is recorded in the grant and bound
        // into its signature, so ACL enforcement can verify both the
        // signature and the issuer's authority.
        let (signer, admin_pubkey) = self.pick_grant_signer(bucket_id).ok_or_else(|| {
            ApiError::Other("no grant-signing authority for this bucket".into())
        })?;

        // `saturating_*` so callers can pass `u64::MAX` for "never expires"
        // without wrapping.
        let ttl_ns = ttl_secs.saturating_mul(1_000_000_000);
        let not_after_ns = now_ns.saturating_add(ttl_ns);
        let mut nonce = [0u8; 16];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut nonce);

        let cluster_id_arr: [u8; 32] = self
            .cluster_id
            .clone()
            .try_into()
            .map_err(|_| ApiError::Other("cluster_id must be 32 bytes".into()))?;

        let mut grant = memvault_auth::Grant {
            issuer: memvault_core::PeerId(self.peer_id.clone()),
            issuing_cluster: memvault_core::ClusterId(cluster_id_arr),
            admin_pubkey,
            audience,
            scopes: vec![],
            actions,
            not_before_ns: now_ns,
            not_after_ns,
            parent: None,
            nonce,
            bucket_scopes: vec![bucket_id.clone()],
            signature: [0u8; 64],
        };

        // Sign
        let signing_bytes = grant
            .signing_bytes()
            .map_err(|e| ApiError::Other(format!("grant signing failed: {e}")))?;
        use ed25519_dalek::Signer;
        let sig = signer.sign(&signing_bytes);
        grant.signature = sig.to_bytes();

        // Store as tagged block
        let grant_json = serde_ipld_dagcbor::to_vec(&grant)
            .map_err(|e| ApiError::Serialization(e.to_string()))?;
        let cid = memvault_core::cid_from_bytes(&grant_json);
        let cid_bytes = cid.to_bytes();

        let bucket_hex = hex::encode(bucket_id.0);
        let meta = memvault_store::EnvelopeMeta {
            author: self.effective_author(),
            // `("grant", <bucket_hex>)` is what `list_bucket_grants`
            // queries by; `("kind", "grant")` is the kind index entry.
            // `("sigchain", "grant")` is what makes the
            // `install_sigchain_notifier` callback fire — without it the
            // block lands in the local store but never triggers a
            // gossipsub head announcement, so peers only learn about
            // the grant on the next RBSR cycle (or never, if no other
            // sigchain block is written before the RBSR partner pool
            // turns over). Sister sigchain helpers tag the same way.
            tags: vec![
                ("grant".to_string(), bucket_hex),
                ("kind".to_string(), "grant".to_string()),
                ("sigchain".to_string(), "grant".to_string()),
            ],
            wall_ns: now_ns,
            causal: vec![],
            provenance: vec![],
            cluster_id: Some(self.cluster_id.clone()),
            bucket_id: Some(bucket_id.0.to_vec()),
                    ..Default::default()
        };
        self.store.insert_envelope(&cid_bytes, &grant_json, &meta)?;

        tracing::info!(bucket = %bucket_id, cid = %hex::encode(&cid_bytes), "bucket grant issued");
        Ok(cid_bytes)
    }

    /// Store a fully-formed, externally-signed grant (path 2: an agent or
    /// owner signed it client-side, e.g. a remote agent whose key this
    /// daemon never holds). The daemon validates and relays — it does NOT
    /// sign. Checks: the signature is authentic for the embedded issuer;
    /// the grant scopes exactly one bucket; and that issuer is authorised
    /// to grant on it (admin / owner agent / attesting node / node owner).
    /// Returns the stored grant CID.
    pub fn submit_signed_grant(&self, grant: &memvault_auth::Grant) -> Result<Vec<u8>> {
        if grant.is_legacy_unsigned() || grant.verify_admin_signature().is_err() {
            return Err(ApiError::Forbidden("grant signature is not authentic".into()));
        }
        // Exactly one bucket scope, so authority is unambiguous.
        let bucket_id = match grant.bucket_scopes.as_slice() {
            [b] => b.clone(),
            _ => {
                return Err(ApiError::Other(
                    "submitted grant must scope exactly one bucket".into(),
                ));
            }
        };
        let (owner_agent_pubkey, owner_node_pubkey) = match self.bucket_info_sync(&bucket_id) {
            Ok(Some(info)) => (info.owner_agent_pubkey, info.owner_node_pubkey),
            _ => (None, None),
        };
        if !self.grant_issuer_authorized(
            &grant.admin_pubkey,
            grant.not_before_ns,
            owner_agent_pubkey.as_ref(),
            owner_node_pubkey.as_ref(),
        ) {
            return Err(ApiError::Forbidden(
                "grant issuer is not authorised for this bucket".into(),
            ));
        }

        let grant_json = serde_ipld_dagcbor::to_vec(grant)
            .map_err(|e| ApiError::Serialization(e.to_string()))?;
        let cid_bytes = memvault_core::cid_from_bytes(&grant_json).to_bytes();
        let meta = memvault_store::EnvelopeMeta {
            author: self.effective_author(),
            tags: vec![
                ("grant".to_string(), hex::encode(bucket_id.0)),
                ("kind".to_string(), "grant".to_string()),
            ],
            wall_ns: memvault_core::wall_ns(),
            cluster_id: Some(self.cluster_id.clone()),
            bucket_id: Some(bucket_id.0.to_vec()),
            ..Default::default()
        };
        self.store.insert_envelope(&cid_bytes, &grant_json, &meta)?;
        tracing::info!(
            bucket = %bucket_id,
            cid = %hex::encode(&cid_bytes),
            "stored externally-signed bucket grant"
        );
        Ok(cid_bytes)
    }

    /// List all grants scoped to a bucket.
    pub fn list_bucket_grants(
        &self,
        bucket_id: &BucketId,
    ) -> Result<Vec<(Vec<u8>, memvault_auth::Grant)>> {
        let bucket_hex = hex::encode(bucket_id.0);
        // Exhaustive: ACL decisions must see every grant on the bucket. A cap
        // could silently drop a grant and mis-decide access (see standards:
        // exhaustive-lookups).
        let cids = self
            .store
            .query_by_tag("grant", &bucket_hex, 0, usize::MAX)
            .unwrap_or_default();

        let mut grants = Vec::new();
        for cid in cids {
            if let Ok(Some(data)) = self.store.get_block(&cid) {
                if let Some(grant) = memvault_store::deserialize_block_as::<memvault_auth::Grant>(&data) {
                    grants.push((cid, grant));
                }
            }
        }
        Ok(grants)
    }

    // -- Bucket merges (alias overlay) --

    /// Bump the alias generation so the next `bucket_alias_maps` call
    /// rebuilds from the `bucket_merge` side blocks. Called on local merge
    /// writes and from the `bucket_merge` notifier arm on synced records.
    pub fn bump_alias_generation(&self) {
        self.alias_generation
            .fetch_add(1, std::sync::atomic::Ordering::AcqRel);
        if let Ok(mut c) = self.alias_cache.write() {
            *c = None;
        }
        // Derived scope member-sets are computed against the union, so a
        // changed alias set invalidates them too.
        let _ = self.store.scope_clear_all();
    }

    /// Load + build the bucket-merge alias maps, cached against
    /// `alias_generation`. Rebuilds from the `bucket_merge` side blocks on
    /// a generation mismatch (small N).
    pub(crate) fn bucket_alias_maps(&self) -> std::sync::Arc<AliasMaps> {
        let cur_gen = self
            .alias_generation
            .load(std::sync::atomic::Ordering::Acquire);
        if let Ok(c) = self.alias_cache.read() {
            if let Some((g, maps)) = c.as_ref() {
                if *g == cur_gen {
                    return std::sync::Arc::clone(maps);
                }
            }
        }
        let maps = std::sync::Arc::new(self.build_bucket_alias_maps());
        if let Ok(mut c) = self.alias_cache.write() {
            *c = Some((cur_gen, std::sync::Arc::clone(&maps)));
        }
        maps
    }

    /// Scan the `bucket_merge` side blocks and fold them into a one-hop
    /// alias map (newest non-retracted record wins per source), then
    /// flatten the transitive `members` inverse. Each record's signature
    /// is verified against its embedded issuer; the issuer's *authority*
    /// was checked at write time (`bucket_merge_sync`) / is re-checkable
    /// but not re-run here (mirrors how grant authority is trusted once a
    /// grant is in the store, with signature authenticity still enforced).
    fn build_bucket_alias_maps(&self) -> AliasMaps {
        let mut newest: std::collections::HashMap<[u8; 32], (u64, [u8; 32])> =
            std::collections::HashMap::new();
        let sources = self
            .store
            .query_unique_labels("bucket_merge", usize::MAX)
            .unwrap_or_default();
        for source_hex in &sources {
            let cids = self
                .store
                .query_by_tag("bucket_merge", source_hex, 0, usize::MAX)
                .unwrap_or_default();
            for cid in cids {
                if self.store.is_retracted(&cid).unwrap_or(false) {
                    continue;
                }
                let Ok(Some(data)) = self.store.get_block(&cid) else {
                    continue;
                };
                let Some(rec) =
                    memvault_store::deserialize_block_as::<memvault_auth::BucketMergeRecord>(&data)
                else {
                    continue;
                };
                // Authenticity: a sync-injected record with a bad signature
                // must not alter resolution.
                if rec.verify_signature().is_err() {
                    continue;
                }
                // A self-edge (source == canonical) is meaningless; skip it
                // so it can never seed a trivial cycle.
                if rec.source.0 == rec.canonical.0 {
                    continue;
                }
                let e = newest.entry(rec.source.0).or_insert((0, rec.canonical.0));
                if rec.created_ns >= e.0 {
                    *e = (rec.created_ns, rec.canonical.0);
                }
            }
        }
        let mut maps = AliasMaps::default();
        for (source, (_ts, canonical)) in newest {
            maps.alias.insert(source, canonical);
        }
        // Fold in deterministic agent aliases (no signed record needed):
        // legacy cluster-scoped agent bucket ids → the pubkey-derived id.
        self.extend_with_agent_aliases(&mut maps.alias);
        maps.build_members();
        maps
    }

    /// Auto-alias pass: add deterministic `legacy_agent_bucket_id →
    /// deterministic_agent_bucket_id` edges that need no signed record
    /// (owner-implied — the same agent pubkey owns both ends). For every
    /// known agent pubkey `P`, the new derivation homes its bucket at
    /// `f(P)` (cluster-independent); its data may sit in a legacy bucket
    /// `legacy_f(c, P)` for some prior cluster context `c`. We alias each
    /// existing legacy bucket onto `f(P)` so the old data surfaces under
    /// the stable canonical.
    ///
    /// Cluster contexts covered: pre-genesis (`[0;32]`) and the current
    /// cluster_id — the two ids the old derivation actually produced.
    /// (ClusterGenesis-history rotation and AgentKeyRotation chains are not
    /// enumerable from stored state today; left as future inputs.)
    ///
    /// Deterministic + per-node: every node computes the same edges, so no
    /// authority signature is needed (unlike a generic `BucketMergeRecord`).
    /// `or_insert` so a signed merge for the same source always wins.
    fn extend_with_agent_aliases(&self, alias: &mut std::collections::HashMap<[u8; 32], [u8; 32]>) {
        // Candidate agent pubkeys: every attested agent, plus any bucket's
        // recorded owner-agent pubkey (covers agents whose attestation this
        // node hasn't synced but whose bucket it holds).
        let mut pubkeys: std::collections::HashSet<[u8; 32]> = std::collections::HashSet::new();
        if let Ok(atts) = crate::sigchain::scan_agent_attestations(self) {
            for att in atts {
                pubkeys.insert(att.agent_pubkey);
            }
        }
        // Read owner pubkeys straight from each BucketDecl — NOT via
        // bucket_info_sync/build_bucket_info, which now calls canonical_of
        // and would recurse back into this alias build.
        for bid in self.all_bucket_id_arrays() {
            if let Ok(Some(decl_cid)) = self.store.get_bucket(&bid) {
                if let Ok(Some(block)) = self.store.get_block(&decl_cid) {
                    if let Some(decl) = Self::parse_bucket_decl(&block) {
                        if let Some(pk) = decl.owner_agent_pubkey {
                            pubkeys.insert(pk);
                        }
                    }
                }
            }
        }

        // Legacy cluster contexts the old derivation could have used.
        let mut clusters: Vec<Vec<u8>> = vec![vec![0u8; 32]];
        if self.cluster_id.iter().any(|&b| b != 0) {
            clusters.push(self.cluster_id.clone());
        }

        for pk in pubkeys {
            let canonical = crate::rebuild::deterministic_agent_bucket_id(&pk).0;
            for c in &clusters {
                let old = crate::rebuild::legacy_agent_bucket_id(c, &pk).0;
                if old == canonical {
                    continue;
                }
                // Only alias a legacy id that actually exists as a bucket on
                // this node — never invent an edge to an empty source.
                if self.store.get_bucket(&old).ok().flatten().is_some() {
                    alias.entry(old).or_insert(canonical);
                }
            }
        }
    }

    /// Write-path companion to [`Self::extend_with_agent_aliases`]: for every
    /// agent pubkey that has a legacy (cluster-scoped) bucket but whose stable
    /// deterministic canonical bucket has no decl yet, create that canonical so
    /// the legacy data folds into a real, *listable* agent bucket instead of an
    /// invisible phantom target (a merged source whose canonical can't be
    /// shown would otherwise vanish from listings entirely). Idempotent — only
    /// writes when the canonical is missing. Returns the number created.
    ///
    /// Needs the node signing key installed (the created decl is node-signed
    /// with the agent as `owner_agent`, exactly like [`ensure_agent_bucket`]),
    /// so call it at daemon startup after the key is set.
    fn materialize_agent_alias_canonicals(&self) -> usize {
        use std::collections::{HashMap, HashSet};

        // Candidate pubkeys: every attested agent, plus any bucket's recorded
        // owner-agent pubkey (covers agents whose attestation hasn't synced but
        // whose legacy bucket this node holds). Remember a display name per
        // pubkey from the owning decl so the created bucket is named sensibly.
        let mut pubkeys: HashSet<[u8; 32]> = HashSet::new();
        let mut name_hint: HashMap<[u8; 32], String> = HashMap::new();
        if let Ok(atts) = crate::sigchain::scan_agent_attestations(self) {
            for att in atts {
                pubkeys.insert(att.agent_pubkey);
                name_hint
                    .entry(att.agent_pubkey)
                    .or_insert_with(|| att.agent_id.0.clone());
            }
        }
        for bid in self.all_bucket_id_arrays() {
            if let Ok(Some(decl_cid)) = self.store.get_bucket(&bid) {
                if let Ok(Some(block)) = self.store.get_block(&decl_cid) {
                    if let Some(decl) = Self::parse_bucket_decl(&block) {
                        if let Some(pk) = decl.owner_agent_pubkey {
                            pubkeys.insert(pk);
                            if let Some(owner) = decl.owner_agent {
                                name_hint.entry(pk).or_insert(owner.0);
                            }
                        }
                    }
                }
            }
        }

        // Legacy cluster contexts the old derivation could have used.
        let mut clusters: Vec<Vec<u8>> = vec![vec![0u8; 32]];
        if self.cluster_id.iter().any(|&b| b != 0) {
            clusters.push(self.cluster_id.clone());
        }

        let mut created = 0usize;
        for pk in pubkeys {
            let canonical = crate::rebuild::deterministic_agent_bucket_id(&pk).0;
            // Already a real bucket — nothing to materialize.
            if self.store.get_bucket(&canonical).ok().flatten().is_some() {
                continue;
            }
            // Only materialize when a legacy source actually exists for this
            // pubkey (mirrors the alias guard: never invent an empty canonical).
            let has_legacy = clusters.iter().any(|c| {
                let old = crate::rebuild::legacy_agent_bucket_id(c, &pk).0;
                old != canonical && self.store.get_bucket(&old).ok().flatten().is_some()
            });
            if !has_legacy {
                continue;
            }
            let hint = name_hint
                .get(&pk)
                .cloned()
                .unwrap_or_else(|| hex::encode(pk));
            match self.ensure_agent_bucket_for_pubkey_sync(&pk, &hint) {
                Ok(bid) => {
                    created += 1;
                    tracing::info!(
                        agent_pubkey = %hex::encode(pk),
                        bucket = %bid,
                        "materialized canonical agent bucket for legacy alias target"
                    );
                }
                Err(e) => tracing::warn!(
                    agent_pubkey = %hex::encode(pk),
                    "failed to materialize canonical agent bucket: {e}"
                ),
            }
        }
        created
    }

    /// Run the agent-bucket migration: materialize any missing canonical agent
    /// buckets that legacy buckets alias onto (so the merged data surfaces
    /// under a real, listable bucket), then force the alias maps to rebuild so
    /// the deterministic legacy→canonical agent aliases (see
    /// [`Self::extend_with_agent_aliases`]) take effect. Idempotent. A daemon
    /// calls this at startup after the node signing key is installed;
    /// resolution also triggers the alias rebuild lazily on first use.
    pub fn run_agent_bucket_migration(&self) {
        self.materialize_agent_alias_canonicals();
        self.bump_alias_generation();
    }

    /// Resolve a bucket id to its terminal canonical, following the merge
    /// alias chain (with a cycle guard). A bucket with no alias resolves to
    /// itself.
    pub fn canonical_of(&self, bucket_id: &[u8; 32]) -> [u8; 32] {
        self.bucket_alias_maps().canonical_of(*bucket_id)
    }

    /// All source bucket ids that resolve (transitively) into `canonical`.
    /// Empty if `canonical` is not a merge target.
    pub fn bucket_merge_members(&self, canonical: &[u8; 32]) -> Vec<[u8; 32]> {
        self.bucket_alias_maps()
            .members
            .get(canonical)
            .cloned()
            .unwrap_or_default()
    }

    /// List all `source → canonical` merge edges (one-hop), for surfaces.
    pub fn bucket_merges(&self) -> Vec<(BucketId, BucketId)> {
        self.bucket_alias_maps()
            .alias
            .iter()
            .map(|(s, c)| (BucketId(*s), BucketId(*c)))
            .collect()
    }

    /// Merge each `source` bucket into `canonical`: store one signed
    /// `bucket_merge` side block per source. Authority (§8): the node must
    /// hold a signing key that is authorised on the canonical **and** on
    /// every source — an `AgentRole::Admin` key (authorised everywhere) or
    /// the bucket owner / attesting node key for those specific buckets.
    /// Returns the stored record CIDs.
    pub fn bucket_merge_sync(
        &self,
        sources: &[BucketId],
        canonical: &BucketId,
    ) -> Result<Vec<Vec<u8>>> {
        let now_ns = memvault_core::wall_ns();
        // The signer must be authorised on the canonical. `pick_grant_signer`
        // returns an admin key when held (authorised everywhere) else the
        // canonical's owner/attester key.
        let (signer, issuer_pubkey) = self.pick_grant_signer(canonical).ok_or_else(|| {
            ApiError::Forbidden("no merge-signing authority for canonical bucket".into())
        })?;
        use ed25519_dalek::Signer;

        let mut cids = Vec::new();
        for source in sources {
            if source.0 == canonical.0 {
                return Err(ApiError::Other(
                    "cannot merge a bucket into itself".into(),
                ));
            }
            // The same issuer must also be authorised on the source bucket,
            // so an owner of the canonical can't annex a bucket they don't
            // control. Admin issuers pass unconditionally.
            let (owner_agent_pubkey, owner_node_pubkey) = match self.bucket_info_sync(source) {
                Ok(Some(info)) => (info.owner_agent_pubkey, info.owner_node_pubkey),
                _ => (None, None),
            };
            if !self.grant_issuer_authorized(
                &issuer_pubkey,
                now_ns,
                owner_agent_pubkey.as_ref(),
                owner_node_pubkey.as_ref(),
            ) {
                return Err(ApiError::Forbidden(format!(
                    "issuer not authorised to merge source bucket {source}"
                )));
            }

            let mut rec = memvault_auth::BucketMergeRecord {
                source: source.clone(),
                canonical: canonical.clone(),
                created_ns: now_ns,
                issued_by_pubkey: issuer_pubkey,
                signature: [0u8; 64],
            };
            let signing_bytes = rec
                .signing_bytes()
                .map_err(|e| ApiError::Other(format!("merge record signing failed: {e}")))?;
            rec.signature = signer.sign(&signing_bytes).to_bytes();

            let rec_bytes = serde_ipld_dagcbor::to_vec(&rec)
                .map_err(|e| ApiError::Serialization(e.to_string()))?;
            let cid_bytes = memvault_core::cid_from_bytes(&rec_bytes).to_bytes();
            let source_hex = hex::encode(source.0);
            let meta = memvault_store::EnvelopeMeta {
                author: self.effective_author(),
                // `("bucket_merge", <source_hex>)` makes the edge queryable
                // by source (`canonical_of`) and discoverable via
                // `query_unique_labels`. `("sigchain", "bucket_merge")` both
                // fires the notifier (gossip head announce + alias-cache
                // invalidation on peers) and routes the block into the audit
                // decode path (§8.1).
                tags: vec![
                    ("bucket_merge".to_string(), source_hex),
                    ("kind".to_string(), "bucket_merge".to_string()),
                    ("sigchain".to_string(), "bucket_merge".to_string()),
                ],
                wall_ns: now_ns,
                causal: vec![],
                provenance: vec![],
                // Home the record on the canonical so it travels with the
                // bucket it governs.
                cluster_id: Some(self.cluster_id.clone()),
                bucket_id: Some(canonical.0.to_vec()),
                ..Default::default()
            };
            self.store.insert_envelope(&cid_bytes, &rec_bytes, &meta)?;
            tracing::info!(
                source = %source,
                canonical = %canonical,
                cid = %hex::encode(&cid_bytes),
                "bucket merge recorded"
            );
            cids.push(cid_bytes);
        }
        self.bump_alias_generation();
        Ok(cids)
    }

    /// Reverse a merge: retract the `source → canonical` record(s) so the
    /// union stops including `source`. Reversible; the source's blocks are
    /// untouched (they were never re-homed).
    pub async fn bucket_unmerge(&self, source: &BucketId, canonical: &BucketId) -> Result<()> {
        let source_hex = hex::encode(source.0);
        let cids = self
            .store
            .query_by_tag("bucket_merge", &source_hex, 0, usize::MAX)
            .unwrap_or_default();
        let want = canonical.0;
        let mut retracted_any = false;
        for cid in cids {
            if self.store.is_retracted(&cid).unwrap_or(false) {
                continue;
            }
            let Ok(Some(data)) = self.store.get_block(&cid) else {
                continue;
            };
            let Some(rec) =
                memvault_store::deserialize_block_as::<memvault_auth::BucketMergeRecord>(&data)
            else {
                continue;
            };
            // The record stores the *direct* one-hop canonical, but callers
            // (e.g. the UI) often pass the *terminal* canonical from
            // `BucketInfo.merged_into` (= `canonical_of`, flattened through any
            // chain). Match either: the direct target, or one whose chain
            // resolves to the requested terminal. Retracting the source's
            // direct edge detaches it regardless of how deep the chain was.
            if rec.canonical.0 == want || self.canonical_of(&rec.canonical.0) == want {
                self.retract(&cid, "bucket unmerge").await?;
                retracted_any = true;
            }
        }
        if !retracted_any {
            return Err(ApiError::Other(format!(
                "no merge edge {source} → {canonical} to reverse"
            )));
        }
        self.bump_alias_generation();
        Ok(())
    }

    /// Revoke a previously-issued bucket grant.
    ///
    /// Signs a [`memvault_auth::GrantRevocation`] under the cluster
    /// admin key (same key that originally signed the target grant) and
    /// records the revocation in two places:
    ///   * the audit `REVOCATIONS` table — so
    ///     [`crate::acl::check_bucket_access`] can skip revoked grants
    ///     with a cheap `is_revoked` lookup,
    ///   * a tagged sigchain envelope (`kind=grant_revocation`,
    ///     `revokes=<grant_cid_hex>`) — so the revocation is auditable
    ///     and replicates across peers like any other block.
    ///
    /// The target CID must refer to an existing bucket grant in this
    /// node's store; passing an unknown or non-grant CID returns
    /// `ApiError::Other`.
    ///
    /// Authority: admin-only. Bucket-owner-initiated revocation would
    /// require a second `GrantRevocation` variant signed by the owner
    /// agent's key + a verifier path that looks up the bucket's
    /// `owner_agent` — not implemented yet.
    pub async fn revoke_bucket_grant(
        &self,
        grant_cid: &[u8],
        reason: &str,
    ) -> Result<Vec<u8>> {
        // Confirm the target actually IS a grant block in this store —
        // catches typos and prevents accidentally poisoning the
        // revocation table with an unrelated CID.
        let raw = self
            .store
            .get_block(grant_cid)
            .map_err(|e| ApiError::Other(format!("lookup grant: {e}")))?
            .ok_or_else(|| {
                ApiError::Other(format!(
                    "no block found for grant cid {}",
                    hex::encode(grant_cid)
                ))
            })?;
        // Confirm the target really is a Grant block before revoking.
        let grant = memvault_store::deserialize_block_as::<memvault_auth::Grant>(&raw)
            .ok_or_else(|| {
                ApiError::Other(format!(
                    "block {} is not a Grant",
                    hex::encode(grant_cid)
                ))
            })?;

        // Sign the revocation with whatever authority this node holds for
        // the grant's bucket (admin / owner agent / node) — symmetric with
        // issuance, so a non-admin owner/node can revoke its own grants.
        let bucket_for_signer = grant
            .bucket_scopes
            .first()
            .cloned()
            .unwrap_or_else(|| BucketId([0u8; 32]));
        let (signer, _signer_pk) = self.pick_grant_signer(&bucket_for_signer).ok_or_else(|| {
            ApiError::Other("no grant-revoking authority for this bucket".into())
        })?;

        let target_cid = memvault_core::cid_from_bytes(&raw);
        let revocation = memvault_auth::sign_grant_revocation(&signer, target_cid, reason)
            .map_err(|e| ApiError::Other(format!("sign grant revocation: {e}")))?;

        let rev_bytes = serde_ipld_dagcbor::to_vec(&revocation)
            .map_err(|e| ApiError::Serialization(e.to_string()))?;

        // Publish as a sigchain block so the revocation propagates to peers
        // via RBSR and fires the local watcher. Without this, a revoked
        // grant kept conferring access on every node except the issuer.
        let rev_cid_bytes = crate::sigchain::publish_grant_revocation(self, &revocation)?;

        // Fast-path index used by `acl::check_bucket_access` (read directly,
        // uncached). The payload doubles as the canonical revocation record.
        self.store
            .record_revocation(grant_cid, &rev_bytes)
            .map_err(|e| ApiError::Other(format!("record_revocation: {e}")))?;

        tracing::info!(
            grant = %hex::encode(grant_cid),
            revocation = %hex::encode(&rev_cid_bytes),
            reason,
            "bucket grant revoked"
        );
        Ok(rev_cid_bytes)
    }

    pub async fn adopt_doc_into_bucket(
        &self,
        doc_id: &DocId,
        bucket: &BucketId,
    ) -> Result<bool> {
        if self.inferred_doc_bucket(doc_id).is_some() {
            return Ok(false);
        }

        // Only adopt docs that have at least one locally-authored block.
        let (_, label) = Self::doc_tag(doc_id);
        let cids = self
            .store
            .query_by_tag("doc", &label, 0, usize::MAX)
            .unwrap_or_default();
        if !self.has_local_author(&cids) {
            return Ok(false);
        }

        // Write a no-op edit that carries the bucket_id.
        let op = Op::DocEdit {
            doc_id: doc_id.clone(),
            patch: memvault_doc::TextPatch { ops: vec![] },
        };
        let tags = vec![Self::doc_tag(doc_id)];
        self.store_op(&op, &tags, &Visibility::Internal, Some(bucket))?;
        Ok(true)
    }

}

impl Drop for LocalClient {
    fn drop(&mut self) {
        // Commit-on-close backstop: land any deferred index write on a clean
        // teardown so it's durable + searchable next start without waiting for
        // the periodic flusher. Best-effort and synchronous: `try_write` never
        // blocks (Drop may run on an async runtime thread), and Drop is skipped
        // on hard kills (SIGKILL / process::exit), so `start_index_flusher`
        // remains the real durability bound. Commits the already-applied
        // writer; it does not drain the reindex queue (the flusher does, ~1s).
        if self
            .index_dirty
            .swap(false, std::sync::atomic::Ordering::AcqRel)
        {
            if let Ok(mut idx) = self.index.try_write() {
                if let Err(e) = idx.commit() {
                    tracing::warn!("tantivy commit on drop failed: {e}");
                }
            }
        }
    }
}

#[async_trait]
impl MemvaultClient for LocalClient {
    async fn put_doc(
        &self,
        doc: Document,
        tags: Vec<(String, String)>,
        vis: Visibility,
        bucket: Option<&BucketId>,
    ) -> Result<Vec<u8>> {
        let op = Op::DocCreate {
            doc_id: doc.id.clone(),
            initial_body: doc.body.clone(),
            frontmatter: doc.frontmatter.clone(),
        };

        let mut all_tags = tags.clone();
        all_tags.push(Self::doc_tag(&doc.id));

        let cid_bytes = self.store_op(&op, &all_tags, &vis, bucket)?;
        tracing::info!(doc_id = %hex::encode(doc.id.0), "doc created");

        // Run the body through the extractor pipeline so links land in the
        // annotation cache. Failures and unsupported MIMEs are silently
        // ignored — the body is still saved.
        let _ = self.extract_doc_and_cache(&doc.id, &cid_bytes, &doc.body, &doc.frontmatter);

        // Index for search
        let title = doc
            .frontmatter
            .get("title")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
        let bucket_hex = self.inferred_doc_bucket(&doc.id).map(hex::encode);
        {
            let mut idx = self.index.write().await;
            let _ = idx.index_doc(
                &doc.id,
                &doc.body,
                title.as_deref(),
                &tags,
                bucket_hex.as_deref(),
                memvault_core::wall_ns(),
            );
            // Commit now, or defer to the batched flusher (long-running hosts).
            self.commit_or_defer(&mut idx);
        }
        let doc_node_id = format!("doc:{}", hex::encode(doc.id.0));
        self.sync_node_created(&doc_node_id, &tags).await;

        self.event_bus.publish(MemvaultEvent::DocCreated {
            doc_id: doc.id.clone(),
            cid: cid_bytes.clone(),
        });

        Ok(cid_bytes)
    }

    async fn get_doc(&self, id: &DocId) -> Result<Option<Document>> {
        self.get_doc_async(id, false).await
    }

    async fn edit_doc(&self, id: &DocId, patch: TextPatch) -> Result<Vec<u8>> {
        let op = Op::DocEdit {
            doc_id: id.clone(),
            patch,
        };

        let tags = vec![Self::doc_tag(id)];
        let inferred_bucket = self
            .inferred_doc_bucket(id)
            .and_then(|bytes| bytes.try_into().ok())
            .map(BucketId);
        let cid_bytes =
            self.store_op(&op, &tags, &Visibility::Internal, inferred_bucket.as_ref())?;

        // After the edit lands, re-extract the doc body so cached links
        // track the new head.
        if let Ok(Some(doc)) = self.get_doc_async(id, false).await {
            let _ = self.extract_doc_and_cache(id, &cid_bytes, &doc.body, &doc.frontmatter);
        }

        self.event_bus.publish(MemvaultEvent::DocUpdated {
            doc_id: id.clone(),
            cid: cid_bytes.clone(),
        });

        Ok(cid_bytes)
    }

    async fn list_docs(
        &self,
        tag_filter: Option<(String, String)>,
        limit: usize,
        bucket: Option<&BucketId>,
    ) -> Result<Vec<DocSummary>> {
        self.list_docs_ex(tag_filter, limit, bucket, false).await
    }

    async fn list_docs_ex(
        &self,
        tag_filter: Option<(String, String)>,
        limit: usize,
        bucket: Option<&BucketId>,
        include_retracted: bool,
    ) -> Result<Vec<DocSummary>> {
        // Bucket-scoped, untagged listing: enumerate the per-bucket member-set
        // (O(bucket)) instead of scanning every doc label in the cluster.
        // Tagged queries already use the narrow `query_by_tag` path, which the
        // member-set (not tag-partitioned) wouldn't improve. See the
        // per-bucket-member-index plan / standards/derived-indexes.md.
        if let (Some(bid), None) = (bucket, &tag_filter) {
            // Drain any pending reindex (synced/seeded blocks) so the
            // maintenance wiring has folded them into the registered set before
            // we read it — read-your-syncs, mirroring scoped_list/scoped_search.
            self.flush_index().await;
            self.ensure_bucket_partition(bid).await?;
            let bsid = memvault_core::bucket_scope_id(bid);
            // include_active is always true; include_retracted gates the
            // retracted partition. Unlimited at the store level — we filter to
            // docs and page at `limit` after.
            let members = self.store.scope_members(&bsid, true, include_retracted, 0)?;
            let mut summaries = Vec::new();
            for (node_id, _wall) in &members {
                if summaries.len() >= limit {
                    break;
                }
                let Some(hex_id) = node_id.strip_prefix("doc:") else {
                    continue;
                };
                let Some(arr) = hex::decode(hex_id)
                    .ok()
                    .and_then(|b| <[u8; 32]>::try_from(b).ok())
                else {
                    continue;
                };
                if let Some(summary) = self.doc_summary(&DocId(arr)) {
                    summaries.push(summary);
                }
            }
            #[cfg(debug_assertions)]
            self.debug_assert_bucket_parity(bid, include_retracted, "doc:")
                .await;
            return Ok(summaries);
        }
        self.list_docs_scan(tag_filter, limit, bucket, include_retracted)
            .await
    }

    async fn upload_file(
        &self,
        data: &[u8],
        filename: Option<&str>,
        mime_type: &str,
        tags: Vec<(String, String)>,
        visibility: &str,
        bucket: Option<&BucketId>,
    ) -> Result<Vec<u8>> {
        // Chunk file into blocks using memvault-attach
        let (root_cid, blocks) = memvault_attach::chunk_file(data)?;

        // Store all blocks
        for (block_cid, block_data) in &blocks {
            self.store.put_block(block_cid, block_data)?;
        }

        // Create attachment manifest
        let layout = memvault_attach::decide_layout(data.len() as u64);
        let replication = memvault_attach::default_replication(data.len() as u64);

        let manifest = AttachmentManifest {
            content_root: root_cid,
            content_size: data.len() as u64,
            chunk_layout: layout,
            filename: filename.map(|s| s.to_string()),
            mime_type: mime_type.to_string(),
            sha256: None,
            width_height: None,
            duration_ms: None,
            extracted_text: None,
            derived_from: None,
            pii_findings: None,
            replication,
        };

        // Encode manifest and store
        let manifest_bytes =
            serde_ipld_dagcbor::to_vec(&manifest).map_err(|e| ApiError::Serialization(e.to_string()))?;
        let manifest_cid = cid_from_bytes(&manifest_bytes);
        let manifest_cid_bytes = manifest_cid.to_bytes();
        self.store.put_block(&manifest_cid_bytes, &manifest_bytes)?;

        // Store envelope metadata for the manifest. Include the `_manifest`
        // reverse-lookup tag (manifest_cid → this envelope) in the *store*
        // index so `get_file_manifest` and `inferred_attachment_bucket` work
        // immediately on fresh uploads — not only after a reindex/sync. The
        // envelope's own display tags (below, via `&tags`) stay unchanged.
        let bucket_id = self.resolve_bucket(bucket);
        let mut meta = EnvelopeMeta {
            author: self.effective_author(),
            tags: tags.clone(),
            wall_ns: memvault_core::wall_ns(),
            causal: vec![],
            provenance: vec![],
            cluster_id: Some(self.cluster_id.clone()),
            bucket_id,
                    ..Default::default()
        };
        meta.tags
            .push(("_manifest".to_string(), hex::encode(&manifest_cid_bytes)));
        let payload = serde_json::json!({
            "kind": "attachment",
            "manifest_cid": manifest_cid_bytes,
            "filename": filename,
            "mime_type": mime_type,
            "size": data.len(),
            "cluster_id": meta.cluster_id,
        });
        let visibility_typed = match visibility {
            "public" => Visibility::Public,
            "federated" => Visibility::Federated,
            _ => Visibility::Internal,
        };
        let (cid_bytes, envelope_bytes) = self.build_signed_envelope(
            payload,
            &tags,
            visibility_typed,
            meta.wall_ns,
            meta.bucket_id.as_deref(),
        )?;
        self.store
            .insert_envelope(&cid_bytes, &envelope_bytes, &meta)?;
        tracing::info!(filename = ?filename, mime_type, size = data.len(), "file attached");

        // Extract text and cache the result (success or failure) in the blockstore.
        let extracted_text = self.extract_and_cache(&manifest_cid_bytes, data, mime_type);

        // Index for unified search (includes extracted text if available).
        {
            let mut idx = self.index.write().await;
            let bucket_hex = meta.bucket_id.as_deref().map(hex::encode);
            let _ = idx.index_attachment(
                &manifest_cid_bytes,
                filename,
                mime_type,
                extracted_text.as_deref(),
                &tags,
                bucket_hex.as_deref(),
                meta.wall_ns,
            );
            // Commit now, or defer to the batched flusher (long-running hosts).
            self.commit_or_defer(&mut idx);
        }
        let file_node_id = format!("file:{}", hex::encode(&manifest_cid_bytes));
        self.sync_node_created(&file_node_id, &tags).await;

        self.event_bus.publish(MemvaultEvent::FileAttached {
            doc_id: DocId([0; 32]), // No doc association in new system
            name: filename.unwrap_or("unnamed").to_string(),
        });

        Ok(manifest_cid_bytes)
    }

    async fn read_file(&self, manifest_cid: &[u8]) -> Result<Vec<u8>> {
        // Accept both "file:" and legacy "attachment:" node IDs for retraction checks.
        let node_id = format!("file:{}", hex::encode(manifest_cid));
        let legacy_node_id = format!("attachment:{}", hex::encode(manifest_cid));
        {
            let idx = self.index.read().await;
            if idx.is_retracted(&node_id) || idx.is_retracted(&legacy_node_id) {
                return Err(ApiError::NotFound("file retracted".into()));
            }
        }
        let manifest_data = self
            .store
            .get_block(manifest_cid)?
            .ok_or_else(|| ApiError::NotFound("file manifest not found".into()))?;

        let manifest: AttachmentManifest = memvault_store::deserialize_block_as(&manifest_data)
            .ok_or_else(|| ApiError::Serialization("cannot parse manifest".into()))?;

        // Read full content via UnixFS
        let data = memvault_attach::read_range::read_full(&self.store, &manifest.content_root)?;
        Ok(data)
    }

    async fn read_file_range(&self, manifest_cid: &[u8], start: u64, end: u64) -> Result<Vec<u8>> {
        let manifest_data = self
            .store
            .get_block(manifest_cid)?
            .ok_or_else(|| ApiError::NotFound("file manifest not found".into()))?;

        let manifest: AttachmentManifest = memvault_store::deserialize_block_as(&manifest_data)
            .ok_or_else(|| ApiError::Serialization("cannot parse manifest".into()))?;

        let data = memvault_attach::read_range::read_range(
            &self.store,
            &manifest.content_root,
            start,
            end,
        )?;
        Ok(data)
    }

    async fn read_extracted_text(&self, manifest_cid: &[u8]) -> Result<Option<String>> {
        // Try cached extraction first, then extract fresh and cache.
        let manifest_data = self
            .store
            .get_block(manifest_cid)?
            .ok_or_else(|| ApiError::NotFound("file manifest not found".into()))?;

        let manifest: AttachmentManifest = memvault_store::deserialize_block_as(&manifest_data)
            .ok_or_else(|| ApiError::Serialization("cannot parse manifest".into()))?;

        let content = memvault_attach::read_range::read_full(&self.store, &manifest.content_root)?;
        Ok(self.extract_and_cache(manifest_cid, &content, &manifest.mime_type))
    }

    async fn pin_file(&self, manifest_cid: &[u8]) -> Result<()> {
        memvault_attach::pin::pin(
            &self.store,
            manifest_cid,
            memvault_attach::PinReason::Manual,
        )?;
        Ok(())
    }

    async fn unpin_file(&self, manifest_cid: &[u8]) -> Result<()> {
        memvault_attach::pin::unpin(&self.store, manifest_cid)?;
        Ok(())
    }

    async fn list_pinned(&self) -> Result<Vec<(Vec<u8>, String)>> {
        // We need to scan known attachment CIDs. For now, query by the "attachment" tag.
        // This is a simplified implementation.
        let cids = self
            .store
            .query_by_tag("attachment", "", 0, 1000)
            .unwrap_or_default();
        let pinned = memvault_attach::pin::list_pinned(&self.store, &cids)?;
        let result = pinned
            .into_iter()
            .map(|(cid, reason)| {
                let reason_str = serde_json::to_string(&reason).unwrap_or_default();
                (cid, reason_str)
            })
            .collect();
        Ok(result)
    }

    async fn get_file_manifest(&self, manifest_cid: &[u8]) -> Result<Option<Vec<u8>>> {
        // Accept both "file:" and legacy "attachment:" node IDs for retraction checks.
        let node_id = format!("file:{}", hex::encode(manifest_cid));
        let legacy_node_id = format!("attachment:{}", hex::encode(manifest_cid));
        {
            let idx = self.index.read().await;
            if idx.is_retracted(&node_id) || idx.is_retracted(&legacy_node_id) {
                return Ok(None);
            }
        }
        if let Some(data) = self.store.get_block(manifest_cid)? {
            return Ok(Some(data));
        }
        // Manifest block missing (legacy file). Fall back to the attachment
        // envelope via the _manifest tag index (written by reindex_block).
        let mcid_hex = hex::encode(manifest_cid);
        let env_cids = self.store.query_by_tag("_manifest", &mcid_hex, 0, 1)?;
        for env_cid in &env_cids {
            if let Some(env_data) = self.store.get_block(env_cid)? {
                // The envelope itself has filename/mime_type/size — return it
                // as if it were the manifest. Callers parse the same fields.
                return Ok(Some(env_data));
            }
        }
        Ok(None)
    }

    async fn add_entity_internal(
        &self,
        entity: Entity,
        vis: Visibility,
        bucket: Option<&BucketId>,
    ) -> Result<EntityId> {
        let entity_id = entity.id.clone();
        let op = Op::EntityCreate {
            entity: entity.clone(),
        };

        let entity_label: String = entity_id.0.iter().map(|b| format!("{b:02x}")).collect();
        let tags = vec![("entity".to_string(), entity_label)];
        self.store_op(&op, &tags, &vis, bucket)?;
        tracing::info!(entity_id = %hex::encode(entity_id.0), kind = %entity.kind, "entity created");

        // Index for unified search
        let bucket_hex = self.inferred_entity_bucket(&entity_id).map(hex::encode);
        {
            let mut idx = self.index.write().await;
            let _ = idx.index_entity(
                &entity_id,
                &entity.kind,
                &entity.props,
                &tags,
                bucket_hex.as_deref(),
                memvault_core::wall_ns(),
            );
            // Commit now, or defer to the batched flusher (long-running hosts).
            self.commit_or_defer(&mut idx);
        }
        let entity_node_id = format!("entity:{}", hex::encode(entity_id.0));
        self.sync_node_created(&entity_node_id, &tags).await;

        self.event_bus.publish(MemvaultEvent::EntityCreated {
            entity_id: entity_id.clone(),
        });

        Ok(entity_id)
    }

    async fn skill_rename(&self, id: &EntityId, new_name: &str) -> Result<()> {
        let mut props: std::collections::BTreeMap<String, serde_json::Value> =
            std::collections::BTreeMap::new();
        props.insert(
            memvault_core::SKILL_NAME_PROP.to_string(),
            serde_json::Value::String(new_name.to_string()),
        );
        let op = Op::EntityUpdate {
            entity_id: id.clone(),
            props,
        };
        let entity_label: String = id.0.iter().map(|b| format!("{b:02x}")).collect();
        let tags = vec![("entity".to_string(), entity_label)];
        let inferred_bucket = self
            .inferred_entity_bucket(id)
            .and_then(|bytes| <[u8; 32]>::try_from(bytes).ok())
            .map(BucketId);
        self.store_op(&op, &tags, &Visibility::Internal, inferred_bucket.as_ref())?;

        // Reindex so search reflects the new name: remove the stale entity doc,
        // then re-add the merged entity (delete+add in one commit, mirroring the
        // retract/tag-update paths).
        if let Ok(Some(entity)) = self.get_entity_async(id, false).await {
            let bucket_hex = self.inferred_entity_bucket(id).map(hex::encode);
            let mut idx = self.index.write().await;
            let _ = idx.remove(&hex::encode(id.0));
            let _ = idx.index_entity(
                id,
                &entity.kind,
                &entity.props,
                &tags,
                bucket_hex.as_deref(),
                memvault_core::wall_ns(),
            );
            self.commit_or_defer(&mut idx);
        }
        Ok(())
    }

    async fn get_entity(&self, id: &EntityId) -> Result<Option<Entity>> {
        self.get_entity_async(id, false).await
    }

    async fn vfs_root_cached(&self, bucket: &BucketId) -> Result<Option<EntityId>> {
        Ok(self
            .store
            .vfs_root_get(&bucket.0)?
            .and_then(|b| <[u8; 32]>::try_from(b).ok())
            .map(EntityId))
    }

    async fn vfs_root_cache_put(&self, bucket: &BucketId, root: &EntityId) -> Result<()> {
        self.store.vfs_root_put(&bucket.0, &root.0)?;
        Ok(())
    }

    async fn node_bucket(&self, node: &NodeRef) -> Result<Option<BucketId>> {
        Ok(self
            .inferred_node_bucket(node)
            .and_then(|b| <[u8; 32]>::try_from(b).ok())
            .map(BucketId))
    }

    async fn entity_history(&self, id: &EntityId) -> Result<Vec<AuditRecord>> {
        let label: String = id.0.iter().map(|b| format!("{b:02x}")).collect();
        let cids = self.store.query_by_tag("entity", &label, 0, usize::MAX)?;

        let mut records = Vec::new();
        for cid in &cids {
            if let Some(data) = self.store.get_block(cid)? {
                if let Some(val) = memvault_store::deserialize_block(&data) {
                    records.push(memvault_query::parse_audit_record(cid, &val));
                }
            }
        }
        Ok(records)
    }

    async fn list_entities(&self, limit: usize, bucket: Option<&BucketId>) -> Result<Vec<Entity>> {
        self.list_entities_ex(limit, bucket, false).await
    }

    async fn list_entities_ex(
        &self,
        limit: usize,
        bucket: Option<&BucketId>,
        include_retracted: bool,
    ) -> Result<Vec<Entity>> {
        // Bucket-scoped listing: enumerate the per-bucket member-set (O(bucket))
        // instead of scanning every entity label in the cluster. See the
        // per-bucket-member-index plan / standards/derived-indexes.md.
        if let Some(bid) = bucket {
            // Read-your-syncs: drain pending reindex so maintenance has folded
            // synced/seeded nodes into the registered set before we read it.
            self.flush_index().await;
            self.ensure_bucket_partition(bid).await?;
            let bsid = memvault_core::bucket_scope_id(bid);
            let members = self.store.scope_members(&bsid, true, include_retracted, 0)?;
            let mut entities = Vec::new();
            for (node_id, _wall) in &members {
                if entities.len() >= limit {
                    break;
                }
                let Some(hex_id) = node_id.strip_prefix("entity:") else {
                    continue;
                };
                let Some(arr) = hex::decode(hex_id)
                    .ok()
                    .and_then(|b| <[u8; 32]>::try_from(b).ok())
                else {
                    continue;
                };
                if let Ok(Some(entity)) =
                    self.get_entity_async(&EntityId(arr), include_retracted).await
                {
                    entities.push(entity);
                }
            }
            #[cfg(debug_assertions)]
            self.debug_assert_bucket_parity(bid, include_retracted, "entity:")
                .await;
            return Ok(entities);
        }
        self.list_entities_scan(limit, bucket, include_retracted).await
    }

    // -- Links (cross-type edges) --

    async fn add_link(&self, source: &NodeRef, edge: Edge, vis: Visibility) -> Result<EdgeId> {
        let edge_id = edge.id.clone();
        let op = Op::EdgeAdd {
            source: source.clone(),
            edge,
        };

        let source_label = source.tag_label();
        let target_label = op_edge_target_label(&op);
        let mut tags = vec![("edge_source".to_string(), source_label)];
        if let Some(tl) = target_label {
            tags.push(("edge_target".to_string(), tl));
        }
        // Also tag by entity label if source is an entity (for backward compat with get_entity)
        if let NodeRef::Entity(id) = source {
            let entity_label: String = id.0.iter().map(|b| format!("{b:02x}")).collect();
            tags.push(("entity".to_string(), entity_label));
        }
        let inferred_bucket = self
            .inferred_node_bucket(source)
            .and_then(|bytes| bytes.try_into().ok())
            .map(BucketId);
        self.store_op(&op, &tags, &vis, inferred_bucket.as_ref())?;
        tracing::info!(source = %source.tag_label(), target = %op_edge_target_label(&op).unwrap_or_default(), "link created");

        Ok(edge_id)
    }

    async fn remove_link_from(&self, source: &NodeRef, edge_id: &EdgeId) -> Result<()> {
        let op = Op::EdgeRemove {
            source: source.clone(),
            edge_id: edge_id.clone(),
        };

        let source_label = source.tag_label();
        let mut tags = vec![("edge_source".to_string(), source_label)];
        if let NodeRef::Entity(id) = source {
            let entity_label: String = id.0.iter().map(|b| format!("{b:02x}")).collect();
            tags.push(("entity".to_string(), entity_label));
        }
        let inferred_bucket = self
            .inferred_node_bucket(source)
            .and_then(|bytes| bytes.try_into().ok())
            .map(BucketId);
        self.store_op(&op, &tags, &Visibility::Internal, inferred_bucket.as_ref())?;
        Ok(())
    }

    async fn edges_of(&self, node: &NodeRef) -> Result<Vec<(NodeRef, Edge)>> {
        let label = node.tag_label();
        let mut results = Vec::new();
        let mut removed_ids: std::collections::HashSet<EdgeId> = std::collections::HashSet::new();

        // Scan all ops tagged with this node as source or target.
        let source_cids = self
            .store
            .query_by_tag("edge_source", &label, 0, usize::MAX)?;
        let target_cids = self
            .store
            .query_by_tag("edge_target", &label, 0, usize::MAX)?;

        let mut all_cids = source_cids;
        all_cids.extend(target_cids);

        for cid in &all_cids {
            if let Some(data) = self.store.get_block(cid)? {
                if let Some(val) = memvault_store::deserialize_block(&data) {
                    if let Some(payload) = val.get("payload") {
                        match serde_json::from_value::<Op>(payload.clone()) {
                            Ok(Op::EdgeAdd { source, edge }) => {
                                results.push((source, edge));
                            }
                            Ok(Op::EdgeRemove { edge_id, .. }) => {
                                removed_ids.insert(edge_id);
                            }
                            _ => {}
                        }
                    }
                }
            }
        }

        // Filter out removed edges, then deduplicate by edge ID.
        results.retain(|(_, edge)| !removed_ids.contains(&edge.id));
        let mut seen = std::collections::HashSet::new();
        results.retain(|(_, edge)| seen.insert(edge.id.clone()));

        Ok(results)
    }

    async fn traverse_from(
        &self,
        from: &NodeRef,
        relation: Option<&str>,
        max_depth: usize,
    ) -> Result<Vec<TraversalHit>> {
        let mut results = Vec::new();
        let mut visited: std::collections::HashSet<NodeRef> = std::collections::HashSet::new();
        let mut queue: VecDeque<(NodeRef, usize, Vec<(EdgeId, String)>)> = VecDeque::new();

        visited.insert(from.clone());
        queue.push_back((from.clone(), 0, Vec::new()));

        while let Some((current_node, depth, path)) = queue.pop_front() {
            if depth > 0 {
                results.push(TraversalHit {
                    node: current_node.clone(),
                    depth,
                    path: path.clone(),
                });
            }

            if depth >= max_depth {
                continue;
            }

            // Get outgoing edges for this node
            let edges = self.edges_of(&current_node).await?;
            for (source, edge) in &edges {
                // Only follow outgoing edges from the current node
                if source != &current_node {
                    continue;
                }
                if let Some(rel_filter) = relation {
                    if edge.relation != rel_filter {
                        continue;
                    }
                }
                if visited.insert(edge.target.clone()) {
                    let mut new_path = path.clone();
                    new_path.push((edge.id.clone(), edge.relation.clone()));
                    queue.push_back((edge.target.clone(), depth + 1, new_path));
                }
            }
        }

        Ok(results)
    }

    async fn search(&self, query: &str, limit: usize) -> Result<Vec<SearchHit>> {
        self.flush_index().await;
        let idx = self.index.read().await;
        let mode = RetractionMode::ActiveOnly;
        let hits: Vec<SearchHit> = idx
            .search_unified_mode(query, None, mode, limit * 2)
            .into_iter()
            .filter(|h| h.node_type == "doc")
            .filter_map(|h| {
                let hex_str = h.node_id.strip_prefix("doc:")?;
                let bytes = hex::decode(hex_str).ok()?;
                if bytes.len() != 32 {
                    return None;
                }
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&bytes);
                Some(SearchHit {
                    doc_id: DocId(arr),
                    score: h.score,
                    snippet: h.snippet,
                })
            })
            .collect();
        drop(idx);

        // Post-filter: only return hits from accessible buckets.
        let accessible = self.accessible_bucket_cids(limit * 20)?;
        if accessible.is_empty() {
            // Pre-genesis or no buckets — return unfiltered.
            return Ok(hits.into_iter().take(limit).collect());
        }
        Ok(hits
            .into_iter()
            .filter(|h| {
                let (_, label) = Self::doc_tag(&h.doc_id);
                self.store
                    // Exhaustive membership (see standards: exhaustive-lookups).
                    .query_by_tag("doc", &label, 0, usize::MAX)
                    .unwrap_or_default()
                    .iter()
                    .any(|c| accessible.contains(c))
            })
            .take(limit)
            .collect())
    }

    async fn search_unified(
        &self,
        query: &str,
        limit: usize,
    ) -> Result<Vec<memvault_query::UnifiedHit>> {
        self.flush_index().await;
        let idx = self.index.read().await;
        let mode = RetractionMode::ActiveOnly;
        let hits = idx.search_unified_mode(query, None, mode, limit * 2);
        drop(idx);

        let buckets = self.store.list_buckets().unwrap_or_default();
        if buckets.is_empty() {
            return Ok(hits.into_iter().take(limit).collect());
        }
        // Filter to nodes in any accessible bucket.
        let bucket_ids: Vec<Vec<u8>> = buckets.into_iter().map(|(id, _)| id).collect();
        Ok(hits
            .into_iter()
            .filter(|h| {
                if let Some(node_bucket) = self.inferred_bucket_for_node_id(&h.node_id) {
                    bucket_ids.iter().any(|b| *b == node_bucket)
                } else {
                    false
                }
            })
            .take(limit)
            .collect())
    }

    async fn view_members(&self, view_name: &str) -> Result<Vec<String>> {
        let view = self
            .get_view(view_name)
            .await?
            .ok_or_else(|| ApiError::NotFound(format!("view '{view_name}' not found")))?;
        self.flush_index().await;
        let idx = self.index.read().await;
        let mode = RetractionMode::ActiveOnly;
        Ok(idx.members_of_view_mode(&view.tags, mode))
    }

    async fn list_all(
        &self,
        view_name: Option<&str>,
        limit: usize,
        bucket: Option<&BucketId>,
    ) -> Result<Vec<(String, String, String, Vec<(String, String)>)>> {
        let view_tags = if let Some(name) = view_name {
            let view = self
                .get_view(name)
                .await?
                .ok_or_else(|| ApiError::NotFound(format!("view '{name}' not found")))?;
            Some(view.tags)
        } else {
            None
        };
        self.flush_index().await;
        // Scan all index rows when scoped to a bucket: a global cap drops nodes
        // of a bucket outside the global first-N (see standards/bucket-scoping.md).
        let fetch = if bucket.is_some() { usize::MAX } else { limit * 2 };
        let idx = self.index.read().await;
        let mode = RetractionMode::ActiveOnly;
        let all: Vec<(String, String, String, Vec<(String, String)>)> = idx
            .list_all_mode(view_tags.as_deref(), None, mode, fetch)
            .into_iter()
            .map(|(id, ty, label, tags, _retracted)| (id, ty, label, tags))
            .collect();
        drop(idx);

        let buckets = self.store.list_buckets().unwrap_or_default();
        if buckets.is_empty() {
            return Ok(all.into_iter().take(limit).collect()); // pre-genesis
        }
        // Scoped to one bucket → keep only that bucket's nodes; otherwise keep
        // any accessible bucket's nodes.
        let accessible: Vec<Vec<u8>> = buckets.into_iter().map(|(id, _)| id).collect();
        let target: Option<Vec<u8>> = bucket.map(|b| b.0.to_vec());
        Ok(all
            .into_iter()
            .filter(|(node_id, _, _, _)| match self.inferred_bucket_for_node_id(node_id) {
                Some(node_bucket) => match &target {
                    Some(t) => node_bucket == *t,
                    None => accessible.iter().any(|b| *b == node_bucket),
                },
                None => false,
            })
            .take(limit)
            .collect())
    }

    // -- Scoped reads (multi-bucket, member-set backed) --

    async fn list_scoped(
        &self,
        scope: &memvault_core::QueryScope,
        limit: usize,
    ) -> Result<Vec<crate::types::NodeSummary>> {
        LocalClient::scoped_list(self, scope, limit).await
    }

    async fn search_scoped(
        &self,
        scope: &memvault_core::QueryScope,
        query: &str,
        limit: usize,
    ) -> Result<Vec<memvault_query::UnifiedHit>> {
        LocalClient::scoped_search(self, scope, query, limit).await
    }

    async fn count_scoped(
        &self,
        scope: &memvault_core::QueryScope,
    ) -> Result<crate::types::ScopeCount> {
        LocalClient::scoped_count(self, scope).await
    }

    async fn get_doc_scoped(
        &self,
        id: &DocId,
        scope: &memvault_core::QueryScope,
    ) -> Result<Option<Document>> {
        LocalClient::get_doc_scoped(self, id, scope).await
    }

    async fn get_entity_scoped(
        &self,
        id: &EntityId,
        scope: &memvault_core::QueryScope,
    ) -> Result<Option<Entity>> {
        LocalClient::get_entity_scoped(self, id, scope).await
    }

    async fn resolve_label_scoped(
        &self,
        node_id: &str,
        scope: &memvault_core::QueryScope,
    ) -> Result<Option<String>> {
        LocalClient::resolve_label_scoped(self, node_id, scope).await
    }

    async fn resolve_label(&self, node_id: &str) -> Result<Option<String>> {
        self.flush_index().await;
        let idx = self.index.read().await;
        Ok(idx.resolve_label_mode(node_id, RetractionMode::ActiveOnly))
    }

    async fn history_of(&self, doc_id: &DocId) -> Result<Vec<AuditRecord>> {
        let query = AuditQuery {
            doc_id: Some(doc_id.clone()),
            ..Default::default()
        };
        Ok(query_audit(&self.store, &query)?)
    }

    async fn audit(&self, query: AuditQuery) -> Result<Vec<AuditRecord>> {
        Ok(query_audit(&self.store, &query)?)
    }

    async fn retract(&self, target_cid: &[u8], _reason: &str) -> Result<Vec<u8>> {
        let tombstone_cid = cid_from_bytes(target_cid);
        let tombstone_bytes = tombstone_cid.to_bytes();
        memvault_query::retract(&self.store, target_cid, &tombstone_bytes)?;

        self.event_bus.publish(MemvaultEvent::Retracted {
            cid: target_cid.to_vec(),
        });

        Ok(tombstone_bytes)
    }

    async fn retract_node_internal(&self, node_id: &str, reason: &str) -> Result<()> {
        self.store_annotation(
            node_id,
            "retraction",
            serde_json::json!({ "reason": reason }),
        )?;
        tracing::info!(node_id, reason, "node retracted");

        // Flag retracted in the in-memory index (entry retained so it stays
        // visible to admins/auditors under IncludeRetracted/RetractedOnly).
        // Flush any deferred create first: retract() finds + rewrites the doc
        // via the committed searcher, so the target must be committed.
        self.flush_index().await;
        {
            let mut idx = self.index.write().await;
            let _ = idx.retract(node_id);
        }
        self.mark_index_dirty();
        // Flush again so sync_node_scopes sees the retraction.
        self.flush_index().await;
        self.sync_node_scopes(node_id).await;

        Ok(())
    }

    async fn issue_token_ex(
        &self,
        role: TokenRole,
        ttl_secs: u64,
        max_uses: u32,
        label: Option<String>,
        issuer_addrs: Vec<String>,
    ) -> Result<String> {
        let admin_key = self.admin_signing_key().ok_or_else(|| {
            ApiError::Other("no admin signing key configured — cannot issue tokens".into())
        })?;
        let peer_id = memvault_core::PeerId(self.peer_id.clone());
        let cluster_id_arr: [u8; 32] = self
            .cluster_id
            .clone()
            .try_into()
            .map_err(|_| ApiError::Other("cluster_id must be 32 bytes".into()))?;
        let cluster_id = memvault_core::ClusterId(cluster_id_arr);

        crate::tokens::issue_token(
            &peer_id,
            &cluster_id,
            &admin_key,
            role,
            ttl_secs,
            max_uses,
            label,
            self.pinned_admin_genesis().cloned(),
            issuer_addrs,
            &self.keystore,
        )
    }

    async fn list_tokens(&self) -> Result<Vec<TokenStatus>> {
        crate::tokens::list_tokens(&self.keystore)
    }

    async fn revoke_token(&self, token_cid: &[u8], reason: &str) -> Result<()> {
        // Keystore is authoritative — works without a redb open, so a
        // separate process can revoke while the daemon holds the blockstore.
        crate::tokens::revoke_token(&self.keystore, token_cid, reason)
    }

    async fn list_rotations(&self) -> Result<Vec<RotationInfo>> {
        crate::rotation::list_rotations(&self.store)
    }

    // -- Tags --

    async fn add_tags(&self, node_id: &str, tags: Vec<(String, String)>) -> Result<()> {
        self.store_tag_update(node_id, &tags, &[])?;
        // Flush deferred creates: apply_tag_update rewrites the doc via the
        // committed searcher, so the target must be committed first.
        self.flush_index().await;
        {
            let mut idx = self.index.write().await;
            let _ = idx.apply_tag_update(node_id, &tags, &[]);
        }
        self.mark_index_dirty();
        self.flush_index().await;
        self.sync_node_scopes(node_id).await;
        tracing::debug!(node_id, tag_count = tags.len(), "tags added");
        Ok(())
    }

    async fn remove_tags(&self, node_id: &str, tags: Vec<(String, String)>) -> Result<()> {
        self.store_tag_update(node_id, &[], &tags)?;
        self.flush_index().await;
        {
            let mut idx = self.index.write().await;
            let _ = idx.apply_tag_update(node_id, &[], &tags);
        }
        self.mark_index_dirty();
        self.flush_index().await;
        self.sync_node_scopes(node_id).await;
        tracing::debug!(node_id, tag_count = tags.len(), "tags removed");
        Ok(())
    }

    async fn get_tags(&self, node_id: &str) -> Result<Vec<(String, String)>> {
        let idx = self.index.read().await;
        Ok(idx.get_tags(node_id))
    }

    // -- Views --

    async fn list_views(&self) -> Result<Vec<crate::types::View>> {
        let labels = self
            .store
            .query_unique_labels("view", usize::MAX)
            .map_err(|e| ApiError::Serialization(e.to_string()))?;
        let mut views = Vec::new();
        for label in &labels {
            let cid_bytes = hex::decode(label).unwrap_or_default();
            // Skip retracted views
            if self.store.is_retracted(&cid_bytes).unwrap_or(false) {
                continue;
            }
            if let Some(data) = self.store.get_block(&cid_bytes)? {
                if let Some(mut view) = memvault_store::deserialize_block_as::<crate::types::View>(&data) {
                    view.cid = label.clone();
                    views.push(view);
                }
            }
        }
        Ok(views)
    }

    async fn create_view(&self, view: crate::types::View) -> Result<()> {
        // Views are typed side blocks (like attachment manifests,
        // bucket grants, and BucketTrust): the stored block IS the
        // View struct, not a Signed<T> envelope wrapping it. They
        // intentionally bypass build_signed_envelope because their
        // integrity model is "by-CID lookup of a self-describing
        // payload" rather than "audit log of authored events". Don't
        // route this through Signed<T> without coordinated reader
        // changes in list_views / get_view / delete_view.
        let view_bytes =
            serde_ipld_dagcbor::to_vec(&view).map_err(|e| ApiError::Serialization(e.to_string()))?;
        let cid = cid_from_bytes(&view_bytes);
        let cid_bytes = cid.to_bytes();
        let cid_hex = hex::encode(&cid_bytes);
        let meta = EnvelopeMeta {
            author: self.effective_author(),
            tags: vec![("view".to_string(), cid_hex)],
            wall_ns: view.created_ns,
            causal: vec![],
            provenance: vec![],
            cluster_id: Some(self.cluster_id.clone()),
            bucket_id: None,
                    ..Default::default()
        };
        self.store.insert_envelope(&cid_bytes, &view_bytes, &meta)?;
        tracing::info!(name = %view.name, tag_count = view.tags.len(), "view created");
        Ok(())
    }

    async fn delete_view(&self, name: &str) -> Result<()> {
        // Find the view by name (scan all views).
        let views = self.list_views().await?;
        for view in &views {
            if view.name == name {
                let cid_bytes = hex::decode(&view.cid).unwrap_or_default();
                self.retract(&cid_bytes, "view deleted").await?;
            }
        }
        Ok(())
    }

    async fn update_view(&self, view: crate::types::View) -> Result<()> {
        self.delete_view(&view.name).await?;
        self.create_view(view).await
    }

    async fn get_view(&self, name: &str) -> Result<Option<crate::types::View>> {
        // Scan all views and find by name.
        let views = self.list_views().await?;
        Ok(views.into_iter().find(|v| v.name == name))
    }

    // -- Buckets --

    async fn bucket_create(
        &self,
        name: &str,
        description: Option<&str>,
        default_visibility: Visibility,
        default_classification: memvault_core::classification::Classification,
        role: memvault_doc::BucketRole,
    ) -> Result<memvault_core::BucketId> {
        self.bucket_create_inner_async(
            memvault_core::BucketId::random(),
            name,
            description,
            default_visibility,
            default_classification,
            role,
            None,
            None,
        )
        .await
    }


    async fn bucket_list_filtered(
        &self,
        include_merged: bool,
    ) -> Result<Vec<crate::types::BucketInfo>> {
        let buckets = self.store.list_buckets()?;
        let mut infos = Vec::new();

        for (bucket_id_bytes, decl_cid) in buckets {
            if let Some(info) = self.build_bucket_info(&bucket_id_bytes, &decl_cid)? {
                infos.push(info);
            }
        }

        if include_merged {
            return Ok(infos);
        }

        // Merged sources are hidden from default listings (treated like
        // retracted) — but ONLY when their terminal canonical is itself present
        // in this listing. If the canonical has no decl here (a phantom target,
        // or one whose decl hasn't synced to this node), keep the source visible
        // so its data isn't orphaned — otherwise the merged buckets vanish
        // entirely (source hidden + canonical absent). Callers that want every
        // source pass `include_merged`.
        let present: std::collections::HashSet<[u8; 32]> =
            infos.iter().map(|i| i.id.0).collect();
        infos.retain(|i| match &i.merged_into {
            Some(canonical) => !present.contains(&canonical.0),
            None => true,
        });

        Ok(infos)
    }

    async fn bucket_get(
        &self,
        id: &memvault_core::BucketId,
    ) -> Result<Option<crate::types::BucketInfo>> {
        let decl_cid = match self.store.get_bucket(&id.0)? {
            Some(c) => c,
            None => return Ok(None),
        };
        self.build_bucket_info(&id.0, &decl_cid)
    }

    async fn bucket_rename(&self, id: &memvault_core::BucketId, new_name: &str) -> Result<()> {
        let wall_ns = memvault_core::wall_ns();
        let tags = vec![
            ("kind".to_string(), "bucket-rename".to_string()),
            ("bucket".to_string(), id.to_string()),
        ];
        // `payload.BucketRename` shape matches audit parsing
        // (`memvault_query::audit::parse_audit_record`).
        let payload = serde_json::json!({
            "BucketRename": {
                "bucket_id": id.0,
                "new_name": new_name,
                "wall_ns": wall_ns,
            }
        });
        let (cid_bytes, envelope_bytes) = self.build_signed_envelope(
            payload,
            &tags,
            Visibility::Internal,
            wall_ns,
            Some(&id.0),
        )?;
        let meta = memvault_store::insert::EnvelopeMeta {
            author: self.effective_author(),
            tags,
            wall_ns,
            causal: vec![],
            provenance: vec![],
            cluster_id: Some(self.cluster_id.clone()),
            bucket_id: Some(id.0.to_vec()),
                    ..Default::default()
        };
        self.store
            .insert_envelope(&cid_bytes, &envelope_bytes, &meta)?;

        // Update the name in the bucket decl by storing a new decl with the updated name
        if let Some(decl_cid) = self.store.get_bucket(&id.0)? {
            if let Some(block) = self.store.get_block(&decl_cid)? {
                if let Some(mut decl) = Self::parse_bucket_decl(&block) {
                    decl.name = new_name.to_string();
                    let new_bytes = serde_ipld_dagcbor::to_vec(&decl)
                        .map_err(|e| ApiError::Serialization(e.to_string()))?;
                    let new_cid = memvault_core::cid_from_bytes(&new_bytes);
                    self.store.insert_envelope(
                        &new_cid.to_bytes(),
                        &new_bytes,
                        &memvault_store::insert::EnvelopeMeta {
                            author: self.effective_author(),
                            tags: vec![
                                ("kind".to_string(), "bucket-decl".to_string()),
                                ("bucket".to_string(), id.to_string()),
                            ],
                            wall_ns: memvault_core::wall_ns(),
                            causal: vec![decl_cid],
                            provenance: vec![],
                            cluster_id: Some(self.cluster_id.clone()),
                            bucket_id: Some(id.0.to_vec()),
                                                    ..Default::default()
                        },
                    )?;
                    self.store.put_bucket(&id.0, &new_cid.to_bytes())?;
                }
            }
        }

        tracing::info!(bucket = %id, new_name, "bucket renamed");
        Ok(())
    }

    async fn bucket_merge(
        &self,
        sources: &[memvault_core::BucketId],
        canonical: &memvault_core::BucketId,
    ) -> Result<()> {
        self.bucket_merge_sync(sources, canonical)?;
        Ok(())
    }

    async fn bucket_unmerge(
        &self,
        source: &memvault_core::BucketId,
        canonical: &memvault_core::BucketId,
    ) -> Result<()> {
        LocalClient::bucket_unmerge(self, source, canonical).await
    }

    async fn bucket_merges(
        &self,
    ) -> Result<Vec<(memvault_core::BucketId, memvault_core::BucketId)>> {
        Ok(LocalClient::bucket_merges(self))
    }

    async fn agent_rename(&self, agent_pubkey: &[u8; 32], new_label: &str) -> Result<()> {
        let agent_hex = hex::encode(agent_pubkey);

        // A relabel is node-signed and only takes effect when signed by the
        // agent's *attesting node* (see `sigchain::agent_label`). Reject up
        // front if this node can't make it stick — otherwise the write would
        // succeed but the label would be silently ignored on read. This makes
        // the no-op observable to every caller (CLI / MCP / HTTP / web).
        let node_pk = self
            .node_signing_key()
            .map(|k| k.verifying_key().to_bytes())
            .ok_or_else(|| ApiError::Forbidden("node signing key not set".into()))?;
        match crate::sigchain::sole_attesting_node(self, agent_pubkey)? {
            Some(att) if att == node_pk => {}
            Some(_) => {
                return Err(ApiError::Forbidden(format!(
                    "agent {agent_hex} is attested by a different node; \
                     issue the relabel on its attesting node"
                )));
            }
            None => {
                return Err(ApiError::Forbidden(format!(
                    "agent {agent_hex} has no unambiguous attestation on this node; \
                     cannot relabel"
                )));
            }
        }

        let wall_ns = memvault_core::wall_ns();
        let tags = vec![
            ("kind".to_string(), "agent-rename".to_string()),
            ("agent".to_string(), agent_hex.clone()),
        ];
        // `payload.AgentRename` shape matches audit parsing
        // (`memvault_query::audit::parse_audit_record`). Display-only metadata:
        // the rebuilt `agent_labels` index reads this; access control never does.
        let payload = serde_json::json!({
            "AgentRename": {
                "agent_pubkey": agent_pubkey.to_vec(),
                "new_label": new_label,
                "wall_ns": wall_ns,
            }
        });
        let (cid_bytes, envelope_bytes) =
            self.build_signed_envelope(payload, &tags, Visibility::Internal, wall_ns, None)?;
        let meta = memvault_store::insert::EnvelopeMeta {
            author: self.effective_author(),
            tags,
            wall_ns,
            causal: vec![],
            provenance: vec![],
            cluster_id: Some(self.cluster_id.clone()),
            ..Default::default()
        };
        self.store
            .insert_envelope(&cid_bytes, &envelope_bytes, &meta)?;
        tracing::info!(agent = %agent_hex, new_label, "agent relabeled");
        Ok(())
    }

    async fn bucket_bind(
        &self,
        bucket_id: &memvault_core::BucketId,
        cluster_id: &memvault_core::ClusterId,
    ) -> Result<()> {
        self.store
            .bind_bucket(&bucket_id.0, &cluster_id.0)?;
        tracing::info!(bucket = %bucket_id, cluster = %cluster_id, "bucket bound to cluster");
        Ok(())
    }

    async fn bucket_attach(&self, id: &memvault_core::BucketId) -> Result<()> {
        // Load current decl, update private_to_peer to None, store new decl
        let decl_cid = self
            .store
            .get_bucket(&id.0)?
            .ok_or_else(|| ApiError::NotFound(format!("bucket {id}")))?;
        let block = self
            .store
            .get_block(&decl_cid)?
            .ok_or_else(|| ApiError::NotFound("bucket decl block".into()))?;
        let mut decl = Self::parse_bucket_decl(&block)
            .ok_or_else(|| ApiError::Other("failed to decode bucket decl".into()))?;

        if decl.private_to_peer.is_none() {
            // Already attached, idempotent
            return Ok(());
        }

        decl.private_to_peer = None;
        let new_bytes =
            serde_ipld_dagcbor::to_vec(&decl).map_err(|e| ApiError::Serialization(e.to_string()))?;
        let new_cid = memvault_core::cid_from_bytes(&new_bytes);
        let meta = memvault_store::insert::EnvelopeMeta {
            author: self.effective_author(),
            tags: vec![
                ("kind".to_string(), "bucket-decl".to_string()),
                ("bucket".to_string(), id.to_string()),
            ],
            wall_ns: memvault_core::wall_ns(),
            causal: vec![decl_cid],
            provenance: vec![],
            cluster_id: Some(self.cluster_id.clone()),
            bucket_id: Some(id.0.to_vec()),
                    ..Default::default()
        };
        self.store
            .insert_envelope(&new_cid.to_bytes(), &new_bytes, &meta)?;
        self.store.put_bucket(&id.0, &new_cid.to_bytes())?;

        // Also bind to the cluster if not already bound.
        if self.cluster_id.iter().any(|&b| b != 0) {
            let _ = self.store.bind_bucket(&id.0, &self.cluster_id);
        }

        tracing::info!(bucket = %id, "bucket attached to cluster");
        Ok(())
    }

    async fn bucket_archive(&self, id: &memvault_core::BucketId, reason: &str) -> Result<()> {
        let now_ns = memvault_core::wall_ns();
        let tags = vec![
            ("kind".to_string(), "bucket-archive".to_string()),
            ("bucket".to_string(), id.to_string()),
        ];
        // `payload.BucketArchive` shape matches audit parsing
        // (`memvault_query::audit::parse_audit_record`).
        let payload = serde_json::json!({
            "BucketArchive": {
                "bucket_id": id.0,
                "reason": reason,
                "archived_at_ns": now_ns,
            }
        });
        let (cid_bytes, envelope_bytes) = self.build_signed_envelope(
            payload,
            &tags,
            Visibility::Internal,
            now_ns,
            Some(&id.0),
        )?;
        let meta = memvault_store::insert::EnvelopeMeta {
            author: self.effective_author(),
            tags,
            wall_ns: now_ns,
            causal: vec![],
            provenance: vec![],
            cluster_id: Some(self.cluster_id.clone()),
            bucket_id: Some(id.0.to_vec()),
                    ..Default::default()
        };
        self.store
            .insert_envelope(&cid_bytes, &envelope_bytes, &meta)?;

        // Mark the bucket decl as archived by storing an updated decl
        if let Some(decl_cid) = self.store.get_bucket(&id.0)? {
            if let Some(block) = self.store.get_block(&decl_cid)? {
                if let Some(mut decl) = Self::parse_bucket_decl(&block) {
                    decl.name = format!("[ARCHIVED] {}", decl.name);
                    decl.description = Some(format!(
                        "Archived: {}. {}",
                        reason,
                        decl.description.unwrap_or_default()
                    ));
                    let new_bytes = serde_ipld_dagcbor::to_vec(&decl)
                        .map_err(|e| ApiError::Serialization(e.to_string()))?;
                    let new_cid = memvault_core::cid_from_bytes(&new_bytes);
                    self.store.insert_envelope(
                        &new_cid.to_bytes(),
                        &new_bytes,
                        &memvault_store::insert::EnvelopeMeta {
                            author: self.effective_author(),
                            tags: vec![
                                ("kind".to_string(), "bucket-decl".to_string()),
                                ("bucket".to_string(), id.to_string()),
                            ],
                            wall_ns: now_ns,
                            causal: vec![decl_cid],
                            provenance: vec![],
                            cluster_id: Some(self.cluster_id.clone()),
                            bucket_id: Some(id.0.to_vec()),
                                                    ..Default::default()
                        },
                    )?;
                    self.store.put_bucket(&id.0, &new_cid.to_bytes())?;
                }
            }
        }

        tracing::info!(bucket = %id, reason, "bucket archived");
        Ok(())
    }

    async fn bucket_grants_list(&self, bucket_id: &BucketId) -> Result<Vec<GrantInfo>> {
        let grants = LocalClient::list_bucket_grants(self, bucket_id)?;
        Ok(grants
            .into_iter()
            .map(|(cid, g)| GrantInfo {
                cid,
                bucket_id: bucket_id.clone(),
                issuer: g.issuer,
                issuing_cluster: g.issuing_cluster,
                audience: g.audience,
                actions: g.actions,
                not_before_ns: g.not_before_ns,
                not_after_ns: g.not_after_ns,
            })
            .collect())
    }

    // -- Sharing --

    async fn share_inbox(&self) -> Result<Vec<Vec<u8>>> {
        Ok(self.store.list_share_inbox(&self.cluster_id)?)
    }

    async fn share_outbox(&self) -> Result<Vec<Vec<u8>>> {
        // Outbox lists proposals this cluster sent — reuse the same list method
        // with the local cluster as the "from" cluster.
        Ok(self.store.list_share_inbox(&self.cluster_id)?)
    }

    async fn share_get_proposal(&self, proposal_cid: &[u8]) -> Result<Option<ShareProposalInfo>> {
        let Some(block) = self.store.get_block(proposal_cid)? else {
            return Ok(None);
        };
        let proposal = if let Some(p) =
            memvault_store::deserialize_block_as::<memvault_auth::ShareProposal>(&block)
        {
            p
        } else if let Some(signed) = memvault_store::deserialize_block_as::<
            memvault_core::Signed<memvault_auth::ShareProposal>,
        >(&block)
        {
            signed.payload
        } else {
            return Ok(None);
        };
        Ok(Some(ShareProposalInfo {
            cid: proposal_cid.to_vec(),
            proposal_id: proposal.proposal_id,
            from_cluster: proposal.from_cluster,
            from_bucket: proposal.from_bucket,
            from_admin: proposal.from_admin,
            to_cluster: proposal.to_cluster,
            to_recipient: proposal.to_recipient,
            proposed_actions: proposal.proposed_actions,
            purpose: proposal.purpose,
            not_after_ns: proposal.not_after_ns,
        }))
    }

    async fn share_decide(
        &self,
        proposal_cid: &[u8],
        approve: bool,
        reason: Option<&str>,
    ) -> Result<()> {
        let now_ns = memvault_core::wall_ns();
        let status: u8 = if approve { 1 } else { 2 };

        // Update the inbox entry status
        self.store
            .record_share_inbox(proposal_cid, &self.cluster_id, now_ns, status)?;

        // If approved and we have an admin signing key, issue a BucketTrust
        if approve {
            if let Some(admin_key) = self.admin_signing_key() {
                // Load the proposal to get bucket/cluster info
                if let Some(proposal_block) = self.store.get_block(proposal_cid)? {
                    if let Ok(proposal) =
                        memvault_store::deserialize_block(&proposal_block).ok_or_else(|| ApiError::Other("cannot parse proposal".into()))
                    {
                        let from_bucket: Option<Vec<u8>> = proposal
                            .get("from_bucket")
                            .and_then(|v| serde_json::from_value(v.clone()).ok());
                        let from_cluster: Option<Vec<u8>> = proposal
                            .get("from_cluster")
                            .and_then(|v| serde_json::from_value(v.clone()).ok());

                        if let (Some(bucket_bytes), Some(cluster_bytes)) =
                            (from_bucket, from_cluster)
                        {
                            // Create and sign a BucketTrust
                            let proposal_cid_obj = memvault_core::cid_from_bytes(proposal_cid);
                            let reply_cid = memvault_core::cid_from_bytes(&now_ns.to_be_bytes());

                            let trust = memvault_auth::BucketTrust {
                                bucket_id: memvault_core::BucketId(
                                    bucket_bytes.clone().try_into().unwrap_or([0u8; 32]),
                                ),
                                from_cluster: memvault_core::ClusterId(
                                    cluster_bytes.clone().try_into().unwrap_or([0u8; 32]),
                                ),
                                to_cluster: memvault_core::ClusterId(
                                    self.cluster_id.clone().try_into().unwrap_or([0u8; 32]),
                                ),
                                actions: vec![memvault_auth::Action::Read],
                                not_after_ns: now_ns + 7 * 24 * 3600 * 1_000_000_000, // 7 days default
                                from_proposal: proposal_cid_obj,
                                from_reply: reply_cid,
                                signature: [0u8; 64],
                            };

                            match trust.sign(&admin_key) {
                                Ok(signed_trust) => {
                                    let trust_bytes =
                                        serde_ipld_dagcbor::to_vec(&signed_trust).unwrap_or_default();
                                    let trust_cid = memvault_core::cid_from_bytes(&trust_bytes);

                                    // Store the trust in BUCKET_TRUST
                                    let _ = self.store.record_bucket_trust(
                                        &bucket_bytes,
                                        &cluster_bytes,
                                        &self.cluster_id,
                                        &trust_cid.to_bytes(),
                                    );

                                    // Store the trust block itself
                                    let meta = memvault_store::insert::EnvelopeMeta {
                                        author: self.effective_author(),
                                        tags: vec![(
                                            "kind".to_string(),
                                            "bucket-trust".to_string(),
                                        )],
                                        wall_ns: now_ns,
                                        causal: vec![proposal_cid.to_vec()],
                                        provenance: vec![],
                                        cluster_id: Some(self.cluster_id.clone()),
                                        bucket_id: Some(bucket_bytes),
                                                                            ..Default::default()
                                    };
                                    let _ = self.store.insert_envelope(
                                        &trust_cid.to_bytes(),
                                        &trust_bytes,
                                        &meta,
                                    );

                                    tracing::info!(
                                        trust_cid = hex::encode(trust_cid.to_bytes()),
                                        "issued BucketTrust for approved proposal"
                                    );
                                }
                                Err(e) => {
                                    tracing::warn!("failed to sign BucketTrust: {e}");
                                }
                            }
                        }
                    }
                }
            }
        }

        tracing::info!(
            proposal = hex::encode(proposal_cid),
            approve,
            reason = reason.unwrap_or("-"),
            "share proposal decided"
        );
        Ok(())
    }

    async fn status(&self) -> Result<NodeStatus> {
        let block_count = self
            .store
            .iter_blocks()
            .map(|b| b.len() as u64)
            .unwrap_or(0);
        let doc_count = self
            .store
            .query_unique_labels("doc", usize::MAX)
            .map(|l| l.len() as u64)
            .unwrap_or(0);
        tracing::debug!(block_count, doc_count, "status queried");
        Ok(NodeStatus {
            peer_id: self.peer_id.clone(),
            cluster_id: self.cluster_id.clone(),
            block_count,
            doc_count,
            peer_count: 1,
            uptime_secs: self.start_time.elapsed().as_secs(),
        })
    }

    async fn legacy_bucket_id(&self) -> Result<BucketId> {
        self.find_legacy_bucket()
            .ok_or_else(|| ApiError::Other("no legacy bucket configured".into()))
    }

    async fn ensure_agent_bucket(
        &self,
        agent_pubkey: &[u8],
        name_hint: &str,
    ) -> Result<BucketId> {
        // Delegate to the inherent pubkey-keyed helper (also used by the
        // server-side HTTP handlers and the enroll path).
        LocalClient::ensure_agent_bucket_for_pubkey(self, agent_pubkey, name_hint).await
    }

    async fn bucket_grant(
        &self,
        bucket_id: &BucketId,
        audience: memvault_auth::GrantAudience,
        actions: Vec<memvault_auth::Action>,
        ttl_secs: u64,
    ) -> Result<Vec<u8>> {
        // Reuse the existing signed-and-stored grant path; `pick_grant_signer`
        // inside picks admin / owner-agent / node key for us.
        LocalClient::issue_bucket_grant(self, bucket_id, audience, actions, ttl_secs).await
    }

    async fn revoke_grant(&self, grant_cid: &[u8], reason: &str) -> Result<Vec<u8>> {
        LocalClient::revoke_bucket_grant(self, grant_cid, reason).await
    }
}

/// Project an active/retracted count pair onto a retraction mode for reporting.
fn apply_retraction_mode(
    c: crate::types::ScopeCount,
    mode: memvault_core::RetractionMode,
) -> crate::types::ScopeCount {
    match mode {
        memvault_core::RetractionMode::ActiveOnly => crate::types::ScopeCount {
            active: c.active,
            retracted: 0,
        },
        memvault_core::RetractionMode::RetractedOnly => crate::types::ScopeCount {
            active: 0,
            retracted: c.retracted,
        },
        memvault_core::RetractionMode::IncludeRetracted => c,
    }
}

//! LocalClient — implements MemvaultClient directly against the store.

use std::collections::VecDeque;
use std::sync::Arc;

use async_trait::async_trait;
use tokio::sync::RwLock;

use memvault_attach::{self, AttachmentManifest};
use memvault_auth::Role;
use memvault_core::{BucketId, DocId, EdgeId, EntityId, NodeRef, Visibility, cid_from_bytes};
use memvault_doc::{Document, Edge, Entity, Op, TextPatch};
use memvault_query::{AuditQuery, AuditRecord, QuotaManager, SearchHit, TextIndex, query_audit};
use memvault_store::{EnvelopeMeta, MemvaultStore};

use crate::client::MemvaultClient;
use crate::error::{ApiError, Result};
use crate::subscription::{EventBus, MemvaultEvent};
use crate::types::{DocSummary, NodeStatus, RotationInfo, TokenStatus, TraversalHit};

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
            macro_rules! get_doc    { ($id:expr) => { $self.get_doc_sync($id) }; }
            macro_rules! get_entity { ($id:expr) => { $self.get_entity_sync($id) }; }
            $body
        }

        $(#[$meta])*
        #[allow(unused_macros)]
        pub async fn $async_name(&$self $(, $pname: $pty)*) -> $ret {
            macro_rules! idx_read  { () => { $self.index.read().await }; }
            macro_rules! idx_write { () => { $self.index.write().await }; }
            macro_rules! get_doc    { ($id:expr) => { $self.get_doc_async($id).await }; }
            macro_rules! get_entity { ($id:expr) => { $self.get_entity_async($id).await }; }
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

/// LocalClient implements MemvaultClient by calling directly into the store.
pub struct LocalClient {
    store: Arc<MemvaultStore>,
    index: Arc<RwLock<TextIndex>>,
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
    /// Cluster admin pubkey of record. Pinned out-of-band: written by
    /// `memctl genesis` (for the admin) or by `memctl cluster-join`
    /// (for peers, extracted from the join token). The daemon loads
    /// the file `<data_dir>/identity/cluster_admin_genesis.cbor` at
    /// startup and installs it here. `None` for legacy data dirs that
    /// pre-date the pin file.
    pinned_admin_genesis: std::sync::OnceLock<memvault_auth::AdminGenesis>,
    /// Optional admin signing key for token issuance and agent enrollment.
    /// `OnceLock` allows write-once initialisation through a shared `Arc`.
    admin_signing_key: std::sync::OnceLock<ed25519_dalek::SigningKey>,
    /// Optional node signing key — the daemon's libp2p ed25519 private key,
    /// used to sign agent attestations and agent revocations. Distinct from
    /// the admin key on non-genesis-admin daemons. Write-once via `OnceLock`.
    node_signing_key: std::sync::OnceLock<ed25519_dalek::SigningKey>,
    /// Optional agent identity for agent-scoped operations. Write-once
    /// via `OnceLock` so it can be installed through a shared `Arc`.
    agent_identity: std::sync::OnceLock<crate::agent_identity::AgentIdentity>,
    start_time: std::time::Instant,
}

impl LocalClient {
    pub fn new(
        store: Arc<MemvaultStore>,
        index: Arc<RwLock<TextIndex>>,
        quotas: Arc<RwLock<QuotaManager>>,
        event_bus: Arc<EventBus>,
        peer_id: Vec<u8>,
        cluster_id: Vec<u8>,
    ) -> Self {
        let client = Self {
            store,
            index,
            quotas,
            event_bus,
            peer_id,
            cluster_id,
            admin_signing_key: std::sync::OnceLock::new(),
            node_signing_key: std::sync::OnceLock::new(),
            trust_state: std::sync::OnceLock::new(),
            pinned_admin_genesis: std::sync::OnceLock::new(),
            agent_identity: std::sync::OnceLock::new(),
            start_time: std::time::Instant::now(),
        };

        // Auto-bind any unbound buckets to the cluster (handles the case where
        // buckets were created before genesis/cluster-join, and the store is
        // now re-opened with a cluster_id).
        if client.cluster_id.iter().any(|&b| b != 0) {
            let _ = client.store.bind_unbound_buckets(&client.cluster_id);
        }

        client
    }

    /// Create a LocalClient and run a blockstore rebuild if the version
    /// is outdated.  This is the recommended entry point — use `new()`
    /// only when you need to skip the rebuild (e.g. tests).
    /// Create a LocalClient and run a sync blockstore rebuild if the
    /// version is outdated.  This is the recommended entry point.
    pub fn open(
        store: Arc<MemvaultStore>,
        index: Arc<RwLock<TextIndex>>,
        quotas: Arc<RwLock<QuotaManager>>,
        event_bus: Arc<EventBus>,
        peer_id: Vec<u8>,
        cluster_id: Vec<u8>,
    ) -> Result<Self> {
        let client = Self::new(store, index, quotas, event_bus, peer_id, cluster_id);
        if let Err(e) = client.rebuild_if_needed() {
            tracing::warn!("blockstore rebuild error on open: {e}");
        }
        Ok(client)
    }

    /// Set the admin signing key (enables real token issuance). Write-once;
    /// subsequent calls are silently ignored so a daemon that re-enters
    /// initialisation cannot accidentally swap admin identity.
    pub fn set_admin_signing_key(&self, key: ed25519_dalek::SigningKey) {
        let _ = self.admin_signing_key.set(key);
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

    /// Install the cluster's pinned `AdminGenesis`. Write-once. Daemons
    /// call this at startup after reading
    /// `<data_dir>/identity/cluster_admin_genesis.cbor`.
    pub fn set_pinned_admin_genesis(&self, genesis: memvault_auth::AdminGenesis) {
        let _ = self.pinned_admin_genesis.set(genesis);
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
        self.store
            .set_index_notifier(std::sync::Arc::new(move |scope, label, cid| {
                if scope == "sigchain" {
                    bus.publish(MemvaultEvent::SigchainBlock {
                        label: label.to_string(),
                        cid: cid.to_vec(),
                    });
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
    pub fn attest_node(
        &self,
        peer_pubkey: [u8; 32],
        role: memvault_auth::Role,
    ) -> Result<Vec<u8>> {
        use ed25519_dalek::Signer;
        let admin_sk = self
            .admin_signing_key
            .get()
            .ok_or_else(|| ApiError::Other("no admin signing key configured".into()))?;
        let cluster_id_arr: [u8; 32] = self
            .cluster_id
            .clone()
            .try_into()
            .map_err(|_| ApiError::Other("cluster_id must be 32 bytes".into()))?;
        let mut node_att = memvault_auth::NodeAttestation {
            cluster_id: memvault_core::ClusterId(cluster_id_arr),
            member: memvault_core::PeerId(peer_pubkey.to_vec()),
            role,
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
            .admin_signing_key
            .get()
            .ok_or_else(|| ApiError::Other("no admin signing key configured".into()))?;
        let rev = memvault_auth::sign_node_revocation(admin_sk, node_pubkey, reason)
            .map_err(|e| ApiError::Other(format!("sign node revocation: {e}")))?;
        crate::sigchain::publish_node_revocation(self, &rev)
    }

    /// Find or create an `Agent`-role bucket for the given agent ID.
    /// Returns the bucket ID (existing or newly created).
    pub async fn ensure_agent_bucket_for(
        &self,
        agent_id: &memvault_core::AgentId,
    ) -> Result<memvault_core::BucketId> {
        // Check if an agent bucket already exists for this agent.
        let buckets = self.bucket_list().await?;
        for b in &buckets {
            if b.role == memvault_doc::BucketRole::Agent
                && b.owner_agent.as_ref() == Some(agent_id)
            {
                return Ok(b.id.clone());
            }
        }

        let name = format!("agent:{}", agent_id.0);
        let bid = self
            .bucket_create(
                &name,
                Some("auto-created agent bucket"),
                Visibility::Internal,
                memvault_core::classification::Classification::Internal,
                memvault_doc::BucketRole::Agent,
            )
            .await?;
        tracing::info!(agent = %agent_id.0, bucket = %bid, "created agent bucket");
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
    pub fn create_bucket_with_id(
        &self,
        bucket_id: BucketId,
        name: &str,
        description: Option<&str>,
        default_visibility: Visibility,
        default_classification: memvault_core::classification::Classification,
        role: memvault_doc::BucketRole,
    ) -> Result<()> {
        use memvault_doc::BucketDecl;

        let has_cluster = self.cluster_id.iter().any(|&b| b != 0);
        let decl = BucketDecl {
            bucket_id: bucket_id.clone(),
            name: name.to_string(),
            description: description.map(|s| s.to_string()),
            owner_agent: None,
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
    pub fn admin_signing_key(&self) -> Option<&ed25519_dalek::SigningKey> {
        self.admin_signing_key.get()
    }

    /// The admin's verifying key, derived from the signing key. `None` on
    /// peer daemons that don't hold the admin key.
    pub fn admin_verifying_key(&self) -> Option<ed25519_dalek::VerifyingKey> {
        self.admin_signing_key.get().map(|sk| sk.verifying_key())
    }

    pub fn agent_id(&self) -> Option<&memvault_core::AgentId> {
        self.agent_identity.get().map(|i| &i.agent_id)
    }

    /// CID of the bound agent's attestation block, if an agent identity is
    /// bound. Used by envelope builders to embed an inline attribution
    /// reference so reads can resolve the agent without a sidecar.
    pub fn agent_attestation_cid(&self) -> Option<&[u8]> {
        self.agent_identity
            .get()
            .map(|i| i.attestation_cid.as_slice())
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
            agent_attestation: agent.map(|a| a.attestation_cid.clone()),
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

        // Fallback: no node signing key configured (tests, pre-genesis
        // bootstrap, headless tooling). Emit an unsigned envelope with
        // the same field shape so the store extracts metadata correctly
        // and the verifier reports `NoSidecar` rather than failing.
        let envelope = serde_json::json!({
            "version": 1,
            "payload": payload,
            "author": self.peer_id,
            "tags": tags,
            "visibility": visibility,
            "wall_ns": wall_ns,
            "bucket_id": bucket_id,
        });
        let envelope_bytes = serde_ipld_dagcbor::to_vec(&envelope)
            .map_err(|e| ApiError::Serialization(e.to_string()))?;
        let cid_bytes = memvault_core::cid_from_bytes(&envelope_bytes).to_bytes();
        Ok((cid_bytes, envelope_bytes))
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

        Ok(Some(crate::types::BucketInfo {
            id: decl.bucket_id,
            name: decl.name,
            description: decl.description,
            owner_agent: decl.owner_agent,
            cluster_id,
            is_attached: decl.private_to_peer.is_none(),
            default_visibility: decl.default_visibility,
            default_classification: decl.default_classification,
            created_ns: decl.created_ns,
            envelope_count,
            role: decl.role,
        }))
    }

    /// Load the TextIndex from a cache file, or rebuild from the blockstore if
    /// the cache is missing/stale. Saves the rebuilt index afterward.
    /// Call this after construction to make search work for pre-existing data.
    pub async fn load_or_rebuild_index(
        &self,
        cache_path: &std::path::Path,
    ) -> Result<(usize, usize, usize)> {
        if let Some(loaded) = TextIndex::load(cache_path) {
            let mut idx = self.index.write().await;
            *idx = loaded;
            let count = idx.len();
            tracing::info!("loaded text index from cache ({count} entries)");
            return Ok((count, 0, 0));
        }
        tracing::info!("text index cache missing or stale, rebuilding from blockstore...");
        let counts = self.populate_index().await?;
        let idx = self.index.read().await;
        if let Err(e) = idx.save(cache_path) {
            tracing::warn!("failed to save text index cache: {e}");
        } else {
            tracing::info!("saved text index cache to {}", cache_path.display());
        }
        Ok(counts)
    }

    // ── dual_impl! generated method pairs ────────────────────────────

    dual_impl! {
        /// Reconstruct a document from the blockstore.
        (get_doc_sync, get_doc_async)
        fn(&self, id: &DocId) -> Result<Option<Document>>
        {
            let node_id = format!("doc:{}", hex::encode(id.0));
            {
                let idx = idx_read!();
                if idx.is_retracted(&node_id) {
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
        /// Reconstruct an entity from the blockstore.
        (get_entity_sync, get_entity_async)
        fn(&self, id: &EntityId) -> Result<Option<Entity>>
        {
            let node_id = format!("entity:{}", hex::encode(id.0));
            {
                let idx = idx_read!();
                if idx.is_retracted(&node_id) {
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
                // Skip docs without a bucket — they are unbucketed foreign data.
                if self.inferred_doc_bucket(&doc_id).is_none() {
                    continue;
                }
                if let Ok(Some(doc)) = get_doc!(&doc_id) {
                    let title = doc.frontmatter.get("title").and_then(|v| v.as_str());
                    // Recover creation-time tags from the envelope metadata.
                    let creation_tags = self.extract_creation_tags("doc", label);
                    let mut idx = idx_write!();
                    idx.index_doc(doc_id, &doc.body, title, creation_tags);
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
                // Skip entities without a bucket — they are unbucketed foreign data.
                if self.inferred_entity_bucket(&eid).is_none() {
                    continue;
                }
                if let Ok(Some(entity)) = get_entity!(&eid) {
                    let creation_tags = self.extract_creation_tags("entity", label);
                    let mut idx = idx_write!();
                    idx.index_entity(&eid, &entity.kind, &entity.props, creation_tags);
                    entity_count += 1;
                }
            }

            // Index attachments
            let blocks = self
                .store
                .iter_blocks()
                .map_err(|e| ApiError::Serialization(e.to_string()))?;
            for (_, data) in &blocks {
                if let Some(view) = memvault_store::EnvelopeView::parse(data) {
                    if view.str_field("kind") == Some("attachment") {
                        // Skip attachments without a bucket.
                        if view.field("bucket_id").and_then(|v| v.as_array()).is_none() {
                            continue;
                        }
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
                            idx.index_attachment(&mcid, filename, mime_type, text.as_deref(), att_tags);
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
                                    idx.apply_tag_update(target, &add, &remove);
                                }
                                "retraction" => {
                                    idx.retract_node(target);
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
                            idx.apply_tag_update(node_id, &add, &remove);
                        }
                    } else if kind == Some("node_retraction") {
                        let node_id = val.get("node_id").and_then(|v| v.as_str()).unwrap_or("");
                        if !node_id.is_empty() {
                            let mut idx = idx_write!();
                            idx.retract_node(node_id);
                        }
                    }
                }
            }

            Ok((doc_count, entity_count, attachment_count))
        }
    }

    /// Save the current TextIndex to a cache file.
    pub async fn save_index(&self, cache_path: &std::path::Path) -> Result<()> {
        let idx = self.index.read().await;
        idx.save(cache_path)
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
            let val: serde_json::Value = memvault_store::deserialize_block(&block_data)?;

            // Unified annotation format
            let data_field = val.get("data").unwrap_or(&val);

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

    /// Access the text index (for direct queries in local backend).
    pub fn index_ref(&self) -> &Arc<RwLock<TextIndex>> {
        &self.index
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
            return self.inferred_node_bucket(&node);
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
        let admin_key = self.admin_signing_key.get().ok_or_else(|| {
            ApiError::Other("no admin signing key — cannot issue grants".into())
        })?;

        let now_ns = memvault_core::wall_ns();
        let not_after_ns = now_ns + ttl_secs * 1_000_000_000;
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
        let sig = admin_key.sign(&signing_bytes);
        grant.signature = sig.to_bytes();

        // Store as tagged block
        let grant_json = serde_ipld_dagcbor::to_vec(&grant)
            .map_err(|e| ApiError::Serialization(e.to_string()))?;
        let cid = memvault_core::cid_from_bytes(&grant_json);
        let cid_bytes = cid.to_bytes();

        let bucket_hex = hex::encode(bucket_id.0);
        let meta = memvault_store::EnvelopeMeta {
            author: self.effective_author(),
            tags: vec![
                ("grant".to_string(), bucket_hex),
                ("kind".to_string(), "grant".to_string()),
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

    /// List all grants scoped to a bucket.
    pub fn list_bucket_grants(
        &self,
        bucket_id: &BucketId,
    ) -> Result<Vec<(Vec<u8>, memvault_auth::Grant)>> {
        let bucket_hex = hex::encode(bucket_id.0);
        let cids = self
            .store
            .query_by_tag("grant", &bucket_hex, 0, 1000)
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

        // Index for search
        let title = doc
            .frontmatter
            .get("title")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
        {
            let mut idx = self.index.write().await;
            idx.index_doc(doc.id.clone(), &doc.body, title.as_deref(), tags.clone());
        }

        self.event_bus.publish(MemvaultEvent::DocCreated {
            doc_id: doc.id,
            cid: cid_bytes.clone(),
        });

        Ok(cid_bytes)
    }

    async fn get_doc(&self, id: &DocId) -> Result<Option<Document>> {
        self.get_doc_async(id).await
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
        // Explicit bucket → scope to that bucket.
        // None → scope to all accessible buckets (or unscoped pre-genesis).
        let bucket_cid_set: Option<std::collections::HashSet<Vec<u8>>> =
            if let Some(bid) = bucket {
                let bucket_cids = self.store.query_by_bucket(&bid.0, 0, limit * 10)?;
                Some(bucket_cids.into_iter().collect())
            } else {
                let all = self.accessible_bucket_cids(limit * 10)?;
                if all.is_empty() { None } else { Some(all) }
            };

        let cids = if let Some((ref scope, ref label)) = tag_filter {
            self.store.query_by_tag(scope, label, 0, limit * 5)?
        } else {
            self.store
                .query_unique_labels("doc", limit * 5)?
                .into_iter()
                .flat_map(|label| {
                    self.store
                        .query_by_tag("doc", &label, 0, 10)
                        .unwrap_or_default()
                })
                .collect()
        };

        let mut summaries = Vec::new();
        let mut seen_docs: std::collections::HashSet<DocId> = std::collections::HashSet::new();

        for cid in &cids {
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
                                    let idx = self.index.read().await;
                                    if idx.is_retracted(&node_id) {
                                        continue;
                                    }
                                    drop(idx);
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

        // Store envelope metadata for the manifest
        let bucket_id = self.resolve_bucket(bucket);
        let meta = EnvelopeMeta {
            author: self.effective_author(),
            tags: tags.clone(),
            wall_ns: memvault_core::wall_ns(),
            causal: vec![],
            provenance: vec![],
            cluster_id: Some(self.cluster_id.clone()),
            bucket_id,
                    ..Default::default()
        };
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
            idx.index_attachment(
                &manifest_cid_bytes,
                filename,
                mime_type,
                extracted_text.as_deref(),
                tags.clone(),
            );
        }

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

    async fn add_entity(
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
        {
            let mut idx = self.index.write().await;
            idx.index_entity(&entity_id, &entity.kind, &entity.props, tags.clone());
        }

        self.event_bus.publish(MemvaultEvent::EntityCreated {
            entity_id: entity_id.clone(),
        });

        Ok(entity_id)
    }

    async fn get_entity(&self, id: &EntityId) -> Result<Option<Entity>> {
        self.get_entity_async(id).await
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
        // Explicit bucket → scope to that bucket.
        // None → scope to all accessible buckets (or unscoped pre-genesis).
        let bucket_cid_set: Option<std::collections::HashSet<Vec<u8>>> =
            if let Some(bid) = bucket {
                let bucket_cids = self.store.query_by_bucket(&bid.0, 0, limit * 10)?;
                Some(bucket_cids.into_iter().collect())
            } else {
                let all = self.accessible_bucket_cids(limit * 10)?;
                if all.is_empty() { None } else { Some(all) }
            };

        let labels = self.store.query_unique_labels("entity", limit)?;
        let mut entities = Vec::new();
        for label in labels {
            // When bucket-filtered, check if any of this entity's CIDs are in the bucket.
            if let Some(ref bset) = bucket_cid_set {
                let entity_cids = self
                    .store
                    .query_by_tag("entity", &label, 0, 10)
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
            if let Ok(Some(entity)) = self.get_entity(&entity_id).await {
                entities.push(entity);
            }
        }
        Ok(entities)
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
        let idx = self.index.read().await;
        let hits = idx.search(query, limit * 2);
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
                    .query_by_tag("doc", &label, 0, 10)
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
        let idx = self.index.read().await;
        let hits = idx.search_unified(query, limit * 2);
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
        let idx = self.index.read().await;
        Ok(idx.members_of_view(&view.tags))
    }

    async fn list_all(
        &self,
        view_name: Option<&str>,
        limit: usize,
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
        let idx = self.index.read().await;
        let all = idx.list_all(view_tags.as_deref(), limit * 2);
        drop(idx);

        let buckets = self.store.list_buckets().unwrap_or_default();
        if buckets.is_empty() {
            return Ok(all.into_iter().take(limit).collect()); // pre-genesis
        }
        let bucket_ids: Vec<Vec<u8>> = buckets.into_iter().map(|(id, _)| id).collect();
        Ok(all
            .into_iter()
            .filter(|(node_id, _, _, _)| {
                if let Some(node_bucket) = self.inferred_bucket_for_node_id(node_id) {
                    bucket_ids.iter().any(|b| *b == node_bucket)
                } else {
                    false
                }
            })
            .take(limit)
            .collect())
    }

    async fn resolve_label(&self, node_id: &str) -> Result<Option<String>> {
        let idx = self.index.read().await;
        Ok(idx.resolve_label(node_id))
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

    async fn retract_node(&self, node_id: &str, reason: &str) -> Result<()> {
        self.store_annotation(
            node_id,
            "retraction",
            serde_json::json!({ "reason": reason }),
        )?;
        tracing::info!(node_id, reason, "node retracted");

        // Remove from in-memory index.
        let mut idx = self.index.write().await;
        idx.retract_node(node_id);

        Ok(())
    }

    async fn issue_token(
        &self,
        role: Role,
        ttl_secs: u64,
        max_uses: u32,
        label: Option<String>,
    ) -> Result<String> {
        let admin_key = self.admin_signing_key.get().ok_or_else(|| {
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
            admin_key,
            role,
            ttl_secs,
            max_uses,
            label,
            self.pinned_admin_genesis().cloned(),
            &self.store,
        )
    }

    async fn list_tokens(&self) -> Result<Vec<TokenStatus>> {
        crate::tokens::list_tokens(&self.store)
    }

    async fn revoke_token(&self, token_cid: &[u8], reason: &str) -> Result<()> {
        self.store.record_revocation(token_cid, reason.as_bytes())?;
        Ok(())
    }

    async fn list_rotations(&self) -> Result<Vec<RotationInfo>> {
        crate::rotation::list_rotations(&self.store)
    }

    // -- Tags --

    async fn add_tags(&self, node_id: &str, tags: Vec<(String, String)>) -> Result<()> {
        self.store_tag_update(node_id, &tags, &[])?;
        let mut idx = self.index.write().await;
        idx.apply_tag_update(node_id, &tags, &[]);
        tracing::debug!(node_id, tag_count = tags.len(), "tags added");
        Ok(())
    }

    async fn remove_tags(&self, node_id: &str, tags: Vec<(String, String)>) -> Result<()> {
        self.store_tag_update(node_id, &[], &tags)?;
        let mut idx = self.index.write().await;
        idx.apply_tag_update(node_id, &[], &tags);
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
        use memvault_doc::BucketDecl;

        let bucket_id = memvault_core::BucketId::random();
        let now_ns = memvault_core::wall_ns();

        // Auto-attach to cluster if the node has one (non-zero cluster_id).
        // Buckets are only private when created before genesis (no cluster yet).
        let has_cluster = self.cluster_id.iter().any(|&b| b != 0);
        let decl = BucketDecl {
            bucket_id: bucket_id.clone(),
            name: name.to_string(),
            description: description.map(|s| s.to_string()),
            owner_agent: self.agent_identity.get().map(|i| i.agent_id.clone()),
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

        // Wrap BucketDecl in an envelope so the block is self-describing
        // (carries its own tags/author/wall_ns for reindexing after sync).
        let tags = vec![
            ("kind".to_string(), "bucket-decl".to_string()),
            ("bucket".to_string(), bucket_id.to_string()),
        ];
        // Payload shape preserves `payload.BucketCreate` so `parse_bucket_decl`
        // continues to find the decl after the Signed<T> migration.
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

        // Record in BUCKETS table
        self.store.put_bucket(&bucket_id.0, &cid_bytes)?;

        // Auto-bind to cluster if one exists
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

    async fn bucket_list(&self) -> Result<Vec<crate::types::BucketInfo>> {
        let buckets = self.store.list_buckets()?;
        let mut infos = Vec::new();

        for (bucket_id_bytes, decl_cid) in buckets {
            let info = self.build_bucket_info(&bucket_id_bytes, &decl_cid)?;
            if let Some(info) = info {
                infos.push(info);
            }
        }

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

    // -- Sharing --

    async fn share_inbox(&self) -> Result<Vec<Vec<u8>>> {
        Ok(self.store.list_share_inbox(&self.cluster_id)?)
    }

    async fn share_outbox(&self) -> Result<Vec<Vec<u8>>> {
        // Outbox lists proposals this cluster sent — reuse the same list method
        // with the local cluster as the "from" cluster.
        Ok(self.store.list_share_inbox(&self.cluster_id)?)
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
            if let Some(admin_key) = self.admin_signing_key.get() {
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

                            match trust.sign(admin_key) {
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

    async fn ensure_agent_bucket(&self, agent_id: &str) -> Result<BucketId> {
        let aid = memvault_core::AgentId(agent_id.to_string());
        self.ensure_agent_bucket_for(&aid).await
    }
}

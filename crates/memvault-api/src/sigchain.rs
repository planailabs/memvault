//! Sig-chain persistence — node attestations, admin rotations, and
//! agent/node revocations stored as tagged blocks in the blockstore.
//!
//! Blocks written through these helpers participate in the existing RBSR
//! sync (phase 5b — actual peer-to-peer broadcast on create is a follow-up).
//! On startup, the daemon scans the blockstore for these tags and rebuilds
//! its in-memory `node_trust`, `revoked_agents`, and `revoked_nodes` tables.
//!
//! Tag layout (kind / label):
//! - `("sigchain", "node_att")` — values are CBOR-encoded `NodeAttestation`
//! - `("sigchain", "agent_rev")` — CBOR `AgentRevocation`
//! - `("sigchain", "node_rev")` — CBOR `NodeRevocation`

use std::collections::{HashMap, HashSet};

use crate::error::{ApiError, Result};
use crate::local::LocalClient;
use memvault_auth::jwt::NodeTrust;
use memvault_auth::{
    AgentAttestation, AgentRevocation, EnvelopeAuthorship, NodeAttestation, NodeRevocation,
};
use memvault_store::insert::EnvelopeMeta;

const KIND: &str = "sigchain";
const LABEL_NODE_ATT: &str = "node_att";
const LABEL_AGENT_ATT: &str = "agent_att";
const LABEL_AGENT_REV: &str = "agent_rev";
const LABEL_NODE_REV: &str = "node_rev";
const LABEL_ENV_AUTH: &str = "envelope_auth";
/// Secondary tag carrying the hex-encoded envelope CID, so a verifier can
/// look up the authorship sidecar in O(1) given just the envelope CID.
const KIND_ENV_AUTH_BY_CID: &str = "env_auth_by_cid";

fn write_block(client: &LocalClient, label: &str, bytes: &[u8]) -> Result<Vec<u8>> {
    write_block_with_extra_tags(client, label, bytes, Vec::new())
}

fn write_block_with_extra_tags(
    client: &LocalClient,
    label: &str,
    bytes: &[u8],
    extra_tags: Vec<(String, String)>,
) -> Result<Vec<u8>> {
    let cid = memvault_core::cid_from_bytes(bytes);
    let cid_bytes = cid.to_bytes();
    let mut tags = vec![(KIND.to_string(), label.to_string())];
    tags.extend(extra_tags);
    let meta = EnvelopeMeta {
        author: client.peer_id().to_vec(),
        tags,
        wall_ns: memvault_core::wall_ns(),
        cluster_id: Some(client.cluster_id().to_vec()),
        ..Default::default()
    };
    // SigchainBlock event publishing happens via the store's index_notifier
    // (installed by `LocalClient::install_sigchain_notifier`) so local writes
    // AND blocks arriving via RBSR sync (which use `reindex_block`) both
    // notify watchers through the same path.
    client
        .store()
        .insert_envelope(&cid_bytes, bytes, &meta)
        .map_err(|e| ApiError::Other(format!("write {label}: {e}")))?;
    Ok(cid_bytes)
}

/// Persist a node `NodeAttestation` so it survives daemon restart and
/// can be picked up by other peers via RBSR sync.
pub fn publish_node_attestation(
    client: &LocalClient,
    attestation: &NodeAttestation,
) -> Result<Vec<u8>> {
    let bytes = serde_ipld_dagcbor::to_vec(attestation)
        .map_err(|e| ApiError::Serialization(e.to_string()))?;
    write_block(client, LABEL_NODE_ATT, &bytes)
}

/// Persist an `AgentAttestation` (the node-signed proof that an agent
/// belongs to this node). Required for cluster-wide envelope authorship
/// verification — the verifier on a peer node walks these to build its
/// trusted-agent set.
pub fn publish_agent_attestation(
    client: &LocalClient,
    attestation: &AgentAttestation,
) -> Result<Vec<u8>> {
    let bytes = serde_ipld_dagcbor::to_vec(attestation)
        .map_err(|e| ApiError::Serialization(e.to_string()))?;
    write_block(client, LABEL_AGENT_ATT, &bytes)
}

/// Persist an `AgentRevocation`.
pub fn publish_agent_revocation(
    client: &LocalClient,
    revocation: &AgentRevocation,
) -> Result<Vec<u8>> {
    let bytes = serde_ipld_dagcbor::to_vec(revocation)
        .map_err(|e| ApiError::Serialization(e.to_string()))?;
    write_block(client, LABEL_AGENT_REV, &bytes)
}

/// Persist a `NodeRevocation`.
pub fn publish_node_revocation(
    client: &LocalClient,
    revocation: &NodeRevocation,
) -> Result<Vec<u8>> {
    let bytes = serde_ipld_dagcbor::to_vec(revocation)
        .map_err(|e| ApiError::Serialization(e.to_string()))?;
    write_block(client, LABEL_NODE_REV, &bytes)
}

/// Persist an `EnvelopeAuthorship` sidecar block. Also tags it with the
/// envelope CID so the verifier can look it up in O(1).
pub fn publish_envelope_authorship(
    client: &LocalClient,
    auth: &EnvelopeAuthorship,
) -> Result<Vec<u8>> {
    let bytes =
        serde_ipld_dagcbor::to_vec(auth).map_err(|e| ApiError::Serialization(e.to_string()))?;
    let extra = vec![(
        KIND_ENV_AUTH_BY_CID.to_string(),
        hex::encode(&auth.envelope_cid),
    )];
    write_block_with_extra_tags(client, LABEL_ENV_AUTH, &bytes, extra)
}

/// Look up the authorship sidecar for a given envelope CID. Returns the
/// first successfully decoded block; on a well-behaved node there should
/// only be one. Does not verify the signature — caller's responsibility.
pub fn lookup_envelope_authorship(
    client: &LocalClient,
    envelope_cid: &[u8],
) -> Result<Option<EnvelopeAuthorship>> {
    let hex_cid = hex::encode(envelope_cid);
    let cids = client
        .store()
        .query_by_tag(KIND_ENV_AUTH_BY_CID, &hex_cid, 0, usize::MAX)
        .map_err(|e| ApiError::Other(format!("query envelope_auth: {e}")))?;
    for cid in cids {
        if let Ok(Some(bytes)) = client.store().get_block(&cid) {
            if let Ok(auth) = serde_ipld_dagcbor::from_slice::<EnvelopeAuthorship>(&bytes) {
                return Ok(Some(auth));
            }
        }
    }
    Ok(None)
}

/// Outcome of [`verify_envelope_authorship`]. Distinguishes "no sidecar
/// exists" (system or pre-auth write — common) from "sidecar exists but is
/// invalid" (tampered or revoked — fail closed).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthorshipStatus {
    /// No sidecar block exists for this envelope CID — read is allowed as
    /// "unattributed" (e.g. system writes, rebuild, pre-genesis bootstrap).
    NoSidecar,
    /// Sidecar exists, signature verifies, agent is currently trusted.
    Valid { agent_pubkey: [u8; 32] },
    /// Sidecar exists but the signature does not verify against the embedded
    /// agent pubkey.
    BadSignature,
    /// Sidecar verifies but the agent is not in any known attestation, OR
    /// has been revoked.
    AgentNotTrusted { agent_pubkey: [u8; 32] },
}

/// Verify the authorship sidecar for an envelope CID. Walks:
///
/// 1. **CID lookup** — find the sidecar (none → [`AuthorshipStatus::NoSidecar`]).
/// 2. **Signature** — `signature` verifies against the embedded `agent_pubkey`.
/// 3. **Attestation chain** — the agent pubkey must be present in an
///    [`memvault_auth::AgentAttestation`] issued by a currently-trusted
///    node, AND must not appear in the revoked-agents set.
///
/// `trusted_agent_pubkeys` is a set of agent pubkeys that the caller has
/// already determined to be currently trusted (i.e. attested by a node in
/// `node_trust` and not in `revoked_agents`). Building this set is the
/// caller's job — the verifier doesn't scan the chain again per call.
pub fn verify_envelope_authorship(
    client: &LocalClient,
    envelope_cid: &[u8],
    trusted_agent_pubkeys: &HashSet<[u8; 32]>,
) -> Result<AuthorshipStatus> {
    let Some(auth) = lookup_envelope_authorship(client, envelope_cid)? else {
        return Ok(AuthorshipStatus::NoSidecar);
    };
    if auth.verify_signature().is_err() {
        return Ok(AuthorshipStatus::BadSignature);
    }
    if !trusted_agent_pubkeys.contains(&auth.agent_pubkey) {
        return Ok(AuthorshipStatus::AgentNotTrusted {
            agent_pubkey: auth.agent_pubkey,
        });
    }
    Ok(AuthorshipStatus::Valid {
        agent_pubkey: auth.agent_pubkey,
    })
}

/// Live trust state shared between the verifier (HTTP request path) and the
/// sigchain watcher (background task). The watcher mutates these in place
/// when new sigchain blocks land; verifiers take read locks per request.
///
/// Held by [`crate::sigchain::spawn_sigchain_watcher`] and the web layer's
/// `AppState` simultaneously — both Arc-clone the same handles.
#[derive(Clone)]
pub struct LiveTrustState {
    pub node_trust: std::sync::Arc<
        std::sync::RwLock<HashMap<[u8; 32], NodeTrust>>,
    >,
    pub revoked_agents: std::sync::Arc<std::sync::RwLock<HashSet<[u8; 32]>>>,
    pub revoked_nodes: std::sync::Arc<std::sync::RwLock<HashSet<[u8; 32]>>>,
    /// Cached set of agent pubkeys currently trusted (attested by a node in
    /// `node_trust` and not in `revoked_agents`). Recomputed by the watcher
    /// whenever a relevant block lands. Verifiers use this for O(1) lookups
    /// instead of rescanning the chain per request.
    pub trusted_agents: std::sync::Arc<std::sync::RwLock<HashSet<[u8; 32]>>>,
}

/// Spawn the sigchain watcher into the current tokio runtime.
///
/// **Must be called from an async context** — i.e. from inside an `async`
/// fn driven by the caller's runtime, or from inside a closure passed to
/// `tokio::runtime::Runtime::block_on`. The watcher lives on the caller's
/// runtime and is dropped/aborted when that runtime shuts down.
///
/// Events arrive both from local writes (publish_*) and from RBSR sync
/// (which calls `insert_envelope` on incoming blocks, and that must also
/// publish `SigchainBlock` — the sync layer's responsibility).
pub fn spawn_sigchain_watcher(
    client: std::sync::Arc<LocalClient>,
    admin_pubkey: Option<ed25519_dalek::VerifyingKey>,
    state: LiveTrustState,
) -> tokio::task::JoinHandle<()> {
    let rx = client.event_bus().subscribe();
    tokio::spawn(run_watcher(client, admin_pubkey, state, rx))
}

/// Watcher body — separated from [`spawn_sigchain_watcher`] so callers
/// can `tokio::spawn` it onto whatever runtime they own.
async fn run_watcher(
    client: std::sync::Arc<LocalClient>,
    admin_pubkey: Option<ed25519_dalek::VerifyingKey>,
    state: LiveTrustState,
    mut rx: tokio::sync::broadcast::Receiver<crate::MemvaultEvent>,
) {
    loop {
        let event = match rx.recv().await {
            Ok(e) => e,
            Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                tracing::info!("sigchain watcher: event bus closed, stopping");
                return;
            }
            Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                tracing::warn!(
                    skipped = n,
                    "sigchain watcher lagged; rescanning sigchain to recover"
                );
                rescan_into(&client, admin_pubkey.as_ref(), &state);
                continue;
            }
        };
        let crate::MemvaultEvent::SigchainBlock { label, cid } = event else {
            continue;
        };
        apply_sigchain_block(&client, admin_pubkey.as_ref(), &state, &label, &cid);
    }
}

/// Recompute the cached set of currently-trusted agent pubkeys from the
/// node_trust + revoked_agents handles in `state`. Called by the watcher
/// whenever an agent attestation or revocation lands.
fn refresh_trusted_agents(client: &LocalClient, state: &LiveTrustState) {
    let nt = state
        .node_trust
        .read()
        .map(|m| m.clone())
        .unwrap_or_default();
    let ra = state
        .revoked_agents
        .read()
        .map(|s| s.clone())
        .unwrap_or_default();
    let Ok(fresh) = scan_trusted_agents(client, &nt, &ra) else {
        return;
    };
    if let Ok(mut w) = state.trusted_agents.write() {
        *w = fresh;
    }
}

/// Re-scan the entire sigchain and replace the live trust state. Used to
/// recover when the watcher's broadcast channel lags (events dropped).
fn rescan_into(
    client: &LocalClient,
    admin_pubkey: Option<&ed25519_dalek::VerifyingKey>,
    state: &LiveTrustState,
) {
    if let Ok(nodes) = scan_trusted_nodes(client, admin_pubkey) {
        if let Ok(mut w) = state.node_trust.write() {
            // Preserve in-memory-only PreGenesis entries (the local node's
            // self-trust seed before genesis). Persisted attestations
            // overwrite anything for the same key.
            for (k, v) in nodes {
                w.insert(k, v);
            }
        }
    }
    let nt_snapshot = state
        .node_trust
        .read()
        .map(|m| m.clone())
        .unwrap_or_default();
    if let Ok((agents, nodes)) = scan_revocations(client, admin_pubkey, &nt_snapshot) {
        if let Ok(mut w) = state.revoked_agents.write() {
            *w = agents;
        }
        if let Ok(mut w) = state.revoked_nodes.write() {
            *w = nodes;
        }
    }
    refresh_trusted_agents(client, state);
}

/// Apply a single sigchain block to the live trust state. Verifies the
/// block's signature before applying — invalid blocks are logged and
/// dropped.
fn apply_sigchain_block(
    client: &LocalClient,
    admin_pubkey: Option<&ed25519_dalek::VerifyingKey>,
    state: &LiveTrustState,
    label: &str,
    cid: &[u8],
) {
    let Ok(Some(bytes)) = client.store().get_block(cid) else {
        tracing::warn!(label, "sigchain watcher: missing block bytes");
        return;
    };
    match label {
        LABEL_NODE_ATT => {
            let Ok(att) = serde_ipld_dagcbor::from_slice::<NodeAttestation>(&bytes) else {
                tracing::warn!("sigchain watcher: bad NodeAttestation bytes");
                return;
            };
            // Verify against admin if we have one. Pre-genesis: nothing to
            // verify against, so peer attestations are ignored — only the
            // local self-trust seed (installed by bootstrap_cluster_trust) counts.
            let Some(admin) = admin_pubkey else { return };
            if att.verify_signature(admin).is_err() {
                tracing::warn!("sigchain watcher: NodeAttestation signature invalid");
                return;
            }
            if att.member.0.len() != 32 {
                return;
            }
            let mut pkbytes = [0u8; 32];
            pkbytes.copy_from_slice(&att.member.0);
            if let Ok(mut w) = state.node_trust.write() {
                w.insert(pkbytes, NodeTrust::Attested(att));
            }
            // A newly-trusted node may make some previously-untrusted agents
            // trusted (their AgentAttestation now chains back).
            refresh_trusted_agents(client, state);
        }
        LABEL_AGENT_REV => {
            let Ok(rev) = serde_ipld_dagcbor::from_slice::<AgentRevocation>(&bytes) else {
                tracing::warn!("sigchain watcher: bad AgentRevocation bytes");
                return;
            };
            // Must come from a currently-trusted node.
            let known = state
                .node_trust
                .read()
                .map(|m| m.contains_key(&rev.node_pubkey))
                .unwrap_or(false);
            if !known {
                tracing::warn!("sigchain watcher: AgentRevocation from unknown node");
                return;
            }
            if rev.verify_signature().is_err() {
                tracing::warn!("sigchain watcher: AgentRevocation signature invalid");
                return;
            }
            if let Ok(mut w) = state.revoked_agents.write() {
                w.insert(rev.agent_pubkey);
            }
            // Drop from trusted_agents too — fail closed on subsequent reads.
            if let Ok(mut w) = state.trusted_agents.write() {
                w.remove(&rev.agent_pubkey);
            }
        }
        LABEL_AGENT_ATT => {
            // New agent attestation — refresh the trusted_agents cache. We
            // could verify the single block, but a rescan covers cascading
            // effects (e.g. an attestation referencing a node that was just
            // added) and is bounded by the AgentAttestation block count.
            refresh_trusted_agents(client, state);
        }
        LABEL_NODE_REV => {
            let Ok(rev) = serde_ipld_dagcbor::from_slice::<NodeRevocation>(&bytes) else {
                tracing::warn!("sigchain watcher: bad NodeRevocation bytes");
                return;
            };
            let Some(admin) = admin_pubkey else { return };
            if rev.admin_pubkey != admin.to_bytes() {
                return;
            }
            if rev.verify_signature().is_err() {
                return;
            }
            if let Ok(mut w) = state.revoked_nodes.write() {
                w.insert(rev.node_pubkey);
            }
            // Every agent attested by this node is now transitively untrusted.
            refresh_trusted_agents(client, state);
        }
        // AgentAttestation / EnvelopeAuthorship are looked up on demand by
        // the verifier — no live mutation needed.
        _ => {}
    }
}

/// Walk every persisted [`memvault_auth::AgentAttestation`] and return the
/// pubkey set of agents currently trusted under `node_trust` and not
/// present in `revoked_agents`. Used by the verifier to validate envelope
/// authorship without re-scanning per call.
/// Load every persisted [`AgentAttestation`] block, signature-verified.
/// Unlike [`scan_trusted_agents`], this preserves the node→agent
/// relationship and does not filter against node_trust or revocations —
/// callers (e.g. the admin trust-tree UI) decide what to display.
pub fn scan_agent_attestations(client: &LocalClient) -> Result<Vec<AgentAttestation>> {
    let mut out = Vec::new();
    for bytes in load_blocks_by_label(client, LABEL_AGENT_ATT)? {
        let att: AgentAttestation = match serde_ipld_dagcbor::from_slice(&bytes) {
            Ok(a) => a,
            Err(e) => {
                tracing::warn!(error = %e, "skipping corrupt agent attestation block");
                continue;
            }
        };
        if att.verify_signature().is_err() {
            continue;
        }
        out.push(att);
    }
    Ok(out)
}

pub fn scan_trusted_agents(
    client: &LocalClient,
    node_trust: &HashMap<[u8; 32], NodeTrust>,
    revoked_agents: &HashSet<[u8; 32]>,
) -> Result<HashSet<[u8; 32]>> {
    let mut out = HashSet::new();
    for bytes in load_blocks_by_label(client, LABEL_AGENT_ATT)? {
        let att: AgentAttestation = match serde_ipld_dagcbor::from_slice(&bytes) {
            Ok(a) => a,
            Err(e) => {
                tracing::warn!(error = %e, "skipping corrupt agent attestation block");
                continue;
            }
        };
        // The attestation must be signed by a node currently in node_trust.
        if !node_trust.contains_key(&att.node_pubkey) {
            continue;
        }
        if att.verify_signature().is_err() {
            continue;
        }
        if revoked_agents.contains(&att.agent_pubkey) {
            continue;
        }
        out.insert(att.agent_pubkey);
    }
    Ok(out)
}

fn load_blocks_by_label(
    client: &LocalClient,
    label: &str,
) -> Result<Vec<Vec<u8>>> {
    let cids = client
        .store()
        .query_by_tag(KIND, label, 0, usize::MAX)
        .map_err(|e| ApiError::Other(format!("query {label}: {e}")))?;
    let mut out = Vec::with_capacity(cids.len());
    for cid in cids {
        if let Ok(Some(bytes)) = client.store().get_block(&cid) {
            out.push(bytes);
        }
    }
    Ok(out)
}

/// Walk the blockstore and reconstruct the trust map keyed by node pubkey.
/// Each entry is `NodeTrust::Attested(_)`. When `admin_pubkey` is `Some`,
/// each attestation's signature is verified against it; failures are
/// logged and the entry is skipped. When `None` (pre-genesis), unverified
/// entries are dropped — only the local self-trust seed counts.
pub fn scan_trusted_nodes(
    client: &LocalClient,
    admin_pubkey: Option<&ed25519_dalek::VerifyingKey>,
) -> Result<HashMap<[u8; 32], NodeTrust>> {
    let mut out = HashMap::new();
    let Some(pk) = admin_pubkey else {
        // Pre-genesis: no trust root, so no attestation can be verified.
        return Ok(out);
    };
    for bytes in load_blocks_by_label(client, LABEL_NODE_ATT)? {
        let att: NodeAttestation = match serde_ipld_dagcbor::from_slice(&bytes) {
            Ok(a) => a,
            Err(e) => {
                tracing::warn!(error = %e, "skipping corrupt node attestation block");
                continue;
            }
        };
        if let Err(e) = att.verify_signature(pk) {
            tracing::warn!(
                error = %e,
                member = %hex::encode(&att.member.0),
                "skipping node attestation: signature does not verify against current admin"
            );
            continue;
        }
        if att.member.0.len() != 32 {
            continue;
        }
        let mut pkbytes = [0u8; 32];
        pkbytes.copy_from_slice(&att.member.0);
        out.insert(pkbytes, NodeTrust::Attested(att));
    }
    Ok(out)
}

/// Walk the blockstore and reconstruct the revoked-agents and revoked-nodes
/// sets, verifying every revocation signature.
///
/// `node_trust` is the trust map produced by [`scan_trusted_nodes`] — used
/// to look up the issuing node's pubkey when verifying `AgentRevocation`
/// signatures (the revocation must be signed by the same node that
/// originally attested the agent).
///
/// `admin_pubkey` (post-genesis only) verifies `NodeRevocation` signatures.
pub fn scan_revocations(
    client: &LocalClient,
    admin_pubkey: Option<&ed25519_dalek::VerifyingKey>,
    node_trust: &HashMap<[u8; 32], NodeTrust>,
) -> Result<(HashSet<[u8; 32]>, HashSet<[u8; 32]>)> {
    let mut agents = HashSet::new();
    let mut nodes = HashSet::new();

    for bytes in load_blocks_by_label(client, LABEL_AGENT_REV)? {
        let rev: AgentRevocation = match serde_ipld_dagcbor::from_slice(&bytes) {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!(error = %e, "skipping corrupt agent revocation block");
                continue;
            }
        };
        // The revocation must be signed by a node that's currently trusted.
        if !node_trust.contains_key(&rev.node_pubkey) {
            tracing::warn!(
                node = %hex::encode(rev.node_pubkey),
                "skipping agent revocation from unknown node"
            );
            continue;
        }
        if let Err(e) = rev.verify_signature() {
            tracing::warn!(
                error = %e,
                agent = %hex::encode(rev.agent_pubkey),
                "skipping agent revocation: bad signature"
            );
            continue;
        }
        agents.insert(rev.agent_pubkey);
    }

    if let Some(admin_pk) = admin_pubkey {
        for bytes in load_blocks_by_label(client, LABEL_NODE_REV)? {
            let rev: NodeRevocation = match serde_ipld_dagcbor::from_slice(&bytes) {
                Ok(r) => r,
                Err(e) => {
                    tracing::warn!(error = %e, "skipping corrupt node revocation block");
                    continue;
                }
            };
            // Embedded admin_pubkey must match current admin AND signature
            // must verify against it.
            if rev.admin_pubkey != admin_pk.to_bytes() {
                tracing::warn!(
                    node = %hex::encode(rev.node_pubkey),
                    "skipping node revocation: admin_pubkey doesn't match current admin"
                );
                continue;
            }
            if let Err(e) = rev.verify_signature() {
                tracing::warn!(
                    error = %e,
                    node = %hex::encode(rev.node_pubkey),
                    "skipping node revocation: bad signature"
                );
                continue;
            }
            nodes.insert(rev.node_pubkey);
        }
    }

    Ok((agents, nodes))
}

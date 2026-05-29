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
    AdminGenesis, AdminKeyAdmission, AdminKeyRetirement, AdminKeyState, AgentAttestation,
    AgentRevocation, GrantRevocation, NodeAttestation, NodeRevocation,
};
use memvault_store::insert::EnvelopeMeta;

const KIND: &str = "sigchain";
const LABEL_ADMIN_GENESIS: &str = "admin_genesis";
const LABEL_NODE_ATT: &str = "node_att";
const LABEL_AGENT_ATT: &str = "agent_att";
const LABEL_AGENT_REV: &str = "agent_rev";
const LABEL_NODE_REV: &str = "node_rev";
const LABEL_ADMIN_ADMISSION: &str = "admin_admission";
const LABEL_ADMIN_RETIREMENT: &str = "admin_retirement";
const LABEL_GRANT_REVOCATION: &str = "grant_revocation";

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

    // Idempotence: if this exact block (same CID) is already in the
    // store, don't re-emit the tag index entries. `insert_envelope`
    // packs the wall_ns into BY_TAG keys, so a duplicate publish
    // creates a NEW tag entry pointing to the SAME block — scans then
    // return the block N times. `init_ui_agent` republishes the UI
    // agent's attestation on every restart; without this gate, the
    // agent would accumulate one duplicate tag entry per boot.
    if matches!(client.store().get_block(&cid_bytes), Ok(Some(_))) {
        return Ok(cid_bytes);
    }

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

/// Persist an `AdminGenesis` block — the cluster's root-of-trust pubkey.
/// Published once at genesis; sync propagates it to peers so they all
/// agree on the admin pubkey without having to be told out-of-band.
pub fn publish_admin_genesis(client: &LocalClient, genesis: &AdminGenesis) -> Result<Vec<u8>> {
    let bytes = serde_ipld_dagcbor::to_vec(genesis)
        .map_err(|e| ApiError::Serialization(e.to_string()))?;
    write_block(client, LABEL_ADMIN_GENESIS, &bytes)
}

/// Load every persisted `AdminGenesis` block scoped to the local cluster,
/// signature-verified. Cluster-id mismatch and bad-signature entries are
/// dropped (logged at warn). The caller typically picks the earliest via
/// [`memvault_auth::pick_earliest_admin_genesis`].
pub fn scan_admin_genesis(client: &LocalClient) -> Result<Vec<AdminGenesis>> {
    let cluster_id = client.cluster_id();
    let mut out = Vec::new();
    for bytes in load_blocks_by_label(client, LABEL_ADMIN_GENESIS)? {
        let g: AdminGenesis = match serde_ipld_dagcbor::from_slice(&bytes) {
            Ok(g) => g,
            Err(e) => {
                tracing::warn!(error = %e, "skipping corrupt admin_genesis block");
                continue;
            }
        };
        if g.cluster_id.0.as_slice() != cluster_id {
            tracing::warn!(
                cluster = %hex::encode(&g.cluster_id.0),
                "skipping admin_genesis block for foreign cluster"
            );
            continue;
        }
        if let Err(e) = g.verify_self_signature() {
            tracing::warn!(error = %e, "skipping admin_genesis with bad self-signature");
            continue;
        }
        out.push(g);
    }
    Ok(out)
}

/// Persist an [`AdminKeyAdmission`] block (multi-admin: a new co-equal
/// admin key admitted by an existing admin).
pub fn publish_admin_admission(
    client: &LocalClient,
    admission: &AdminKeyAdmission,
) -> Result<Vec<u8>> {
    let bytes = serde_ipld_dagcbor::to_vec(admission)
        .map_err(|e| ApiError::Serialization(e.to_string()))?;
    write_block(client, LABEL_ADMIN_ADMISSION, &bytes)
}

/// Persist an [`AdminKeyRetirement`] block.
pub fn publish_admin_retirement(
    client: &LocalClient,
    retirement: &AdminKeyRetirement,
) -> Result<Vec<u8>> {
    let bytes = serde_ipld_dagcbor::to_vec(retirement)
        .map_err(|e| ApiError::Serialization(e.to_string()))?;
    write_block(client, LABEL_ADMIN_RETIREMENT, &bytes)
}

/// Persist a [`GrantRevocation`] as a sigchain block so it propagates to
/// peers and fires the watcher (which applies it to the local revocation
/// index). The caller also records it locally for immediate effect.
pub fn publish_grant_revocation(
    client: &LocalClient,
    revocation: &GrantRevocation,
) -> Result<Vec<u8>> {
    let bytes = serde_ipld_dagcbor::to_vec(revocation)
        .map_err(|e| ApiError::Serialization(e.to_string()))?;
    write_block(client, LABEL_GRANT_REVOCATION, &bytes)
}

/// Apply a single [`GrantRevocation`] to the local revocation index if
/// its issuer is authorised to revoke the target grant. Returns true if
/// recorded. Used by both the bootstrap scan and the live watcher.
///
/// Authority mirrors issuance: the revocation's issuer (embedded
/// `admin_pubkey`) must be a cluster admin, OR the target grant's bucket
/// owner agent / owning node / the owner's attesting node — resolved from
/// the target grant's bucket. A non-authorised revocation is ignored.
fn apply_grant_revocation(client: &LocalClient, bytes: &[u8]) -> bool {
    let Ok(rev) = serde_ipld_dagcbor::from_slice::<GrantRevocation>(bytes) else {
        return false;
    };
    // Self-signature must be authentic for the embedded issuer pubkey.
    if rev.verify_signature().is_err() {
        return false;
    }
    // Resolve the target grant's bucket owners to check revoker authority.
    let grant_cid = rev.grant_cid.to_bytes();
    let (owner_agent_pk, owner_node_pk) = match client.store().get_block(&grant_cid) {
        Ok(Some(raw)) => memvault_store::deserialize_block_as::<memvault_auth::Grant>(&raw)
            .and_then(|g| g.bucket_scopes.first().cloned())
            .and_then(|b| client.bucket_info_sync(&b).ok().flatten())
            .map(|i| (i.owner_agent_pubkey, i.owner_node_pubkey))
            .unwrap_or((None, None)),
        _ => (None, None),
    };
    if !client.grant_issuer_authorized(
        &rev.admin_pubkey,
        rev.revoked_at_ns,
        owner_agent_pk.as_ref(),
        owner_node_pk.as_ref(),
    ) {
        return false;
    }
    client.store().record_revocation(&grant_cid, bytes).is_ok()
}

/// Scan every persisted [`GrantRevocation`] block and apply the
/// admin-signed ones to the local revocation index. Run at bootstrap so
/// revocations issued (or synced) while this node was down take effect.
pub fn scan_grant_revocations(
    client: &LocalClient,
    admin_keys: &[ed25519_dalek::VerifyingKey],
) -> Result<usize> {
    if admin_keys.is_empty() {
        return Ok(0);
    }
    let mut applied = 0usize;
    for bytes in load_blocks_by_label(client, LABEL_GRANT_REVOCATION)? {
        if apply_grant_revocation(client, &bytes) {
            applied += 1;
        }
    }
    Ok(applied)
}

/// Rebuild the cluster's [`AdminKeyState`] from the pinned anchor plus
/// every admission/retirement envelope on the chain, and install it on
/// the client.
///
/// **Security model.** This is the *only* path that mutates the admin-key
/// set, and it always rebuilds from scratch in a deterministic order —
/// never incrementally from block arrival order. That closes the
/// reorder attack where a retirement observed before its target's
/// admission would otherwise leave a retired key valid.
///
/// Ordering: events are sorted by `(timestamp, cid)` where `timestamp` is
/// the envelope's own signed `admitted_at_ns` / `retired_at_ns` (so it's
/// tamper-evident) and `cid` is a deterministic tiebreak. Each event is
/// applied only if its signer was a cluster-valid admin *at that
/// timestamp* per the state built so far — anchored at the pinned admin.
/// A non-admin therefore cannot inject either envelope.
///
/// Invariants enforced while applying:
/// - admission: `admitting_pubkey` valid at `admitted_at_ns`; POP and
///   admitting signature verify; cluster matches.
/// - retirement: `retiring_pubkey` valid at `retired_at_ns`; signature
///   verifies; `retiring_pubkey != retired_pubkey`; and at least one
///   *other* admin key remains valid at `retired_at_ns` (no admin
///   lockout).
pub fn rebuild_admin_key_state(
    client: &LocalClient,
    anchor: &ed25519_dalek::VerifyingKey,
) -> Result<()> {
    let cluster_id = client.cluster_id();
    let mut state = AdminKeyState::new_with_bootstrap(anchor.to_bytes(), 0);

    enum Event {
        Admit(Box<AdminKeyAdmission>),
        Retire(Box<AdminKeyRetirement>),
    }

    let mut events: Vec<(u64, Vec<u8>, Event)> = Vec::new();

    for bytes in load_blocks_by_label(client, LABEL_ADMIN_ADMISSION)? {
        let adm: AdminKeyAdmission = match serde_ipld_dagcbor::from_slice(&bytes) {
            Ok(a) => a,
            Err(e) => {
                tracing::warn!(error = %e, "skipping corrupt admin_admission block");
                continue;
            }
        };
        if adm.cluster_id.0.as_slice() != cluster_id {
            continue;
        }
        // Self-contained checks: admitting signature + incoming POP.
        if adm.verify().is_err() {
            tracing::warn!(
                new = %hex::encode(adm.new_pubkey),
                "skipping admin_admission: bad signature or POP"
            );
            continue;
        }
        let cid = memvault_core::cid_from_bytes(&bytes).to_bytes();
        events.push((adm.admitted_at_ns, cid, Event::Admit(Box::new(adm))));
    }

    for bytes in load_blocks_by_label(client, LABEL_ADMIN_RETIREMENT)? {
        let ret: AdminKeyRetirement = match serde_ipld_dagcbor::from_slice(&bytes) {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!(error = %e, "skipping corrupt admin_retirement block");
                continue;
            }
        };
        if ret.cluster_id.0.as_slice() != cluster_id {
            continue;
        }
        if ret.verify_retiring_signature().is_err() {
            tracing::warn!(
                retired = %hex::encode(ret.retired_pubkey),
                "skipping admin_retirement: bad signature"
            );
            continue;
        }
        let cid = memvault_core::cid_from_bytes(&bytes).to_bytes();
        events.push((ret.retired_at_ns, cid, Event::Retire(Box::new(ret))));
    }

    // Deterministic total order: timestamp, then CID.
    events.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(&b.1)));

    for (ts, tie, ev) in events {
        match ev {
            Event::Admit(adm) => {
                // Signer must be a cluster-valid admin at admission time.
                if !state.is_key_valid_at(&adm.admitting_pubkey, ts) {
                    tracing::warn!(
                        admitting = %hex::encode(adm.admitting_pubkey),
                        "skipping admin_admission: admitting key not a valid admin at admission time"
                    );
                    continue;
                }
                // The incoming admin's POP must not have expired by the time
                // the admission was issued — bounds replay of a captured POP.
                if adm.admitted_at_ns > adm.pop_not_after_ns {
                    tracing::warn!(
                        new = %hex::encode(adm.new_pubkey),
                        "skipping admin_admission: POP expired before admission"
                    );
                    continue;
                }
                // `introduced_by` is an audit-only pointer; the tie value
                // is the admission's CID bytes but reconstructing a typed
                // Cid here would pull in the `cid` crate. Audit tooling can
                // resolve the admission via its tag, so leave it None.
                let _ = &tie;
                state.apply_admission(&adm, None);
            }
            Event::Retire(ret) => {
                if !state.is_key_valid_at(&ret.retiring_pubkey, ts) {
                    tracing::warn!(
                        retiring = %hex::encode(ret.retiring_pubkey),
                        "skipping admin_retirement: retiring key not a valid admin at retirement time"
                    );
                    continue;
                }
                if ret.retiring_pubkey == ret.retired_pubkey {
                    tracing::warn!("skipping admin_retirement: self-retirement is not allowed");
                    continue;
                }
                // No-lockout: at least one OTHER key valid at retirement time.
                let others_valid = state
                    .valid_keys_at(ret.retired_at_ns)
                    .into_iter()
                    .any(|k| k != ret.retired_pubkey);
                if !others_valid {
                    tracing::warn!(
                        retired = %hex::encode(ret.retired_pubkey),
                        "skipping admin_retirement: would leave the cluster with no valid admin"
                    );
                    continue;
                }
                state.apply_retirement(&ret);
            }
        }
    }

    client.set_admin_key_state(state);
    Ok(())
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

/// Outcome of [`verify_envelope_authorship`]. The verifier checks the
/// envelope as a `Signed<T>` block — there is no sidecar path anymore.
/// Pre-migration raw-JSON envelopes have no `signature` field and read
/// as [`AuthorshipStatus::NoSidecar`] (unattributed).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthorshipStatus {
    /// Envelope has no signature — legacy raw-JSON or system/rebuild
    /// write. Treat as unattributed; read paths can decide whether to
    /// enforce.
    NoSidecar,
    /// Node signature verifies AND the agent co-signature verifies
    /// against a currently-trusted agent. `agent_pubkey` identifies
    /// the agent on whose behalf the write was made.
    Valid { agent_pubkey: [u8; 32] },
    /// Node signature verifies but there is no agent co-signature —
    /// this was a pure node write. `node_pubkey` is the signer.
    NodeSigned { node_pubkey: [u8; 32] },
    /// A signature was present but failed to verify (node or agent).
    /// Treat as tampered / fail closed.
    BadSignature,
    /// Signatures verify but the agent_attestation cid is not in the
    /// currently-trusted set — revoked, unknown, or issued by an
    /// untrusted node.
    AgentNotTrusted { agent_pubkey: [u8; 32] },
}

/// Verify the envelope's authorship via its embedded `Signed<T>`
/// signatures.
///
/// Trust inputs are passed in by the caller — the verifier doesn't
/// re-scan the sigchain per call:
/// - `trusted_attestations` — `cid → agent_pubkey` map used to resolve
///   an envelope's inline `agent_attestation` field.
/// - `trusted_node_pubkeys` — currently-trusted node pubkeys
///   (admitted via NodeAttestation, not revoked).
pub fn verify_envelope_authorship(
    client: &LocalClient,
    envelope_cid: &[u8],
    trusted_attestations: &HashMap<Vec<u8>, [u8; 32]>,
    trusted_node_pubkeys: &HashSet<[u8; 32]>,
) -> Result<AuthorshipStatus> {
    let Ok(Some(bytes)) = client.store().get_block(envelope_cid) else {
        return Ok(AuthorshipStatus::NoSidecar);
    };
    let Ok(signed) =
        serde_ipld_dagcbor::from_slice::<memvault_core::Signed<serde_json::Value>>(&bytes)
    else {
        return Ok(AuthorshipStatus::NoSidecar);
    };
    if signed.signature.is_empty() {
        return Ok(AuthorshipStatus::NoSidecar);
    }
    verify_signed_envelope(&signed, trusted_attestations, trusted_node_pubkeys)
}

/// Verify a Signed<T> envelope's node signature plus its optional agent
/// co-signature. Returns the most specific applicable status.
fn verify_signed_envelope(
    signed: &memvault_core::Signed<serde_json::Value>,
    trusted_attestations: &HashMap<Vec<u8>, [u8; 32]>,
    trusted_node_pubkeys: &HashSet<[u8; 32]>,
) -> Result<AuthorshipStatus> {
    // Convert author bytes → ed25519 verifying key.
    let author_bytes: [u8; 32] = match signed.author.0.as_slice().try_into() {
        Ok(b) => b,
        Err(_) => return Ok(AuthorshipStatus::BadSignature),
    };
    let author_vk = match ed25519_dalek::VerifyingKey::from_bytes(&author_bytes) {
        Ok(vk) => vk,
        Err(_) => return Ok(AuthorshipStatus::BadSignature),
    };

    if signed.verify(&author_vk).is_err() {
        return Ok(AuthorshipStatus::BadSignature);
    }

    // Node-only writes (no agent_attestation): require the signing node
    // to be currently trusted.
    let Some(att_cid) = signed.agent_attestation.as_ref() else {
        if trusted_node_pubkeys.contains(&author_bytes) {
            return Ok(AuthorshipStatus::NodeSigned {
                node_pubkey: author_bytes,
            });
        }
        // Genesis / pre-trust writes — treat as unattributed rather
        // than blocking. Read paths can decide whether to enforce.
        return Ok(AuthorshipStatus::NoSidecar);
    };

    // Agent-attributed write: resolve the cid → pubkey, verify the
    // agent co-signature, return Valid.
    let Some(agent_pubkey) = trusted_attestations.get(att_cid).copied() else {
        return Ok(AuthorshipStatus::AgentNotTrusted {
            agent_pubkey: [0u8; 32],
        });
    };
    let agent_vk = match ed25519_dalek::VerifyingKey::from_bytes(&agent_pubkey) {
        Ok(vk) => vk,
        Err(_) => return Ok(AuthorshipStatus::BadSignature),
    };
    if signed.verify_agent(&agent_vk).is_err() {
        return Ok(AuthorshipStatus::BadSignature);
    }
    Ok(AuthorshipStatus::Valid { agent_pubkey })
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
    /// Cached map from AgentAttestation CID → agent pubkey for the
    /// currently-trusted attestations. Lets the Signed<T> verifier
    /// resolve an envelope's inline `agent_attestation` field to the
    /// pubkey needed to verify `agent_signature`, without re-scanning
    /// the sigchain per request.
    pub trusted_attestations: std::sync::Arc<std::sync::RwLock<HashMap<Vec<u8>, [u8; 32]>>>,
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

/// Recompute the cached set of currently-trusted agent pubkeys AND the
/// `cid → pubkey` map for the Signed<T> verifier. Called by the watcher
/// whenever an agent attestation or revocation lands. The two views are
/// refreshed together so verifiers always see a consistent snapshot.
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
    if let Ok(fresh) = scan_trusted_agents(client, &nt, &ra) {
        if let Ok(mut w) = state.trusted_agents.write() {
            *w = fresh;
        }
    }
    if let Ok(fresh) = scan_trusted_attestations(client, &nt, &ra) {
        if let Ok(mut w) = state.trusted_attestations.write() {
            *w = fresh;
        }
    }
}

/// Re-scan the entire sigchain and replace the live trust state. Used to
/// recover when the watcher's broadcast channel lags (events dropped).
fn rescan_into(
    client: &LocalClient,
    admin_pubkey: Option<&ed25519_dalek::VerifyingKey>,
    state: &LiveTrustState,
) {
    // Rebuild the multi-admin key set from the chain first (anchored at
    // the pinned admin), so node attestations signed by any admitted
    // admin verify. Then derive the live key set for the scans below.
    if let Some(anchor) = admin_pubkey {
        let _ = rebuild_admin_key_state(client, anchor);
    }
    let admin_keys = client.admin_verifying_keys();
    if let Ok(nodes) = scan_trusted_nodes(client, &admin_keys) {
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
    if let Ok((agents, nodes)) = scan_revocations(client, &admin_keys, &nt_snapshot) {
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
            // Verify against any known cluster admin key. Pre-genesis:
            // empty set, so peer attestations are ignored — only the local
            // self-trust seed (installed by bootstrap_cluster_trust) counts.
            let admin_keys = client.admin_verifying_keys();
            if admin_keys.is_empty() {
                return;
            }
            if !admin_keys.iter().any(|k| att.verify_signature(k).is_ok()) {
                tracing::warn!("sigchain watcher: NodeAttestation verifies against no known admin");
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
            // The revoker must be the agent's attesting node (not just any
            // trusted node).
            if let Ok(Some(att)) = find_agent_attestation(client, &rev.agent_pubkey) {
                if att.node_pubkey != rev.node_pubkey {
                    tracing::warn!(
                        agent = %hex::encode(rev.agent_pubkey),
                        "sigchain watcher: AgentRevocation revoker is not the attesting node"
                    );
                    return;
                }
            }
            if let Ok(mut w) = state.revoked_agents.write() {
                w.insert(rev.agent_pubkey);
            }
            // Drop from trusted_agents too — fail closed on subsequent reads.
            if let Ok(mut w) = state.trusted_agents.write() {
                w.remove(&rev.agent_pubkey);
            }
            // And drop any attestation cids pointing to the revoked pubkey.
            if let Ok(mut w) = state.trusted_attestations.write() {
                w.retain(|_cid, pk| *pk != rev.agent_pubkey);
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
            // Accept if the embedded admin_pubkey is any known cluster admin
            // and the signature verifies against it.
            let admin_keys = client.admin_verifying_keys();
            let known_admin = admin_keys.iter().any(|k| k.to_bytes() == rev.admin_pubkey);
            if !known_admin {
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
        LABEL_GRANT_REVOCATION => {
            // A bucket-grant revocation landed (local or synced). Apply it
            // to the revocation index if admin-signed; ACL's `is_revoked`
            // check reads that index directly (uncached), so the revoked
            // grant stops conferring access on the next check.
            let _ = apply_grant_revocation(client, &bytes);
        }
        LABEL_ADMIN_ADMISSION | LABEL_ADMIN_RETIREMENT => {
            // Admin-key set changed. SECURITY: never apply incrementally
            // from arrival order — a retirement could be observed before
            // the admission that introduced its target. Always do a full
            // sorted rescan anchored at the pinned admin, then refresh the
            // dependent caches (node trust depends on the admin set).
            if let Some(anchor) = admin_pubkey {
                if rebuild_admin_key_state(client, anchor).is_ok() {
                    rescan_into(client, admin_pubkey, state);
                }
            }
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
/// Look up a single `AgentAttestation` by agent pubkey. Used by the
/// JWT verifier as `lookup_agent`. Returns the first signature-valid
/// attestation whose `agent_pubkey` matches; later attestations for
/// the same key (post-rotation, etc.) are ignored.
pub fn find_agent_attestation(
    client: &LocalClient,
    agent_pubkey: &[u8; 32],
) -> Result<Option<AgentAttestation>> {
    for bytes in load_blocks_by_label(client, LABEL_AGENT_ATT)? {
        let Ok(att) = serde_ipld_dagcbor::from_slice::<AgentAttestation>(&bytes) else {
            continue;
        };
        if att.agent_pubkey != *agent_pubkey {
            continue;
        }
        if att.verify_signature().is_err() {
            continue;
        }
        return Ok(Some(att));
    }
    Ok(None)
}

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

/// Build the `cid → agent_pubkey` map for the currently-trusted set
/// of agent attestations. The Signed<T> verifier resolves an envelope's
/// inline `agent_attestation` cid through this map to get the pubkey
/// needed to verify `agent_signature`.
///
/// Uses the same filter as [`scan_trusted_agents`] (issuer node trusted,
/// signature OK, pubkey not revoked) so the two maps stay consistent.
pub fn scan_trusted_attestations(
    client: &LocalClient,
    node_trust: &HashMap<[u8; 32], NodeTrust>,
    revoked_agents: &HashSet<[u8; 32]>,
) -> Result<HashMap<Vec<u8>, [u8; 32]>> {
    let mut out = HashMap::new();
    for bytes in load_blocks_by_label(client, LABEL_AGENT_ATT)? {
        let att: AgentAttestation = match serde_ipld_dagcbor::from_slice(&bytes) {
            Ok(a) => a,
            Err(e) => {
                tracing::warn!(error = %e, "skipping corrupt agent attestation block");
                continue;
            }
        };
        if !node_trust.contains_key(&att.node_pubkey) {
            continue;
        }
        if att.verify_signature().is_err() {
            continue;
        }
        if revoked_agents.contains(&att.agent_pubkey) {
            continue;
        }
        let cid = memvault_core::cid_from_bytes(&bytes).to_bytes();
        out.insert(cid, att.agent_pubkey);
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
    admin_keys: &[ed25519_dalek::VerifyingKey],
) -> Result<HashMap<[u8; 32], NodeTrust>> {
    let mut out = HashMap::new();
    if admin_keys.is_empty() {
        // Pre-genesis: no trust root, so no attestation can be verified.
        return Ok(out);
    }
    for bytes in load_blocks_by_label(client, LABEL_NODE_ATT)? {
        let att: NodeAttestation = match serde_ipld_dagcbor::from_slice(&bytes) {
            Ok(a) => a,
            Err(e) => {
                tracing::warn!(error = %e, "skipping corrupt node attestation block");
                continue;
            }
        };
        // Multi-admin: accept if ANY known cluster admin key verifies it.
        if !admin_keys.iter().any(|k| att.verify_signature(k).is_ok()) {
            tracing::warn!(
                member = %hex::encode(&att.member.0),
                "skipping node attestation: signature does not verify against any known admin"
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
/// `admin_keys` (post-genesis only) verifies `NodeRevocation` signatures —
/// a revocation is accepted if its embedded `admin_pubkey` is one of the
/// cluster's known admin keys and the signature verifies against it.
pub fn scan_revocations(
    client: &LocalClient,
    admin_keys: &[ed25519_dalek::VerifyingKey],
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
        // The revoker must be the node that attested the agent — a trusted
        // node cannot revoke another node's agents. If the agent has an
        // on-chain attestation, require rev.node_pubkey to match it.
        if let Ok(Some(att)) = find_agent_attestation(client, &rev.agent_pubkey) {
            if att.node_pubkey != rev.node_pubkey {
                tracing::warn!(
                    agent = %hex::encode(rev.agent_pubkey),
                    revoker = %hex::encode(rev.node_pubkey),
                    attester = %hex::encode(att.node_pubkey),
                    "skipping agent revocation: revoker is not the attesting node"
                );
                continue;
            }
        }
        agents.insert(rev.agent_pubkey);
    }

    if !admin_keys.is_empty() {
        let admin_key_bytes: HashSet<[u8; 32]> =
            admin_keys.iter().map(|k| k.to_bytes()).collect();
        for bytes in load_blocks_by_label(client, LABEL_NODE_REV)? {
            let rev: NodeRevocation = match serde_ipld_dagcbor::from_slice(&bytes) {
                Ok(r) => r,
                Err(e) => {
                    tracing::warn!(error = %e, "skipping corrupt node revocation block");
                    continue;
                }
            };
            // Embedded admin_pubkey must be one of the cluster's known
            // admin keys AND the signature must verify against it.
            if !admin_key_bytes.contains(&rev.admin_pubkey) {
                tracing::warn!(
                    node = %hex::encode(rev.node_pubkey),
                    "skipping node revocation: admin_pubkey is not a known cluster admin"
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

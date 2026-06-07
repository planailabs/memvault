//! Cluster trust bootstrap.
//!
//! Brings a [`LocalClient`] from "freshly opened" to "ready to verify
//! envelope authorship and serve cluster operations." Composes the
//! per-domain helpers — [`crate::sigchain`], [`crate::LocalClient`]'s
//! signing-key accessors — into a single call.
//!
//! Domain-agnostic: HTTP/UI hookup lives elsewhere (e.g.
//! `memvault_web::init_ui_agent`). Any daemon that needs envelope-
//! authorship enforcement calls this regardless of whether it serves the
//! web UI.
//!
//! Two trust modes:
//! - **Post-genesis** (admin signing key present): self-attest the local
//!   node, persist the attestation, return `Some(admin_pubkey)`.
//! - **Pre-genesis** (no admin key yet): insert the local node as
//!   `NodeTrust::PreGenesis` in memory; return `None`. The watcher's
//!   peer-attestation handler refuses to admit foreign attestations in
//!   this mode (no trust root to verify them against).

use std::sync::{Arc, RwLock};

use ed25519_dalek::VerifyingKey;

use crate::LocalClient;
use crate::error::{ApiError, Result};
use crate::sigchain::{self, LiveTrustState};

use memvault_auth::jwt::NodeTrust;
use memvault_auth::{AttestationOrigin, NodeAttestation};

/// Output of [`bootstrap_cluster_trust`].
pub struct ClusterTrustBootstrap {
    /// Cluster admin's verifying key. `None` pre-genesis.
    pub admin_pubkey: Option<VerifyingKey>,
    /// Live trust handles — also installed on the client via
    /// [`LocalClient::set_trust_state`] so [`LocalClient::verify_envelope_authorship`]
    /// shares them with anything else holding `LiveTrustState`.
    pub trust_state: LiveTrustState,
}

/// Bootstrap cluster trust for a `LocalClient`.
///
/// 1. Install the store→event-bus sigchain notifier (so the watcher and
///    other subscribers see incoming blocks from both local writes and
///    RBSR sync).
/// 2. Self-attest the local node if an admin key is configured;
///    persist the attestation as a sigchain block.
/// 3. Scan persisted [`NodeAttestation`]s and overlay the local node.
/// 4. Scan persisted revocations (agent + node).
/// 5. Compute the initial `trusted_agents` cache.
/// 6. Assemble [`LiveTrustState`] and publish it to the client.
///
/// The caller is responsible for spawning
/// [`crate::sigchain::spawn_sigchain_watcher`] from inside an async
/// context — this function stays sync.
///
/// Requires `client.node_signing_key()` to be set (see
/// [`LocalClient::set_node_signing_key`]).
pub fn bootstrap_cluster_trust(client: &Arc<LocalClient>) -> Result<ClusterTrustBootstrap> {
    let node_signing_key = client
        .node_signing_key()
        .ok_or_else(|| {
            ApiError::Other(
                "node signing key not set on client; call set_node_signing_key first".into(),
            )
        })?
        .clone();

    // Bridge store→bus so the watcher sees blocks arriving from both
    // local writes and RBSR sync without the sync layer caring about
    // events.
    client.install_sigchain_notifier();

    let cluster_bytes = client.cluster_id();
    let mut cluster_arr = [0u8; 32];
    if cluster_bytes.len() == 32 {
        cluster_arr.copy_from_slice(cluster_bytes);
    }
    let cluster_id = memvault_core::ClusterId(cluster_arr);
    let node_pubkey_bytes = node_signing_key.verifying_key().to_bytes();

    // (Step 2a) Source of truth for `admin_pubkey` is the
    // `pinned_admin_genesis` set on the client by the daemon at startup
    // (read from `<data_dir>/identity/cluster_admin_genesis.cbor`). The
    // pin is established TOFU-style: at genesis (we created the
    // cluster) or at join time (the join token carries the genesis
    // block, signed by admin, that the join command pins on first
    // contact). We deliberately do NOT consult the sigchain for trust
    // bootstrap — a peer accepting an AdminGenesis from sync would let
    // any block-injecting attacker forge cluster trust.
    let pinned_admin_genesis = client.pinned_admin_genesis().cloned();
    let pinned_admin_pubkey = pinned_admin_genesis
        .as_ref()
        .and_then(|g| ed25519_dalek::VerifyingKey::from_bytes(&g.admin_pubkey).ok());

    // (Step 2b) If we hold the admin signing key, the pin file must
    // exist (written at genesis) and must match. Publish a fresh
    // NodeAttestation; the AdminGenesis block is published once at
    // genesis (in the `memctl genesis` command) and never re-emitted.
    let (admin_pubkey, node_trust_entry) = if let Some(admin_sk) = client.admin_signing_key() {
        let admin_pubkey = admin_sk.verifying_key();

        // Sanity: pin must agree with the key we hold. If not, either we
        // were re-genesis'd over a populated data dir, or someone
        // tampered with the pin — refuse to boot rather than silently
        // diverge.
        if let Some(existing) = pinned_admin_pubkey.as_ref() {
            if existing.to_bytes() != admin_pubkey.to_bytes() {
                return Err(ApiError::Other(format!(
                    "local admin signing key disagrees with pinned admin pubkey \
                     (pinned: {}, local key implies: {}); refusing to bootstrap. \
                     Either restore the matching admin.key or wipe the data_dir.",
                    hex::encode(existing.to_bytes()),
                    hex::encode(admin_pubkey.to_bytes()),
                )));
            }
        }
        // If the admin's chain doesn't have an AdminGenesis block yet,
        // publish one (informational; not used for trust bootstrap, but
        // useful for audit tools that scan the chain). The pin file is
        // written by `memctl genesis` — bootstrap does no file I/O.
        if sigchain::scan_admin_genesis(client)?.is_empty() {
            let genesis = memvault_auth::sign_admin_genesis(
                &admin_sk,
                cluster_id.clone(),
                memvault_core::wall_ns(),
            )
            .map_err(|e| ApiError::Other(format!("sign admin_genesis: {e}")))?;
            sigchain::publish_admin_genesis(client, &genesis)?;
        }

        let mut node_att = NodeAttestation {
            cluster_id,
            member: memvault_core::PeerId(node_pubkey_bytes.to_vec()),
            not_after_ns: u64::MAX,
            issued_via: AttestationOrigin::Direct,
            signature: [0u8; 64],
        };
        let bytes = node_att
            .signing_bytes()
            .map_err(|e| ApiError::Other(format!("node attestation signing bytes: {e}")))?;
        node_att.signature = {
            use ed25519_dalek::Signer;
            admin_sk.sign(&bytes).to_bytes()
        };
        sigchain::publish_node_attestation(client, &node_att)?;
        (Some(admin_pubkey), NodeTrust::Attested(node_att))
    } else if let Some(pinned_pk) = pinned_admin_pubkey {
        // Peer node: admin pubkey pinned at join time, no local signing
        // key. Register ourselves as PreGenesis locally — admin attests
        // us by publishing a NodeAttestation for our pubkey via the
        // /join/1.0 flow; scan_trusted_nodes picks it up below.
        (Some(pinned_pk), NodeTrust::PreGenesis)
    } else {
        // Truly pre-genesis: no admin key locally, no pinned admin.
        (None, NodeTrust::PreGenesis)
    };

    // (Step 3) Persisted attestations + local overlay.
    //
    // On the admin path, `node_trust_entry` is a freshly-signed
    // attestation we just published — always overlay.
    //
    // On the peer path it's `NodeTrust::PreGenesis`, which is only a
    // fallback for "we have no real attestation yet." If `scan_trusted_nodes`
    // already loaded a real `NodeTrust::Attested(_)` for our pubkey
    // (i.e. admin previously attested us and it synced over), do NOT
    // clobber it.
    // Seed the admin-key state from the pinned anchor, then rebuild it
    // from any admission/retirement envelopes on the chain so the full
    // multi-admin key set is available for verification. (The rescan is
    // a no-op beyond the anchor until admin envelopes exist.)
    if let Some(anchor) = admin_pubkey.as_ref() {
        client.seed_admin_anchor(anchor.to_bytes());
        sigchain::rebuild_admin_key_state(client, anchor)?;
    }
    let admin_keys = client.admin_verifying_keys();

    let mut node_trust_map = sigchain::scan_trusted_nodes(client, &admin_keys)?;
    let local_is_pre_genesis = matches!(node_trust_entry, NodeTrust::PreGenesis);
    let scanned_has_local = node_trust_map.contains_key(&node_pubkey_bytes);
    if !(local_is_pre_genesis && scanned_has_local) {
        node_trust_map.insert(node_pubkey_bytes, node_trust_entry);
    }

    // (Step 4) Revocations.
    let (revoked_agents_set, revoked_nodes_set) =
        sigchain::scan_revocations(client, &admin_keys, &node_trust_map)?;
    // Apply any admin-signed bucket-grant revocations that landed (locally
    // or via sync) so revoked grants don't keep conferring access after a
    // restart.
    if let Err(e) = sigchain::scan_grant_revocations(client, &admin_keys) {
        tracing::warn!(error = %e, "scan grant revocations");
    }

    let node_trust = Arc::new(RwLock::new(node_trust_map));
    let revoked_agents = Arc::new(RwLock::new(revoked_agents_set));
    let revoked_nodes = Arc::new(RwLock::new(revoked_nodes_set));

    // (Step 5) Initial trusted-agents cache.
    let trusted_agents_set = {
        let nt = node_trust.read().map(|m| m.clone()).unwrap_or_default();
        let ra = revoked_agents.read().map(|s| s.clone()).unwrap_or_default();
        sigchain::scan_trusted_agents(client, &nt, &ra)?
    };
    let trusted_agents = Arc::new(RwLock::new(trusted_agents_set));

    let trusted_attestations_map = {
        let nt = node_trust.read().map(|m| m.clone()).unwrap_or_default();
        let ra = revoked_agents.read().map(|s| s.clone()).unwrap_or_default();
        sigchain::scan_trusted_attestations(client, &nt, &ra)?
    };
    let trusted_attestations = Arc::new(RwLock::new(trusted_attestations_map));

    // (Step 6) Publish to the client and return.
    let trust_state = LiveTrustState {
        node_trust,
        revoked_agents,
        revoked_nodes,
        trusted_agents,
        trusted_attestations,
    };
    client.set_trust_state(trust_state.clone());

    Ok(ClusterTrustBootstrap {
        admin_pubkey,
        trust_state,
    })
}

/// Background tasks + trust handles owned by a long-running memvault host.
/// Returned by [`start_host_services`]. Hold it for the host's lifetime: the
/// `JoinHandle`s keep the sigchain watcher and index flusher running (tokio
/// detaches a task when its handle drops, so dropping these does not stop the
/// tasks — but holding them documents ownership and allows an explicit abort).
pub struct HostServices {
    /// Cluster trust bootstrap result (`admin_pubkey` + live trust state),
    /// used to build the web `AppState`.
    pub trust: ClusterTrustBootstrap,
    /// Sigchain watcher task — applies attestations/revocations arriving via
    /// local writes and RBSR sync.
    pub sigchain_watcher: tokio::task::JoinHandle<()>,
    /// Periodic Tantivy index flusher — commits deferred (batched) index
    /// writes within ~1s so a long-running host stays durable + searchable.
    pub index_flusher: tokio::task::JoinHandle<()>,
}

/// Wire the services every long-running memvault host needs (the daemon, the
/// `memvault-web` server, and `memctl daemon` all share this): bootstrap
/// cluster trust + install the store→index notifier, spawn the sigchain
/// watcher, enable deferred (batched) Tantivy commits, and start the periodic
/// index flusher.
///
/// Must be called from within a tokio runtime (it spawns tasks), after the
/// node signing key is installed (a precondition of [`bootstrap_cluster_trust`]).
/// Short-lived CLI invocations do **not** call this — they keep inline commits
/// so a write-then-exit process is durable without a flusher.
pub fn start_host_services(client: &Arc<LocalClient>) -> Result<HostServices> {
    let trust = bootstrap_cluster_trust(client)?;
    // Trust is now settled from the local sigchain. Sweep out orphaned agent
    // attestations — ones signed by a node that was never attested into the
    // cluster (e.g. an ephemeral instance that gossiped its `_ui` Admin agent
    // in). They're inert (ACL/JWT both reject untrusted attesting nodes), so
    // this only clears cruft; a legit not-yet-synced agent self-heals via RBSR.
    match client.prune_orphaned_agent_attestations() {
        Ok(0) => {}
        Ok(n) => tracing::info!(pruned = n, "swept orphaned agent attestations at startup"),
        Err(e) => tracing::warn!("orphan-attestation sweep failed: {e}"),
    }
    let sigchain_watcher = sigchain::spawn_sigchain_watcher(
        Arc::clone(client),
        trust.admin_pubkey,
        trust.trust_state.clone(),
    );
    // Long-running host: batch Tantivy commits (defer + periodic flush) instead
    // of committing per write; the flusher and read/drop paths land the tail.
    client.set_defer_index_commits(true);
    let index_flusher = client.start_index_flusher();
    Ok(HostServices {
        trust,
        sigchain_watcher,
        index_flusher,
    })
}

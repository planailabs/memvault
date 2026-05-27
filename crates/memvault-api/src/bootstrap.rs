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
use memvault_auth::{AttestationOrigin, NodeAttestation, Role};

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

    // (Step 2) Self-attestation, gated on whether we hold the admin key.
    let (admin_pubkey, node_trust_entry) = match client.admin_signing_key().cloned() {
        Some(admin_sk) => {
            let admin_pubkey = admin_sk.verifying_key();
            let mut node_att = NodeAttestation {
                cluster_id,
                member: memvault_core::PeerId(node_pubkey_bytes.to_vec()),
                role: Role::AgentHost,
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
        }
        None => (None, NodeTrust::PreGenesis),
    };

    // (Step 3) Persisted attestations + local overlay.
    let mut node_trust_map = sigchain::scan_trusted_nodes(client, admin_pubkey.as_ref())?;
    node_trust_map.insert(node_pubkey_bytes, node_trust_entry);

    // (Step 4) Revocations.
    let (revoked_agents_set, revoked_nodes_set) =
        sigchain::scan_revocations(client, admin_pubkey.as_ref(), &node_trust_map)?;

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

    // (Step 6) Publish to the client and return.
    let trust_state = LiveTrustState {
        node_trust,
        revoked_agents,
        revoked_nodes,
        trusted_agents,
    };
    client.set_trust_state(trust_state.clone());

    Ok(ClusterTrustBootstrap {
        admin_pubkey,
        trust_state,
    })
}

//! `memvault-web` — Axum-based REST API and web UI for the memvault daemon.
//!
//! Uses `plan-ai-design` for shared UI components and styling.
//!
//! Server-side modules (`api`, `components`, `error`, router builders) are
//! gated behind the `server` feature so the crate compiles cleanly as a
//! WASM client when built with `--features web`.

#[cfg(feature = "server")]
pub mod api;
#[cfg(feature = "server")]
pub mod components;
#[cfg(feature = "server")]
pub mod error;

#[cfg(feature = "webui")]
pub mod ui;

/// Re-export the shared design system for consumers.
pub use plan_ai_design as design;

/// Client-side (WASM) entry point — launches the dioxus web app with hydration.
#[cfg(feature = "webui")]
pub fn launch_client() {
    dioxus::launch(ui::app::App);
}

// ── Server-only exports ────────────────────────────────────────────────

#[cfg(feature = "server")]
mod server_router {
    use std::sync::Arc;

    use axum::Router;
    use ed25519_dalek::VerifyingKey;
    use memvault_api::{EventBus, MemvaultClient};

    /// Application state shared across all handlers.
    ///
    /// Auth uses the admin → node → agent JWT chain (see `memvault_auth::jwt`).
    /// `node_attestations` maps a node's pubkey to its admin-signed
    /// `NodeAttestation`; the verifier looks up the JWT's claimed issuing
    /// node here and confirms it against `admin_pubkey`.
    ///
    /// For now this holds just the local node; phase 5 of the sig-chain sync
    /// will populate it with attestations from other peers as they're received.
    pub struct AppState {
        pub client: Arc<dyn MemvaultClient>,
        pub event_bus: Arc<EventBus>,
        /// Cluster admin's verifying key. `None` pre-genesis (no admin key
        /// exists yet) — `node_trust` entries must then be
        /// [`memvault_auth::jwt::NodeTrust::PreGenesis`] for them to verify.
        pub admin_pubkey: Option<VerifyingKey>,
        /// Trusted-node lookup table keyed by node pubkey. Wrapped in an
        /// `RwLock` so the sigchain watcher (see [`spawn_sigchain_watcher`])
        /// can insert new entries when peers announce `NodeAttestation`s
        /// over RBSR sync without restarting the daemon.
        pub node_trust: Arc<
            std::sync::RwLock<
                std::collections::HashMap<[u8; 32], memvault_auth::jwt::NodeTrust>,
            >,
        >,
        /// Revoked agent pubkeys. Populated from
        /// [`memvault_auth::AgentRevocation`] blocks in the sig-chain (phase 5
        /// sync) and on local revoke calls. JWTs from any of these agents
        /// are rejected unconditionally.
        pub revoked_agents: Arc<std::sync::RwLock<std::collections::HashSet<[u8; 32]>>>,
        /// Revoked node pubkeys. Populated from
        /// [`memvault_auth::NodeRevocation`] blocks. When a node is revoked,
        /// the JWT verifier's lookup table filters it out — transitively
        /// invalidating every agent that node attested.
        pub revoked_nodes: Arc<std::sync::RwLock<std::collections::HashSet<[u8; 32]>>>,
        /// Operational metrics.
        pub metrics: Arc<memvault_api::metrics::Metrics>,
    }

    /// Bootstrap result from [`init_web_auth`].
    pub struct WebAuthBootstrap {
        /// `None` pre-genesis. `Some` once the daemon holds an admin key.
        pub admin_pubkey: Option<ed25519_dalek::VerifyingKey>,
        /// Live trust state — shared handles to node_trust, revoked_*, and
        /// trusted_agents. The same `Arc`s are wired into `AppState` and
        /// passed to [`memvault_api::sigchain::spawn_sigchain_watcher`] so
        /// the watcher mutates exactly what the verifier reads.
        pub trust_state: memvault_api::sigchain::LiveTrustState,
    }

    /// Bootstrap per-agent web auth.
    ///
    /// Two paths:
    ///
    /// **Post-genesis** (daemon holds the admin signing key):
    /// 1. Derive admin pubkey.
    /// 2. Self-attest the local node (admin signs `NodeAttestation`).
    ///    Insert as `NodeTrust::Attested(_)`.
    /// 3. Generate `_ui` agent signed by the node key.
    ///
    /// **Pre-genesis** (no admin key yet):
    /// 1. `admin_pubkey = None`.
    /// 2. Insert the local node as `NodeTrust::PreGenesis` — no attestation
    ///    persisted; the entry is in-memory only.
    /// 3. Generate `_ui` agent signed by the node key.
    ///
    /// In the single-node admin case the node signing key equals the admin
    /// signing key; the chain still verifies end-to-end.
    pub fn init_web_auth(
        client: &Arc<memvault_api::LocalClient>,
        data_dir: &std::path::Path,
    ) -> Result<WebAuthBootstrap, Box<dyn std::error::Error + Send + Sync>> {
        use memvault_auth::jwt::NodeTrust;
        use memvault_auth::{AttestationOrigin, NodeAttestation, Role};

        let node_signing_key = client
            .node_signing_key()
            .ok_or("node signing key not set on client; call set_node_signing_key first")?
            .clone();

        // Bridge the store's index notifier to the event bus so the sigchain
        // watcher (spawned below) sees blocks arriving from both local writes
        // and RBSR sync without the sync layer knowing about events.
        client.install_sigchain_notifier();

        let cluster_bytes = client.cluster_id();
        let mut cluster_arr = [0u8; 32];
        if cluster_bytes.len() == 32 {
            cluster_arr.copy_from_slice(cluster_bytes);
        }
        let cluster_id = memvault_core::ClusterId(cluster_arr);

        let node_pubkey_bytes = node_signing_key.verifying_key().to_bytes();

        // Decide trust mode based on whether an admin key is configured.
        let (admin_pubkey, node_trust_entry) = match client.admin_signing_key().cloned() {
            Some(admin_sk) => {
                let admin_pubkey = admin_sk.verifying_key();
                let mut node_att = NodeAttestation {
                    cluster_id: cluster_id.clone(),
                    member: memvault_core::PeerId(node_pubkey_bytes.to_vec()),
                    role: Role::AgentHost,
                    not_after_ns: u64::MAX,
                    issued_via: AttestationOrigin::Direct,
                    signature: [0u8; 64],
                };
                let bytes = node_att
                    .signing_bytes()
                    .map_err(|e| format!("node attestation signing bytes: {e}"))?;
                node_att.signature = {
                    use ed25519_dalek::Signer;
                    admin_sk.sign(&bytes).to_bytes()
                };
                // Persist the attestation as a sigchain block so it survives
                // restart and propagates via RBSR sync (phase 5).
                let _ = memvault_api::sigchain::publish_node_attestation(client, &node_att)
                    .map_err(|e| format!("publish node attestation: {e}"))?;
                (Some(admin_pubkey), NodeTrust::Attested(node_att))
            }
            None => (None, NodeTrust::PreGenesis),
        };

        // Start from any node attestations already in the sigchain (received
        // via RBSR sync from peers in previous runs), then overlay the local
        // node so the daemon's freshly-issued JWTs always verify. Persisted
        // attestations are verified against the current admin pubkey at
        // load — any that don't chain to the current admin are dropped.
        let mut node_trust_map =
            memvault_api::sigchain::scan_trusted_nodes(client, admin_pubkey.as_ref())
                .map_err(|e| format!("scan trusted nodes: {e}"))?;
        node_trust_map.insert(node_pubkey_bytes, node_trust_entry);

        // Hydrate revocation sets — also signature-verified.
        let (revoked_agents_set, revoked_nodes_set) = memvault_api::sigchain::scan_revocations(
            client,
            admin_pubkey.as_ref(),
            &node_trust_map,
        )
        .map_err(|e| format!("scan revocations: {e}"))?;

        let node_trust = Arc::new(std::sync::RwLock::new(node_trust_map));

        // Generate the built-in UI agent, signed by the node's key.
        let ui_identity_dir = data_dir.join("identity").join("ui_agent");
        let _ = std::fs::remove_dir_all(&ui_identity_dir);
        let ui_identity = memvault_api::agent_identity::AgentIdentity::generate_local(
            &ui_identity_dir,
            "_ui",
            &cluster_id,
            &node_signing_key,
            memvault_auth::Role::AgentHost,
            365 * 24 * 60 * 60 * 1_000_000_000,
        )?;

        // Publish the agent attestation to the sigchain so peers can verify
        // envelope authorship blocks from this agent after RBSR sync.
        memvault_api::sigchain::publish_agent_attestation(client, &ui_identity.attestation)
            .map_err(|e| format!("publish ui agent attestation: {e}"))?;

        super::ui::state::set_ui_agent_identity(Arc::new(ui_identity));

        let revoked_agents = Arc::new(std::sync::RwLock::new(revoked_agents_set));
        let revoked_nodes = Arc::new(std::sync::RwLock::new(revoked_nodes_set));

        // Initial trusted-agents cache: scan AgentAttestations attested by a
        // currently-trusted node and not in revoked_agents.
        let trusted_agents_set = {
            let nt = node_trust
                .read()
                .map(|m| m.clone())
                .unwrap_or_default();
            let ra = revoked_agents
                .read()
                .map(|s| s.clone())
                .unwrap_or_default();
            memvault_api::sigchain::scan_trusted_agents(client, &nt, &ra)
                .map_err(|e| format!("scan trusted agents: {e}"))?
        };
        let trusted_agents = Arc::new(std::sync::RwLock::new(trusted_agents_set));

        // Assemble the live trust state and publish it to the client so
        // read-path enforcement (LocalClient::verify_envelope_authorship)
        // sees the same handles. The caller is responsible for spawning
        // `memvault_api::sigchain::spawn_sigchain_watcher` from inside an
        // async context — this keeps init_web_auth itself sync and free of
        // tokio-runtime assumptions.
        let trust_state = memvault_api::sigchain::LiveTrustState {
            node_trust,
            revoked_agents,
            revoked_nodes,
            trusted_agents,
        };
        client.set_trust_state(trust_state.clone());

        Ok(WebAuthBootstrap {
            admin_pubkey,
            trust_state,
        })
    }

    /// Build the API-only memvault router (no web UI).
    pub fn build_router(state: Arc<AppState>) -> Router {
        Router::new().nest("/api/v1", super::api::routes(state))
    }

    /// Serve the memvault fullstack app using dioxus::serve().
    ///
    /// This handles port negotiation with dx's dev server automatically.
    /// Call this instead of manual axum::serve when running under dx serve.
    /// This function does NOT return — it runs the server forever.
    pub fn serve_app(state: Arc<AppState>) {
        use dioxus::server::{DioxusRouterExt, ServeConfig};

        dioxus::serve(move || {
            let state = Arc::clone(&state);
            async move {
                let router = axum::Router::new()
                    .serve_dioxus_application(ServeConfig::new(), super::ui::app::App)
                    .nest("/api/v1", super::api::routes(state));
                Ok(router)
            }
        });
    }

    /// Build a fullstack router: API + Dioxus SSR + static assets.
    ///
    /// Uses `serve_dioxus_application` (the standard dioxus fullstack pattern)
    /// which handles SSR, hydration data injection, and static file serving
    /// from `DIOXUS_PUBLIC_PATH`. The caller must ensure that directory contains
    /// the WASM client assets before calling this.
    pub fn build_fullstack_router(state: Arc<AppState>) -> Router<()> {
        use dioxus::server::{DioxusRouterExt, ServeConfig};

        // API routes
        let api = Router::new().nest("/api/v1", super::api::routes(state));

        // Dioxus fullstack: server fns + SSR + static assets (same as main.rs)
        let dioxus =
            Router::new().serve_dioxus_application(ServeConfig::new(), super::ui::app::App);

        api.merge(dioxus)
    }
}

#[cfg(feature = "server")]
pub use server_router::*;

#[cfg(test)]
mod tests;

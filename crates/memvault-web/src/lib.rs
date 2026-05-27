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
    /// `MembershipAttestation`; the verifier looks up the JWT's claimed issuing
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
        /// Trusted-node lookup table keyed by node pubkey.
        pub node_trust:
            std::collections::HashMap<[u8; 32], memvault_auth::jwt::NodeTrust>,
        /// Operational metrics.
        pub metrics: Arc<memvault_api::metrics::Metrics>,
    }

    /// Bootstrap per-agent web auth: derive the cluster admin pubkey from the
    /// client (which must hold the admin signing key) and register a fresh
    /// "_ui" agent identity that the web UI uses for its session JWTs.
    ///
    /// Call once before constructing [`AppState`]; the returned pubkey is the
    /// root of trust for JWT verification on every API request.
    /// Load (or generate + persist) a per-daemon node signing key at
    /// `<data_dir>/identity/node.key`. Used by dev / non-libp2p callers
    /// (memctl, memvault-web standalone main). The full daemon reuses its
    /// libp2p host key instead (design A-1).
    pub fn load_or_generate_node_key(
        data_dir: &std::path::Path,
    ) -> std::io::Result<ed25519_dalek::SigningKey> {
        let path = data_dir.join("identity").join("node.key");
        if let Ok(bytes) = std::fs::read(&path) {
            if bytes.len() >= 32 {
                let mut seed = [0u8; 32];
                seed.copy_from_slice(&bytes[..32]);
                return Ok(ed25519_dalek::SigningKey::from_bytes(&seed));
            }
        }
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let mut seed = [0u8; 32];
        rand::Rng::fill(&mut rand::thread_rng(), &mut seed);
        std::fs::write(&path, &seed)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
        }
        Ok(ed25519_dalek::SigningKey::from_bytes(&seed))
    }

    /// Bootstrap result from [`init_web_auth`].
    pub struct WebAuthBootstrap {
        /// `None` pre-genesis. `Some` once the daemon holds an admin key.
        pub admin_pubkey: Option<ed25519_dalek::VerifyingKey>,
        /// Trusted-node lookup. Always populated with at least the local node:
        /// `NodeTrust::Attested(_)` post-genesis, `NodeTrust::PreGenesis`
        /// before.
        pub node_trust: std::collections::HashMap<[u8; 32], memvault_auth::jwt::NodeTrust>,
    }

    /// Bootstrap per-agent web auth.
    ///
    /// Two paths:
    ///
    /// **Post-genesis** (daemon holds the admin signing key):
    /// 1. Derive admin pubkey.
    /// 2. Self-attest the local node (admin signs `MembershipAttestation`).
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
        client: &memvault_api::LocalClient,
        data_dir: &std::path::Path,
        node_signing_key: ed25519_dalek::SigningKey,
    ) -> Result<WebAuthBootstrap, Box<dyn std::error::Error + Send + Sync>> {
        use memvault_auth::jwt::NodeTrust;
        use memvault_auth::{AttestationOrigin, MembershipAttestation, Role};

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
                // Post-genesis: admin signs a MembershipAttestation for the
                // node (the node's pubkey is distinct from admin's unless the
                // single-key dev convenience is in play). Insert as
                // Attested(_) so the chain verifies fully.
                let admin_pubkey = admin_sk.verifying_key();
                let mut node_att = MembershipAttestation {
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
                (Some(admin_pubkey), NodeTrust::Attested(node_att))
            }
            None => {
                // Pre-genesis: no admin key. The node signing key still
                // signs the `_ui` agent attestation; trust is local-only.
                (None, NodeTrust::PreGenesis)
            }
        };

        let mut node_trust = std::collections::HashMap::new();
        node_trust.insert(node_pubkey_bytes, node_trust_entry);

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
        super::ui::state::set_ui_agent_identity(Arc::new(ui_identity));

        Ok(WebAuthBootstrap {
            admin_pubkey,
            node_trust,
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

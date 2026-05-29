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
        /// Optional injectable lookup for `AgentAttestation` by agent
        /// pubkey. Production wires this to the sigchain scan via
        /// [`memvault_api::sigchain::find_agent_attestation`]; tests
        /// install a stub so they don't need a full `LocalClient` set up.
        /// `None` falls back to the global `LOCAL_CLIENT` lookup.
        #[allow(clippy::type_complexity)]
        pub agent_attestation_lookup: Option<
            Arc<
                dyn Fn(&[u8; 32]) -> Option<memvault_auth::AgentAttestation>
                    + Send
                    + Sync,
            >,
        >,
    }

    /// Load (or generate) the built-in `_ui` agent identity used by the
    /// web UI to issue per-session JWTs, and publish its attestation to
    /// the sigchain.
    ///
    /// The identity is persisted under `<data_dir>/identity/ui_agent/`
    /// across restarts: the keypair, the node-signed `AgentAttestation`,
    /// and metadata. On startup we reuse the saved identity iff:
    ///   1. The attestation's `node_pubkey` matches the daemon's current
    ///      node signing key (no key rotation), AND
    ///   2. The attestation hasn't expired.
    /// Otherwise we rotate. This keeps the agent stable across restarts
    /// (so existing JWTs and envelope-authorship blocks remain valid)
    /// without leaving an orphaned identity behind after a node-key
    /// rotation.
    ///
    /// **Prerequisite**: cluster trust must already be bootstrapped on the
    /// client via [`memvault_api::bootstrap::bootstrap_cluster_trust`].
    ///
    /// Called only by web-serving callers (full daemon, memvault-web
    /// standalone, memctl daemon-mode). Headless / CLI consumers skip it.
    pub fn init_ui_agent(
        client: &memvault_api::LocalClient,
        data_dir: &std::path::Path,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // Delegates to the canonical LocalClient enrollment helper.
        // Web-specific work here is limited to picking the identity_dir
        // and installing the resulting identity in the UI state cache.
        let ui_identity_dir = data_dir.join("identity").join("ui_agent");
        let ui_identity = memvault_api::agent_identity::enroll_local_agent(
            client,
            "_ui",
            &ui_identity_dir,
            memvault_auth::Role::AgentHost,
            // Daemon-managed identity — no expiry. `generate_local`
            // saturates so this is treated as effectively never-expires.
            u64::MAX,
        )?;
        // The `_ui` agent is a read/admin surface, not a writer — it doesn't
        // get its own bucket.
        super::ui::state::set_ui_agent_identity(Arc::new(ui_identity));
        Ok(())
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

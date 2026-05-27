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
    /// Auth is per-agent: every request carries an EdDSA-signed JWT (see
    /// `memvault_auth::jwt`) embedding the issuing agent's MembershipAttestation.
    /// The server verifies the attestation against `admin_pubkey`, then verifies
    /// the JWT signature against the agent's public key from the attestation.
    pub struct AppState {
        pub client: Arc<dyn MemvaultClient>,
        pub event_bus: Arc<EventBus>,
        /// Cluster admin's verifying key — the root of trust for attestations.
        /// Loaded from `LocalClient::admin_signing_key().verifying_key()` on
        /// genesis-admin daemons, or from rotation state on joined peers.
        pub admin_pubkey: VerifyingKey,
        /// Operational metrics.
        pub metrics: Arc<memvault_api::metrics::Metrics>,
    }

    /// Bootstrap per-agent web auth: derive the cluster admin pubkey from the
    /// client (which must hold the admin signing key) and register a fresh
    /// "_ui" agent identity that the web UI uses for its session JWTs.
    ///
    /// Call once before constructing [`AppState`]; the returned pubkey is the
    /// root of trust for JWT verification on every API request.
    pub fn init_web_auth(
        client: &memvault_api::LocalClient,
        data_dir: &std::path::Path,
        peer_id: Vec<u8>,
    ) -> Result<ed25519_dalek::VerifyingKey, Box<dyn std::error::Error + Send + Sync>> {
        let admin_pubkey = client.admin_verifying_key().ok_or_else(|| {
            "no admin signing key configured — daemon must be cluster admin (genesis) before serving the web API".to_string()
        })?;
        let admin_signing_key = client.admin_signing_key().cloned().unwrap();

        let cluster_bytes = client.cluster_id();
        let mut cluster_arr = [0u8; 32];
        if cluster_bytes.len() == 32 {
            cluster_arr.copy_from_slice(cluster_bytes);
        }
        let cluster_id = memvault_core::ClusterId(cluster_arr);
        let admin_peer_id = memvault_core::PeerId(peer_id);

        let ui_identity_dir = data_dir.join("identity").join("ui_agent");
        // Rotate the UI identity on every startup — JWTs are short-lived and
        // the WASM client refreshes via /auth/session-token.
        let _ = std::fs::remove_dir_all(&ui_identity_dir);
        let ui_identity = memvault_api::agent_identity::AgentIdentity::generate_local(
            &ui_identity_dir,
            "_ui",
            &cluster_id,
            &admin_peer_id,
            &admin_signing_key,
            memvault_auth::Role::AgentHost,
            365 * 24 * 60 * 60 * 1_000_000_000,
        )?;
        super::ui::state::set_ui_agent_identity(Arc::new(ui_identity));

        Ok(admin_pubkey)
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

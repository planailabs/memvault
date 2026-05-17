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
    use memvault_api::{EventBus, MemvaultClient};

    /// Application state shared across all handlers.
    pub struct AppState {
        pub client: Arc<dyn MemvaultClient>,
        pub event_bus: Arc<EventBus>,
        /// Pre-shared bearer token for Phase 7 authentication.
        pub auth_token: String,
        /// Operational metrics.
        pub metrics: Arc<memvault_api::metrics::Metrics>,
    }

    /// Load the API bearer token from `data_dir/api.token`, generating a new
    /// random token on first run. The file is created with mode 0600.
    pub fn load_or_generate_token(data_dir: &std::path::Path) -> std::io::Result<String> {
        let token_path = data_dir.join("api.token");
        if let Ok(token) = std::fs::read_to_string(&token_path) {
            let token = token.trim().to_string();
            if !token.is_empty() {
                return Ok(token);
            }
        }
        use rand::Rng;
        let mut bytes = [0u8; 32];
        rand::thread_rng().fill(&mut bytes);
        let token = hex::encode(bytes);
        std::fs::write(&token_path, &token)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&token_path, std::fs::Permissions::from_mode(0o600))?;
        }
        Ok(token)
    }

    /// Build the API-only memvault router (no web UI).
    pub fn build_router(state: Arc<AppState>) -> Router {
        Router::new().nest("/api/v1", super::api::routes(state))
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
        let dioxus = Router::new()
            .serve_dioxus_application(ServeConfig::new(), super::ui::app::App);

        api.merge(dioxus)
    }
}

#[cfg(feature = "server")]
pub use server_router::*;

#[cfg(test)]
mod tests;

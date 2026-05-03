//! `memvault-web` — Axum-based REST API and web UI for the memvault daemon.
//!
//! Uses `plan-ai-design` for shared UI components and styling.
//!
//! Server-side modules (`api`, `components`, `error`, router builders) are
//! gated behind the `server` feature so the crate compiles cleanly as a
//! WASM client when built with `--features web`.

#[cfg(not(target_arch = "wasm32"))]
pub mod api;
#[cfg(not(target_arch = "wasm32"))]
pub mod components;
#[cfg(not(target_arch = "wasm32"))]
pub mod error;

#[cfg(feature = "webui")]
pub mod ui;

/// Re-export the shared design system for consumers.
pub use plan_ai_design as design;

// ── Server-only exports ────────────────────────────────────────────────

#[cfg(not(target_arch = "wasm32"))]
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

    /// Build the API-only memvault router (no web UI).
    pub fn build_router(state: Arc<AppState>) -> Router {
        Router::new().nest("/api/v1", super::api::routes(state))
    }

    /// Build a fullstack router: API + Dioxus server functions + SSR + custom asset fallback.
    ///
    /// The `asset_fallback` handler serves pre-built web assets (typically via
    /// rust-embed in the host binary).  Dioxus server functions are registered
    /// automatically so `#[server]` calls from the WASM client work.
    #[cfg(feature = "server")]
    pub fn build_fullstack_router<F>(state: Arc<AppState>, asset_fallback: F) -> Router
    where
        F: FnOnce(Router) -> Router + Send + 'static,
    {
        use dioxus::server::{DioxusRouterExt, FullstackState, ServeConfig};

        // API routes (already stateless — .with_state() called inside).
        let api = Router::new().nest("/api/v1", super::api::routes(state));

        // Dioxus server functions + SSR.
        let dioxus = Router::<FullstackState>::new()
            .register_server_functions()
            .fallback(axum::routing::get(FullstackState::render_handler))
            .with_state(FullstackState::new(ServeConfig::new(), super::ui::app::App));

        // Merge API on top (higher priority), then Dioxus server fns,
        // then embedded assets as the outermost fallback.
        let router = api.merge(dioxus);
        asset_fallback(router)
    }
}

#[cfg(not(target_arch = "wasm32"))]
pub use server_router::*;

#[cfg(test)]
mod tests;

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

    /// Build a fullstack router: API + Dioxus server fns + embedded asset serving.
    ///
    /// No SSR — the pre-built WASM client renders everything client-side.
    /// Server functions are registered headlessly so `#[server]` calls work.
    /// `try_asset` serves embedded static files; `index.html` is the SPA fallback.
    #[cfg(feature = "server")]
    pub fn build_fullstack_router<F>(state: Arc<AppState>, try_asset: F) -> Router
    where
        F: Fn(&str) -> Option<axum::response::Response> + Clone + Send + Sync + 'static,
    {
        use dioxus::server::{DioxusRouterExt, FullstackState};

        // API routes (already stateless — .with_state() called inside).
        let api = Router::new().nest("/api/v1", super::api::routes(state));

        // Dioxus server functions (headless — no SSR rendering).
        let server_fns = Router::<FullstackState>::new()
            .register_server_functions()
            .with_state(FullstackState::headless());

        // Serve embedded assets as the fallback (index.html for SPA routing).
        let try_asset_clone = try_asset.clone();
        let asset_fallback = move |uri: axum::http::Uri| {
            let try_asset = try_asset_clone.clone();
            async move {
                let path = uri.path().trim_start_matches('/');
                if let Some(response) = try_asset(path) {
                    return response;
                }
                // SPA fallback: serve index.html for unknown paths.
                try_asset("index.html")
                    .unwrap_or_else(|| {
                        axum::response::IntoResponse::into_response((
                            axum::http::StatusCode::NOT_FOUND,
                            "index.html not found in embedded assets",
                        ))
                    })
            }
        };

        api.merge(server_fns).fallback(asset_fallback)
    }
}

#[cfg(not(target_arch = "wasm32"))]
pub use server_router::*;

#[cfg(test)]
mod tests;

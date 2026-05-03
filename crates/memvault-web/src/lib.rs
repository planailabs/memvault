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

    /// Minimal index.html for Dioxus SSR.  Includes the WASM script tag and
    /// Tailwind CSS link.  Dioxus injects hydration data at render time.
    const INDEX_HTML: &str = r#"<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>memvault</title>
    <link rel="stylesheet" href="/tailwind.css">
</head>
<body>
    <div id="main"></div>
    <script type="module" src="/wasm/memvault-web.js"></script>
</body>
</html>"#;

    /// Tailwind CSS — bundled at compile time from the public/ directory.
    const TAILWIND_CSS: &[u8] = include_bytes!("../public/tailwind.css");

    /// Write index.html and tailwind.css to a temp dir and set `DIOXUS_PUBLIC_PATH`
    /// so `ServeConfig::new()` picks them up.
    /// Must be called **before** `build_fullstack_router` or `dioxus::serve`.
    #[cfg(feature = "server")]
    pub fn prepare_public_dir() {
        let dir = std::env::temp_dir().join("memvault-web-public");
        let _ = std::fs::create_dir_all(&dir);
        let _ = std::fs::write(dir.join("index.html"), INDEX_HTML);
        let _ = std::fs::write(dir.join("tailwind.css"), TAILWIND_CSS);
        // SAFETY: called before the router is built.
        unsafe { std::env::set_var("DIOXUS_PUBLIC_PATH", &dir) };
    }

    /// Build a fullstack router: API + Dioxus server fns + SSR + embedded assets.
    ///
    /// `try_asset` serves embedded static files (wasm, js, css).
    /// The Dioxus SSR handler renders HTML pages with hydration data.
    #[cfg(feature = "server")]
    pub fn build_fullstack_router<F>(state: Arc<AppState>, try_asset: F) -> Router
    where
        F: Fn(&str) -> Option<axum::response::Response> + Clone + Send + Sync + 'static,
    {
        use axum::extract::State;
        use axum::http::Request;
        use axum::body::Body;
        use dioxus::server::{DioxusRouterExt, FullstackState, ServeConfig};

        // API routes (already stateless — .with_state() called inside).
        let api = Router::new().nest("/api/v1", super::api::routes(state));

        // Combined fallback: try embedded asset first, then SSR.
        let try_asset_clone = try_asset.clone();
        let combined_fallback = move |State(ssr_state): State<FullstackState>,
                                      request: Request<Body>| {
            let try_asset = try_asset_clone.clone();
            async move {
                let path = request.uri().path().trim_start_matches('/');
                // Serve embedded static assets (wasm, js, css).
                if let Some(response) = try_asset(path) {
                    return response;
                }
                // SSR: render HTML with hydration data.
                axum::response::IntoResponse::into_response(
                    FullstackState::render_handler(State(ssr_state), request).await
                )
            }
        };

        // Dioxus server functions + SSR with combined fallback.
        let dioxus = Router::<FullstackState>::new()
            .register_server_functions()
            .fallback(combined_fallback)
            .with_state(FullstackState::new(ServeConfig::new(), super::ui::app::App));

        api.merge(dioxus)
    }
}

#[cfg(not(target_arch = "wasm32"))]
pub use server_router::*;

#[cfg(test)]
mod tests;

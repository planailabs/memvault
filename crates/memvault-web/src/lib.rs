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
        use axum::http::Request;
        use axum::body::Body;
        use axum::middleware;
        use dioxus::server::{DioxusRouterExt, ServeConfig};

        // API routes (already stateless — .with_state() called inside).
        let api = Router::new().nest("/api/v1", super::api::routes(state));

        // Dioxus server functions + SSR (GET-only fallback, matching standard
        // serve_api_application pattern to avoid hydration mismatches).
        let dioxus = Router::new()
            .serve_api_application(ServeConfig::new(), super::ui::app::App);

        // Layer that intercepts requests for embedded static assets before they
        // reach the Dioxus SSR handler.
        let asset_layer = middleware::from_fn(move |request: Request<Body>, next: middleware::Next| {
            let try_asset = try_asset.clone();
            async move {
                let path = request.uri().path().trim_start_matches('/');
                if let Some(response) = try_asset(path) {
                    return response;
                }
                next.run(request).await
            }
        });

        api.merge(dioxus).layer(asset_layer)
    }
}

#[cfg(feature = "server")]
pub use server_router::*;

#[cfg(test)]
mod tests;

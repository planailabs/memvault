fn main() {
    #[cfg(feature = "server")]
    {
        // Use dioxus::serve() to provide a custom router that includes both
        // the Dioxus SSR/server-fns AND our REST API routes. Everything runs
        // on the single port that dx serve manages.
        dioxus::serve(|| async {
            use std::sync::Arc;
            use memvault_api::EventBus;

            // Build the Dioxus router (SSR + server functions).
            let dioxus_router = dioxus::server::router(memvault_web::ui::app::App);

            // Initialize the client (lazy init opens the db on first use).
            let client = match memvault_web::ui::state::client() {
                Ok(c) => c,
                Err(e) => {
                    tracing::warn!("memvault client init failed: {e}; API routes will error");
                    // Return just the Dioxus router without API routes.
                    return Ok(dioxus_router);
                }
            };

            let app_state = Arc::new(memvault_web::AppState {
                client,
                event_bus: Arc::new(EventBus::new(64)),
                auth_token: String::new(), // no auth in standalone dev mode
                metrics: Arc::new(memvault_api::metrics::Metrics::new()),
            });
            let api = axum::Router::new()
                .nest("/api/v1", memvault_web::api::routes(app_state));

            Ok(api.merge(dioxus_router))
        });
    }

    #[cfg(not(feature = "server"))]
    {
        dioxus::launch(memvault_web::ui::app::App);
    }
}

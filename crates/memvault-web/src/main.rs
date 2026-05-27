fn main() {
    #[cfg(feature = "server")]
    {
        use dioxus::server::{DioxusRouterExt, ServeConfig, axum};

        dioxus::serve(move || async move {
            let mut router = axum::Router::new()
                .serve_dioxus_application(ServeConfig::new(), memvault_web::ui::app::App);

            // Attach REST API routes (client is lazily initialized on first use).
            match memvault_web::ui::state::client() {
                Ok(client) => {
                    use std::sync::Arc;

                    let data_dir = std::env::var("MEMVAULT_DATA_DIR")
                        .map(std::path::PathBuf::from)
                        .unwrap_or_else(|_| {
                            dirs::data_local_dir()
                                .unwrap_or_else(|| std::path::PathBuf::from("."))
                                .join("memvault")
                        });
                    // Local client is required to derive admin pubkey + ui agent.
                    let local_client = match memvault_web::ui::state::local_client() {
                        Ok(c) => c,
                        Err(e) => {
                            eprintln!("memvault: API routes NOT mounted: {e}");
                            return Ok(router);
                        }
                    };
                    let auth = match memvault_web::init_web_auth(
                        &local_client,
                        &data_dir,
                        Vec::new(),
                    ) {
                        Ok(a) => a,
                        Err(e) => {
                            eprintln!("memvault: API routes NOT mounted (auth init: {e})");
                            return Ok(router);
                        }
                    };

                    let app_state = Arc::new(memvault_web::AppState {
                        client,
                        event_bus: Arc::new(memvault_api::EventBus::new(64)),
                        admin_pubkey: auth.admin_pubkey,
                        node_trust: auth.node_trust,
                        metrics: Arc::new(memvault_api::metrics::Metrics::new()),
                    });
                    router = axum::Router::new()
                        .nest("/api/v1", memvault_web::api::routes(app_state))
                        .merge(router);
                    eprintln!("memvault: API routes mounted at /api/v1");
                }
                Err(e) => {
                    eprintln!("memvault: API routes NOT mounted (client init failed: {e})");
                }
            }

            Ok(router)
        });
    }

    #[cfg(not(feature = "server"))]
    {
        dioxus::launch(memvault_web::ui::app::App);
    }
}

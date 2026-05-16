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
                    let auth_token = memvault_web::load_or_generate_token(&data_dir)
                        .unwrap_or_default();

                    let app_state = Arc::new(memvault_web::AppState {
                        client,
                        event_bus: Arc::new(memvault_api::EventBus::new(64)),
                        auth_token,
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

    #[cfg(all(not(feature = "server"), not(feature = "web-embedded")))]
    {
        dioxus::launch(memvault_web::ui::app::App);
    }

    // Embedded daemon mode: launch via dioxus-web directly WITHOUT hydrate
    // feature to avoid hydration mismatches from separately-built WASM.
    // SSR content remains visible until this point (fast initial paint), then
    // the client takes over with a fresh render.
    #[cfg(feature = "web-embedded")]
    {
        // Clear SSR content before fresh render to avoid duplicate DOM nodes.
        if let Some(el) = web_sys::window()
            .and_then(|w| w.document())
            .and_then(|d| d.get_element_by_id("main"))
        {
            el.set_inner_html("");
        }
        dioxus_web::launch::launch(
            memvault_web::ui::app::App,
            vec![],
            vec![],
        );
    }
}

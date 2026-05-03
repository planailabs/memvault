fn main() {
    #[cfg(feature = "server")]
    {
        use dioxus::server::{DioxusRouterExt, ServeConfig, axum};

        dioxus::serve(move || async move {
            let mut router = axum::Router::new()
                .serve_dioxus_application(ServeConfig::new(), memvault_web::ui::app::App);

            // Attach our REST API if the client can be initialized.
            if let Ok(client) = memvault_web::ui::state::client() {
                use std::sync::Arc;
                let app_state = Arc::new(memvault_web::AppState {
                    client,
                    event_bus: Arc::new(memvault_api::EventBus::new(64)),
                    auth_token: String::new(),
                    metrics: Arc::new(memvault_api::metrics::Metrics::new()),
                });
                router = axum::Router::new()
                    .nest("/api/v1", memvault_web::api::routes(app_state))
                    .merge(router);
            }

            Ok(router)
        });
    }

    #[cfg(not(feature = "server"))]
    {
        dioxus::launch(memvault_web::ui::app::App);
    }
}

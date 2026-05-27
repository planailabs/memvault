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
                    // Standalone mode: load (or generate) a per-daemon node
                    // key and install it on the LocalClient. The daemon main
                    // path does this with the libp2p host key; here we use a
                    // file-backed key under `<data_dir>/identity/node.key`.
                    match memvault_api::node_key::load_or_generate(&data_dir) {
                        Ok(k) => local_client.set_node_signing_key(k),
                        Err(e) => {
                            eprintln!("memvault: API routes NOT mounted (node key: {e})");
                            return Ok(router);
                        }
                    }
                    let trust = match memvault_api::bootstrap::bootstrap_cluster_trust(
                        &local_client,
                    ) {
                        Ok(t) => t,
                        Err(e) => {
                            eprintln!("memvault: API routes NOT mounted (trust bootstrap: {e})");
                            return Ok(router);
                        }
                    };

                    // Inside dioxus::serve's async closure, a tokio runtime
                    // is active — spawn the watcher onto it.
                    let _watcher = memvault_api::sigchain::spawn_sigchain_watcher(
                        Arc::clone(&local_client),
                        trust.admin_pubkey,
                        trust.trust_state.clone(),
                    );

                    if let Err(e) = memvault_web::init_ui_agent(&local_client, &data_dir) {
                        eprintln!("memvault: API routes NOT mounted (ui agent: {e})");
                        return Ok(router);
                    }

                    let app_state = Arc::new(memvault_web::AppState {
                        client,
                        event_bus: Arc::new(memvault_api::EventBus::new(64)),
                        admin_pubkey: trust.admin_pubkey,
                        node_trust: Arc::clone(&trust.trust_state.node_trust),
                        revoked_agents: Arc::clone(&trust.trust_state.revoked_agents),
                        revoked_nodes: Arc::clone(&trust.trust_state.revoked_nodes),
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

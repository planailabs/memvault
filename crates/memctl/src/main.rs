// When compiled for wasm32 (by dx), this is the WASM client entry point.
#[cfg(target_arch = "wasm32")]
fn main() {
    memvault_web::launch_client();
}

#[cfg(not(target_arch = "wasm32"))]
fn main() {
    use clap::Parser;

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into()),
        )
        .init();

    let args: Vec<String> = std::env::args().collect();
    let has_subcommand = args.len() > 1;

    if has_subcommand {
        // CLI mode: create a tokio runtime for async commands.
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("failed to build tokio runtime");
        rt.block_on(async {
            let cli = memctl::Cli::parse();
            if let Err(e) = memctl::run(cli).await {
                eprintln!("Error: {e:#}");
                std::process::exit(1);
            }
        });
    } else if std::env::var("DIOXUS_DEVSERVER_ADDR").is_ok() {
        // Launched by `dx serve` — use dioxus::serve() so the dx dev
        // proxy can connect. This path is dev-only (hot-reload).
        // No swarm — dx serve mode is frontend development only.
        #[cfg(feature = "daemon")]
        {
            use std::sync::Arc;
            use dioxus::server::{DioxusRouterExt, ServeConfig};

            memvault_web::ui::state::set_client({
                let c = memvault_web::ui::state::client()
                    .expect("failed to initialize memvault client");
                c
            });

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
                client: memvault_web::ui::state::client().unwrap(),
                event_bus: Arc::new(memvault_api::EventBus::new(256)),
                auth_token,
                metrics: Arc::new(memvault_api::metrics::Metrics::new()),
            });

            dioxus::serve(move || {
                let state = Arc::clone(&app_state);
                async move {
                    let router = axum::Router::new()
                        .serve_dioxus_application(ServeConfig::new(), memvault_web::ui::app::App)
                        .nest("/api/v1", memvault_web::api::routes(state));
                    Ok(router)
                }
            });
        }
    } else {
        // No subcommand, not dx serve → run as daemon (web UI + P2P swarm).
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("failed to build tokio runtime");
        rt.block_on(async {
            let mut injected = args;
            injected.insert(1, "daemon".to_string());
            let cli = memctl::Cli::parse_from(injected);
            if let Err(e) = memctl::run(cli).await {
                eprintln!("Error: {e:#}");
                std::process::exit(1);
            }
        });
    }
}

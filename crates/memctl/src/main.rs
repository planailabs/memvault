// When compiled for wasm32 (by dx), this is the WASM client entry point.
#[cfg(target_arch = "wasm32")]
fn main() {
    memvault_web::launch_client();
}

// Native entry point.
//
// Two modes:
//   - Zero args (dx serve or bare invocation): dioxus::serve() with a
//     P2P swarm running on a background thread.
//   - Has subcommand: CLI mode (`memctl daemon`, `memctl genesis`, etc.).
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

    if args.len() > 1 {
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
    } else {
        // Zero args → dioxus::serve() + swarm on background thread.
        #[cfg(feature = "daemon")]
        {
            use std::sync::Arc;
            use dioxus::server::{DioxusRouterExt, ServeConfig};

            let data_dir = std::env::var("MEMVAULT_DATA_DIR")
                .map(std::path::PathBuf::from)
                .unwrap_or_else(|_| {
                    dirs::data_local_dir()
                        .unwrap_or_else(|| std::path::PathBuf::from("."))
                        .join("memvault")
                });

            // Shared EventBus: the client publishes events, the swarm
            // thread subscribes and announces heads over gossipsub.
            let event_bus = Arc::new(memvault_api::EventBus::new(256));

            // Spawn P2P swarm on a background thread (its own tokio runtime).
            // Returns the store so we can share it with the web client
            // (redb only allows one open handle per database file).
            let store = match memctl::spawn_swarm_background(&data_dir, Arc::clone(&event_bus)) {
                Ok((store, _handle)) => {
                    tracing::info!("P2P swarm spawned on background thread");
                    Some(store)
                }
                Err(e) => {
                    tracing::warn!("failed to start P2P swarm: {e} (continuing without sync)");
                    None
                }
            };

            // Build LocalClient using the shared store + event bus, then
            // set it BEFORE dioxus::serve() so server functions find it.
            if let Some(store) = store {
                let client: Arc<dyn memvault_api::MemvaultClient> = Arc::new(
                    memctl::create_client_with_bus(
                        store,
                        &data_dir,
                        Arc::clone(&event_bus),
                    )
                );
                memvault_web::ui::state::set_client(Arc::clone(&client));
            }
            // If swarm failed, let client() do its lazy init (opens its own store).

            let auth_token = memvault_web::load_or_generate_token(&data_dir)
                .unwrap_or_default();

            let client_arc = memvault_web::ui::state::client()
                .expect("failed to initialize memvault client");

            let app_state = Arc::new(memvault_web::AppState {
                client: client_arc,
                event_bus,
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

        #[cfg(not(feature = "daemon"))]
        {
            eprintln!("No subcommand given and daemon feature disabled. Run `memctl --help`.");
            std::process::exit(1);
        }
    }
}

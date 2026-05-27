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
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
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
            use dioxus::server::{DioxusRouterExt, ServeConfig};
            use std::sync::Arc;

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

            // Open store and run rebuild BEFORE starting the swarm.
            // The rebuild rewrites blocks (changing CIDs) and must complete
            // before any peer can request data.
            let store = match memvault_store::MemvaultStore::open(
                data_dir.join("blocks.redb"),
            ) {
                Ok(s) => {
                    let store = std::sync::Arc::new(s);
                    let local_client = Arc::new(
                        memctl::create_client_with_bus(
                            Arc::clone(&store),
                            &data_dir,
                            Arc::clone(&event_bus),
                        )
                        .expect("create_client_with_bus failed"),
                    );
                    memvault_web::ui::state::set_client(Arc::clone(&local_client));
                    Some((store, local_client))
                }
                Err(e) => {
                    tracing::warn!("failed to open store: {e} (continuing without sync)");
                    None
                }
            };

            // NOW spawn the swarm — rebuild is complete, safe to serve blocks.
            if let Some((store, _)) = &store {
                match memctl::spawn_swarm_with_store(
                    Arc::clone(store),
                    &data_dir,
                    Arc::clone(&event_bus),
                ) {
                    Ok(_handle) => {
                        tracing::info!("P2P swarm spawned on background thread");
                    }
                    Err(e) => {
                        tracing::warn!("failed to start P2P swarm: {e} (continuing without sync)");
                    }
                }
            }
            // If swarm failed, let client() do its lazy init (opens its own store).

            let local_client = store
                .as_ref()
                .map(|(_, c)| Arc::clone(c))
                .expect("daemon mode requires a successfully-opened store");
            // Design A-1: node signing key == libp2p host key. Same
            // file the swarm uses, so bootstrap_cluster_trust and the
            // /join/1.0 request carry the same ed25519 pubkey. See
            // tests::join_protocol::libp2p_key_drives_both_swarm_and_node_signing_key.
            local_client.set_node_signing_key(
                memctl::libp2p_node_signing_key(&data_dir).expect("load node signing key"),
            );
            let trust = memvault_api::bootstrap::bootstrap_cluster_trust(&local_client)
                .expect("cluster trust bootstrap failed");
            memvault_web::init_ui_agent(&local_client, &data_dir)
                .expect("init_ui_agent failed");

            let client_arc =
                memvault_web::ui::state::client().expect("failed to initialize memvault client");

            let app_state = Arc::new(memvault_web::AppState {
                client: client_arc,
                event_bus,
                admin_pubkey: trust.admin_pubkey,
                node_trust: Arc::clone(&trust.trust_state.node_trust),
                revoked_agents: Arc::clone(&trust.trust_state.revoked_agents),
                revoked_nodes: Arc::clone(&trust.trust_state.revoked_nodes),
                metrics: Arc::new(memvault_api::metrics::Metrics::new()),
            });

            // Sync `fn main()` — no tokio runtime yet. Defer the watcher
            // spawn until inside the async block, which IS driven by
            // dioxus' runtime. The sync portion of dioxus' callback runs
            // outside any runtime, so `tokio::spawn` would panic there.
            // `OnceLock` guards against double-spawn if dioxus rebuilds
            // the router (e.g. on HMR / reconnect).
            let watcher_client = Arc::clone(&local_client);
            let watcher_admin = trust.admin_pubkey;
            let watcher_state = trust.trust_state.clone();
            let watcher_spawned = Arc::new(std::sync::OnceLock::<()>::new());

            dioxus::serve(move || {
                let state = Arc::clone(&app_state);
                let watcher_client = Arc::clone(&watcher_client);
                let watcher_state = watcher_state.clone();
                let watcher_spawned = Arc::clone(&watcher_spawned);
                async move {
                    if watcher_spawned.get().is_none() {
                        let _ = memvault_api::sigchain::spawn_sigchain_watcher(
                            watcher_client,
                            watcher_admin,
                            watcher_state,
                        );
                        let _ = watcher_spawned.set(());
                    }
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

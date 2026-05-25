// When compiled for wasm32 (by dx), this is the WASM client entry point.
// Both this and the daemon mode's SSR compile the same App component from
// memvault-web, ensuring hydration entry ordering matches perfectly.
#[cfg(target_arch = "wasm32")]
fn main() {
    memvault_web::launch_client();
}

// Native entry point — NOT #[tokio::main] because dioxus::serve() needs
// to create its own runtime when running under dx serve.
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
    // Check if any arg matches a known subcommand name.
    const SUBCOMMANDS: &[&str] = &[
        "genesis", "put", "get", "search", "list", "audit", "history",
        "retract", "token-issue", "token-list", "token-revoke", "rotations",
        "status", "graph-add", "graph-link", "graph-query", "gc", "peers",
        "repair-index", "fix-cluster-id", "renew-attestation", "export",
        "import-files", "import-docs", "share-inbox", "share-outbox",
        "share-approve", "share-reject", "bucket-new", "bucket-list",
        "bucket-show", "bucket-rename", "bucket-attach", "bucket-archive",
        "bucket-bind", "daemon", "agent-enroll", "agent-list", "agent-show",
        "help",
    ];
    let has_subcommand = args.iter().skip(1).any(|a| SUBCOMMANDS.contains(&a.as_str()));

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
    } else {
        // No subcommand. Two cases:
        // 1. dx serve launched us → public/ exists → use dioxus::serve()
        // 2. bare `cargo run` → no public/ → fall through to daemon command

        // With embed feature, assets are in the binary — no filesystem check needed.
        #[cfg(feature = "embed")]
        let has_assets = true;
        #[cfg(not(feature = "embed"))]
        let has_assets = std::env::current_exe()
            .ok()
            .and_then(|p| p.parent().map(|d| d.join("public").exists()))
            .unwrap_or(false);

        if has_assets {
            // dx serve mode: assets exist, use dioxus::serve() which
            // creates its own runtime and handles dx port negotiation.
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
            // No assets — run daemon command (API-only, with fallback).
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
}

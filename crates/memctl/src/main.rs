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
    // Only fall back to daemon mode when launched with zero arguments
    // (i.e. by dx serve). Any args at all → parse normally with clap.
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
    } else {
        // No subcommand → run as daemon (web UI + P2P swarm).
        // Commands::Daemon handles both fullstack (when assets/embed exist)
        // and API-only mode. It always runs the libp2p swarm.
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

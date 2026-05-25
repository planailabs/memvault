// When compiled for wasm32 (by dx), this is the WASM client entry point.
// Both this and the daemon mode's SSR compile the same App component from
// memvault-web, ensuring hydration works correctly.
#[cfg(target_arch = "wasm32")]
fn main() {
    #[cfg(feature = "web")]
    memvault_web::launch_client();
}

// Normal CLI entry point.
#[cfg(not(target_arch = "wasm32"))]
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    use clap::Parser;

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into()),
        )
        .init();

    // When launched by `dx serve`, the binary receives no arguments.
    // Detect this and default to daemon mode so the Dioxus fullstack
    // server starts automatically.
    let args: Vec<String> = std::env::args().collect();
    let has_subcommand = args.len() > 1 && !args[1].starts_with('-');

    let cli = if has_subcommand {
        memctl::Cli::parse()
    } else {
        // No subcommand → inject "daemon" so we start in server mode.
        // This makes `memctl` (bare) and `dx serve` both start the daemon.
        let mut injected = args.clone();
        injected.insert(1, "daemon".to_string());
        memctl::Cli::parse_from(injected)
    };

    memctl::run(cli).await
}

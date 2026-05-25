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

    let cli = memctl::Cli::parse();
    memctl::run(cli).await
}

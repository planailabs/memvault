//! memctl — standalone binary entry point.
//! Delegates to memvault_api::memctl::run().

use anyhow::Result;
use clap::Parser;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into()),
        )
        .init();

    let cli = memvault_api::memctl::Cli::parse();
    memvault_api::memctl::run(cli).await
}

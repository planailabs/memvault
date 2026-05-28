use anyhow::Result;
use clap::Parser;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "memvault_mcp=info,rmcp=warn".parse().unwrap()),
        )
        .with_writer(std::io::stderr)
        .init();

    let cli = memvault_mcp::Cli::parse();
    memvault_mcp::run(cli).await
}

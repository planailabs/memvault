pub mod enroll;
pub mod server;
pub mod types;

use std::sync::Arc;

use anyhow::Result;
use clap::{Parser, Subcommand};
use rmcp::ServiceExt;

use crate::server::MemvaultServer;

#[derive(Parser, Debug)]
#[command(
    name = "plan-ai-memvault",
    about = "MCP server for memvault p2p memory"
)]
pub struct Cli {
    #[command(flatten)]
    pub client: memvault_api::ClientArgs,

    /// Default tags applied when the agent omits them (comma-separated, scope:label format).
    #[arg(long, env = "MEMVAULT_DEFAULT_TAGS", value_delimiter = ',')]
    pub default_tags: Vec<String>,

    /// Default visibility when the agent omits it (internal, federated, public).
    #[arg(long, env = "MEMVAULT_DEFAULT_VISIBILITY", default_value = "internal")]
    pub default_visibility: String,

    /// Agent identifier — used to look up or create the agent-scoped default
    /// bucket. When set, all writes that omit `bucket` will be scoped to that
    /// bucket.
    #[arg(long, env = "MEMVAULT_AGENT_ID")]
    pub agent_id: Option<String>,

    /// Optional subcommand. With no subcommand, runs the MCP server
    /// (the historical behavior).
    #[command(subcommand)]
    pub command: Option<Command>,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Exchange an agent join token with a remote memvault server for a
    /// full agent credential and persist it into the local identity dir.
    Enroll(enroll::EnrollArgs),
}

/// Run the memvault MCP server with the given CLI arguments — or, if a
/// subcommand was provided, dispatch to that instead.
pub async fn run(cli: Cli) -> Result<()> {
    // Install the rustls ring crypto provider once for the process
    // before any reqwest::Client is constructed. The workspace pins
    // reqwest with the `rustls-no-provider` feature so the picker is
    // per-binary — without this, HTTPS calls (e.g. `mcp enroll
    // --server https://…`) panic on the first request.
    let _ = rustls::crypto::ring::default_provider().install_default();

    if let Some(command) = cli.command {
        return match command {
            Command::Enroll(args) => enroll::run(args).await,
        };
    }
    let client: Arc<dyn memvault_api::MemvaultClient> = Arc::from(cli.client.connect().await?);

    // Resolve the agent bucket once at startup so subsequent writes can default to it.
    let agent_bucket = if let Some(agent_id) = cli.agent_id.as_deref() {
        match client.ensure_agent_bucket(agent_id).await {
            Ok(bid) => {
                tracing::info!(
                    agent_id,
                    bucket = %hex::encode(bid.0),
                    "resolved agent bucket"
                );
                Some(bid)
            }
            Err(e) => {
                tracing::warn!(
                    agent_id,
                    "failed to resolve agent bucket: {e} — writes without an explicit bucket will fail"
                );
                None
            }
        }
    } else {
        None
    };

    let server = MemvaultServer::new(
        client,
        cli.default_tags,
        cli.default_visibility,
        agent_bucket,
    );

    let transport = rmcp::transport::io::stdio();
    let server_handle = server.serve(transport).await?;
    server_handle.waiting().await?;

    Ok(())
}

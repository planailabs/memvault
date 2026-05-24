//! CLI binary for memvault-export.

use std::path::PathBuf;

use anyhow::Result;
use clap::Parser;

use memvault_export::{create_sink, run_export, ExportOptions};

#[derive(Parser)]
#[command(name = "memvault-export", about = "Export memvault content to directory or tar archive")]
struct Cli {
    /// Output path (directory or .tar/.tar.gz file)
    #[arg(short, long, default_value = "./memvault-export")]
    output: PathBuf,

    /// Force tar output (auto-detected from .tar/.tar.gz extension)
    #[arg(long)]
    tar: bool,

    /// Compress tar with gzip
    #[arg(long)]
    gzip: bool,

    /// Include historical versions of documents
    #[arg(long)]
    history: bool,

    /// Skip VFS symlink tree
    #[arg(long)]
    no_vfs: bool,

    /// Filter by tag (scope:label format)
    #[arg(long)]
    tag: Option<String>,

    /// Filter by view name
    #[arg(long)]
    view: Option<String>,

    /// Path to redb database (local mode)
    #[arg(long, env = "MEMVAULT_DB")]
    db: Option<PathBuf>,

    /// Memvault HTTP API URL (used when --db is not set)
    #[arg(long, env = "MEMVAULT_URL", default_value = "http://127.0.0.1:8401")]
    url: String,

    /// Bearer token file (HTTP mode)
    #[arg(long, env = "MEMVAULT_TOKEN_FILE")]
    token_file: Option<PathBuf>,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "memvault_export=info".parse().unwrap()),
        )
        .init();

    let cli = Cli::parse();

    let tag_filter = cli.tag.as_deref().and_then(|t| {
        let parts: Vec<&str> = t.splitn(2, ':').collect();
        if parts.len() == 2 {
            Some((parts[0].to_string(), parts[1].to_string()))
        } else {
            None
        }
    });

    let opts = ExportOptions {
        history: cli.history,
        include_vfs: !cli.no_vfs,
        tag_filter,
        view_filter: cli.view,
    };

    let token = cli.token_file.as_ref()
        .and_then(|p| std::fs::read_to_string(p).ok())
        .map(|s| s.trim().to_string());
    let client = memvault_api::connect(memvault_api::ConnectOptions {
        db: cli.db,
        url: Some(cli.url),
        token,
    }).await?;

    let sink = create_sink(&cli.output, cli.tar, cli.gzip)?;
    let stats = run_export(&*client, sink, opts).await?;

    println!(
        "Exported {} documents, {} files, {} entities ({} history versions)",
        stats.documents, stats.files, stats.entities, stats.history_versions
    );

    Ok(())
}

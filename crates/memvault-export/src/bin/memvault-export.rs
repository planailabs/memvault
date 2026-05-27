//! CLI binary for memvault-export.

use std::path::PathBuf;

use anyhow::Result;
use clap::Parser;

use memvault_export::{ExportOptions, create_sink, run_export};

#[derive(Parser)]
#[command(
    name = "memvault-export",
    about = "Export memvault content to directory or tar archive"
)]
struct Cli {
    #[command(flatten)]
    client: memvault_api::ClientArgs,

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

    let tag_filter = cli.tag.as_deref().and_then(memvault_api::docs::parse_tag_filter);

    let opts = ExportOptions {
        history: cli.history,
        include_vfs: !cli.no_vfs,
        tag_filter,
        view_filter: cli.view,
    };

    let client = cli.client.connect().await?;
    let sink = create_sink(&cli.output, cli.tar, cli.gzip)?;
    let stats = run_export(&*client, sink, opts).await?;

    println!(
        "Exported {} documents, {} files, {} entities ({} history versions)",
        stats.documents, stats.files, stats.entities, stats.history_versions
    );

    Ok(())
}

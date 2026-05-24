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

    /// Memvault HTTP API URL
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

    let db_path = cli.db.as_ref().ok_or_else(|| {
        anyhow::anyhow!("--db is required (HTTP mode not yet supported, use local redb path)")
    })?;
    let client = create_local_client(db_path).await?;

    let sink = create_sink(&cli.output, cli.tar, cli.gzip)?;
    let stats = run_export(&client, sink, opts).await?;

    println!(
        "Exported {} documents, {} files, {} entities ({} history versions)",
        stats.documents, stats.files, stats.entities, stats.history_versions
    );

    Ok(())
}

async fn create_local_client(db_path: &std::path::Path) -> Result<memvault_api::LocalClient> {
    use std::sync::Arc;
    use tokio::sync::RwLock;
    use memvault_query::{QuotaManager, TextIndex};
    use memvault_store::MemvaultStore;
    use memvault_api::EventBus;

    let store = Arc::new(MemvaultStore::open(db_path)?);
    let client = memvault_api::LocalClient::new(
        store,
        Arc::new(RwLock::new(TextIndex::new())),
        Arc::new(RwLock::new(QuotaManager::new(Default::default()))),
        Arc::new(EventBus::new(16)),
        vec![0u8; 32],
        vec![0u8; 32],
    );
    Ok(client)
}


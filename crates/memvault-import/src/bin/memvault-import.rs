//! CLI binary for memvault-import.

use std::path::PathBuf;

use anyhow::Result;
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "memvault-import",
    about = "Import files and documents into memvault"
)]
struct Cli {
    #[command(flatten)]
    client: memvault_api::ClientArgs,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Import files or folders into memvault
    Files {
        /// Path to file or folder to import
        path: PathBuf,
        /// VFS folder to place imported files in (e.g. "/documents")
        #[arg(long)]
        vfs: Option<String>,
        /// Tags to apply (scope:label format)
        #[arg(short, long)]
        tag: Vec<String>,
        /// Visibility (internal, federated, public)
        #[arg(short, long, default_value = "internal")]
        visibility: String,
    },
    /// Import text/markdown files as documents
    Docs {
        /// Path to file or folder to import (reads .md, .txt, .markdown files)
        path: PathBuf,
        /// VFS folder to place imported docs in (e.g. "/notes")
        #[arg(long)]
        vfs: Option<String>,
        /// Tags to apply (scope:label format)
        #[arg(short, long)]
        tag: Vec<String>,
        /// Visibility (internal, federated, public)
        #[arg(short, long, default_value = "internal")]
        visibility: String,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "memvault_import=info".parse().unwrap()),
        )
        .init();

    let cli = Cli::parse();
    let client = cli.client.connect().await?;

    match cli.command {
        Commands::Files {
            path,
            vfs,
            tag,
            visibility,
        } => {
            let tags = memvault_api::docs::parse_tags(&tag);
            let imported =
                memvault_import::import_files(&*client, &path, vfs.as_deref(), &tags, &visibility)
                    .await?;
            println!("Imported {imported} file(s).");
        }
        Commands::Docs {
            path,
            vfs,
            tag,
            visibility,
        } => {
            let tags = memvault_api::docs::parse_tags(&tag);
            let vis = memvault_api::docs::parse_visibility(Some(&visibility));
            let imported =
                memvault_import::import_docs(&*client, &path, vfs.as_deref(), &tags, vis).await?;
            println!("Imported {imported} document(s).");
        }
    }

    Ok(())
}

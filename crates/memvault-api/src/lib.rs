//! `memvault-api` — Agent-facing API, RPC layer, and client trait for memvault.

pub mod agent_identity;
pub mod client;
pub mod docs;
pub mod error;
pub mod files;
pub mod health;
#[cfg(feature = "http-client")]
pub mod http;
pub mod local;
pub mod metrics;
pub mod rebuild;
pub mod otel;
pub mod quotas;
pub mod rotation;
pub mod rpc;
pub mod subscription;
pub mod tokens;
pub mod types;
pub mod vfs;

pub use client::MemvaultClient;
pub use error::{ApiError, Result};
#[cfg(feature = "http-client")]
pub use http::HttpApiClient;
pub use local::LocalClient;
pub use subscription::{EventBus, MemvaultEvent};
pub use types::{DocSummary, NodeStatus, RotationInfo, TokenStatus, TraversalHit, View};

/// Shared CLI arguments for connecting to a memvault instance.
/// Embed in your CLI struct with `#[command(flatten)]`.
#[cfg(feature = "http-client")]
#[derive(clap::Args, Debug, Clone)]
pub struct ClientArgs {
    /// Path to redb database (local mode). Takes priority over --url.
    #[arg(long, env = "MEMVAULT_DB")]
    pub db: Option<std::path::PathBuf>,

    /// Memvault HTTP API URL (used when --db is not set).
    #[arg(long, env = "MEMVAULT_URL", default_value = "http://127.0.0.1:8401")]
    pub url: String,

    /// Bearer token file (HTTP mode).
    #[arg(long, env = "MEMVAULT_TOKEN_FILE")]
    pub token_file: Option<std::path::PathBuf>,
}

#[cfg(feature = "http-client")]
impl ClientArgs {
    /// Connect to memvault using these CLI args.
    /// Returns a local client if `--db` is set, otherwise an HTTP client.
    pub async fn connect(&self) -> std::result::Result<Box<dyn MemvaultClient>, anyhow::Error> {
        if let Some(db_path) = &self.db {
            use memvault_query::{QuotaManager, TextIndex};
            use memvault_store::MemvaultStore;
            use std::sync::Arc;
            use tokio::sync::RwLock;

            if let Some(parent) = db_path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            let store = Arc::new(MemvaultStore::open(db_path)?);
            let client = LocalClient::open(
                store,
                Arc::new(RwLock::new(TextIndex::new())),
                Arc::new(RwLock::new(QuotaManager::new(Default::default()))),
                Arc::new(EventBus::new(64)),
                vec![0u8; 32],
                vec![0u8; 32],
            )
            .await?;
            Ok(Box::new(client))
        } else {
            let token = self
                .token_file
                .as_ref()
                .and_then(|p| std::fs::read_to_string(p).ok())
                .map(|s| s.trim().to_string())
                .unwrap_or_default();
            let client = HttpApiClient::new(&self.url, &token)?;
            Ok(Box::new(client))
        }
    }
}

/// Connection options for creating a MemvaultClient (programmatic API).
#[cfg(feature = "http-client")]
pub struct ConnectOptions {
    /// Path to redb database (local mode). Takes priority over URL.
    pub db: Option<std::path::PathBuf>,
    /// HTTP API URL (used when db is None).
    pub url: Option<String>,
    /// Bearer token (HTTP mode).
    pub token: Option<String>,
}

/// Create a MemvaultClient from connection options.
#[cfg(feature = "http-client")]
pub async fn connect(
    opts: ConnectOptions,
) -> std::result::Result<Box<dyn MemvaultClient>, anyhow::Error> {
    if let Some(db_path) = &opts.db {
        use memvault_query::{QuotaManager, TextIndex};
        use memvault_store::MemvaultStore;
        use std::sync::Arc;
        use tokio::sync::RwLock;

        if let Some(parent) = db_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let store = Arc::new(MemvaultStore::open(db_path)?);
        let client = LocalClient::open(
            store,
            Arc::new(RwLock::new(TextIndex::new())),
            Arc::new(RwLock::new(QuotaManager::new(Default::default()))),
            Arc::new(EventBus::new(64)),
            vec![0u8; 32],
            vec![0u8; 32],
        )
        .await?;
        Ok(Box::new(client))
    } else {
        let url = opts
            .url
            .unwrap_or_else(|| "http://127.0.0.1:8401".to_string());
        let token = opts.token.unwrap_or_default();
        let client = HttpApiClient::new(&url, &token)?;
        Ok(Box::new(client))
    }
}

//! `memvault-api` — Agent-facing API, RPC layer, and client trait for memvault.

pub mod acl;
pub mod agent_identity;
pub mod bootstrap;
pub mod client;
pub mod docs;
pub mod error;
pub mod files;
pub mod health;
#[cfg(feature = "http-client")]
pub mod http;
pub mod link_reconcile;
pub mod local;
pub mod metrics;
pub mod node_key;
pub mod rebuild;
pub mod sigchain;
pub mod otel;
pub mod quotas;
pub mod rotation;
pub mod rpc;
pub mod subscription;
pub mod tokens;
pub mod types;
pub mod vfs;

pub use client::MemvaultClient;
pub use ed25519_dalek;
pub use error::{ApiError, Result};
#[cfg(feature = "http-client")]
pub use http::HttpApiClient;
pub use local::LocalClient;
pub use subscription::{EventBus, MemvaultEvent};
pub use types::{
    DocSummary, GrantInfo, NodeStatus, RotationInfo, ShareProposalInfo, TokenStatus, TraversalHit,
    View,
};

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

    /// Agent identity directory (HTTP mode). The directory must contain
    /// `private_key.pem`, `attestation.cbor`, `enrollment.cbor`, and
    /// `agent.json` (as produced by `AgentIdentity::generate_local`).
    /// Defaults to `<data_local_dir>/memvault/identity/ui_agent` for
    /// localhost daemon access.
    #[arg(long, env = "MEMVAULT_IDENTITY_DIR")]
    pub identity_dir: Option<std::path::PathBuf>,
}

#[cfg(feature = "http-client")]
fn default_identity_dir() -> std::path::PathBuf {
    dirs::data_local_dir()
        .unwrap_or_else(|| std::path::PathBuf::from("."))
        .join("memvault")
        .join("identity")
        .join("ui_agent")
}

#[cfg(feature = "http-client")]
impl ClientArgs {
    /// Connect to memvault using these CLI args.
    /// Returns a local client if `--db` is set, otherwise an HTTP client
    /// authenticated with a JWT issued from the loaded agent identity.
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
            )?;
            Ok(Box::new(client))
        } else {
            // Load the agent identity and hand it to HttpApiClient. Every
            // outgoing request gets a freshly-issued JWT signed with the
            // agent's private key, auto-renewed near expiry.
            let identity_dir = self.identity_dir.clone().unwrap_or_else(default_identity_dir);
            let identity =
                crate::agent_identity::AgentIdentity::load(&identity_dir).map_err(|e| {
                    anyhow::anyhow!(
                        "failed to load agent identity from {}: {e} — pass --identity-dir or set MEMVAULT_IDENTITY_DIR",
                        identity_dir.display()
                    )
                })?;
            let client = HttpApiClient::new(&self.url, Some(std::sync::Arc::new(identity)))?;
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
        )?;
        Ok(Box::new(client))
    } else {
        let url = opts
            .url
            .unwrap_or_else(|| "http://127.0.0.1:8401".to_string());
        // ConnectOptions::token is preserved for callers that already issued
        // their own JWT externally — but the canonical path now wires through
        // an AgentIdentity via ClientArgs. Unauthenticated client is the
        // fallback here.
        let client = HttpApiClient::new(&url, None)?;
        Ok(Box::new(client))
    }
}

//! Server-side state for Dioxus server functions.

#[cfg(feature = "server")]
mod inner {
    use std::sync::{Arc, OnceLock};

    use memvault_api::MemvaultClient;

    static CLIENT: OnceLock<Arc<dyn MemvaultClient>> = OnceLock::new();

    /// Set the client explicitly (used by the daemon).
    pub fn set_client(client: Arc<dyn MemvaultClient>) {
        let _ = CLIENT.set(client);
    }

    /// Get the shared client. If not set explicitly (standalone dx serve mode),
    /// lazily opens a local redb database on first call.
    pub fn client() -> Result<Arc<dyn MemvaultClient>, dioxus::prelude::ServerFnError> {
        if let Some(c) = CLIENT.get() {
            return Ok(c.clone());
        }

        // Lazy init for standalone mode (dx serve).
        let client = init_local_client()
            .map_err(|e| dioxus::prelude::ServerFnError::new(format!("memvault init: {e}")))?;
        let _ = CLIENT.set(client);
        CLIENT
            .get()
            .cloned()
            .ok_or_else(|| dioxus::prelude::ServerFnError::new("memvault client init race"))
    }

    fn init_local_client() -> Result<Arc<dyn MemvaultClient>, Box<dyn std::error::Error>> {
        use tokio::sync::RwLock;

        let data_dir = std::env::var("MEMVAULT_DATA_DIR")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|_| {
                dirs::data_local_dir()
                    .unwrap_or_else(|| std::path::PathBuf::from("."))
                    .join("memvault")
            });
        let db_path = std::env::var("MEMVAULT_DB")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|_| data_dir.join("blocks.redb"));

        if let Some(parent) = db_path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        tracing::info!("opening local memvault db at {}", db_path.display());
        let store = Arc::new(memvault_store::MemvaultStore::open(&db_path)?);
        let client = Arc::new(memvault_api::LocalClient::new(
            store,
            Arc::new(RwLock::new(memvault_query::TextIndex::new())),
            Arc::new(RwLock::new(memvault_query::QuotaManager::new(Default::default()))),
            Arc::new(memvault_api::EventBus::new(64)),
            vec![0u8; 32],
            vec![0u8; 32],
        ));

        // Load or rebuild the text index in a background thread to avoid
        // blocking the async runtime (we may be called from inside tokio).
        let index_cache = db_path.with_extension("text_index.json");
        let client_clone = Arc::clone(&client);
        let _ = std::thread::spawn(move || {
            let rt = tokio::runtime::Runtime::new().unwrap();
            let _ = rt.block_on(client_clone.load_or_rebuild_index(&index_cache));
        })
        .join();

        Ok(client as Arc<dyn MemvaultClient>)
    }
}

#[cfg(feature = "server")]
pub use inner::*;

/// Server-side storage for the API auth token, used to generate session tokens
/// for the web UI to call the REST API directly.
#[cfg(feature = "server")]
mod token_store {
    use std::sync::OnceLock;

    static API_TOKEN: OnceLock<String> = OnceLock::new();

    /// Set the API auth token (called during server startup).
    pub fn set_api_token(token: String) {
        let _ = API_TOKEN.set(token);
    }

    /// Get the API auth token for session-token generation.
    pub fn api_token() -> Option<&'static str> {
        API_TOKEN.get().map(|s| s.as_str())
    }
}

#[cfg(feature = "server")]
pub use token_store::*;

//! Server-side state for Dioxus server functions.

#[cfg(feature = "server")]
mod inner {
    use std::sync::{Arc, OnceLock};

    use memvault_api::MemvaultClient;

    static CLIENT: OnceLock<Arc<dyn MemvaultClient>> = OnceLock::new();
    static LOCAL_CLIENT: OnceLock<Arc<memvault_api::LocalClient>> = OnceLock::new();

    /// Set the client explicitly (used by the daemon). Populates both the
    /// trait-object and concrete handles so grant/ACL server functions work.
    pub fn set_client(client: Arc<memvault_api::LocalClient>) {
        let _ = LOCAL_CLIENT.set(Arc::clone(&client));
        let _ = CLIENT.set(client as Arc<dyn MemvaultClient>);
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

    /// Get the concrete LocalClient (for grant/ACL operations).
    pub fn local_client() -> Result<Arc<memvault_api::LocalClient>, dioxus::prelude::ServerFnError> {
        // Ensure lazy init happened
        let _ = client()?;
        LOCAL_CLIENT
            .get()
            .cloned()
            .ok_or_else(|| dioxus::prelude::ServerFnError::new("local client not available"))
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

        // Read peer_id and cluster_id from store (set during genesis/daemon start)
        let peer_id = store
            .get_local_peer_id()
            .ok()
            .flatten()
            .unwrap_or_else(|| vec![0u8; 32]);
        let cluster_id = store
            .get_local_cluster_id()
            .ok()
            .flatten()
            .unwrap_or_else(|| vec![0u8; 32]);

        let client = Arc::new(
            memvault_api::LocalClient::open(
                store,
                Arc::new(RwLock::new(memvault_query::TextIndex::new())),
                Arc::new(RwLock::new(memvault_query::QuotaManager::new(
                    Default::default(),
                ))),
                Arc::new(memvault_api::EventBus::new(64)),
                peer_id,
                cluster_id,
            )
            .unwrap_or_else(|e| panic!("memvault LocalClient::open failed: {e}")),
        );

        let index_cache = db_path.with_extension("text_index.json");

        // Load or rebuild the text index in a background thread to avoid
        // blocking the async runtime (we may be called from inside tokio).
        let client_clone = Arc::clone(&client);
        let _ = std::thread::spawn(move || {
            let rt = tokio::runtime::Runtime::new().unwrap();
            let _ = rt.block_on(client_clone.load_or_rebuild_index(&index_cache));
        })
        .join();

        let _ = LOCAL_CLIENT.set(Arc::clone(&client));
        Ok(client as Arc<dyn MemvaultClient>)
    }
}

#[cfg(feature = "server")]
pub use inner::*;

/// Server-side storage for the built-in "web UI" agent identity.
/// Used to issue session JWTs for the WASM client via `/auth/session-token`.
#[cfg(feature = "server")]
mod ui_identity_store {
    use std::sync::{Arc, OnceLock};

    use memvault_api::agent_identity::AgentIdentity;

    static UI_AGENT: OnceLock<Arc<AgentIdentity>> = OnceLock::new();

    /// Set the daemon's built-in web-ui agent identity. Called once at daemon
    /// startup. Subsequent calls are no-ops.
    pub fn set_ui_agent_identity(id: Arc<AgentIdentity>) {
        let _ = UI_AGENT.set(id);
    }

    /// Get the web-ui agent identity, if one has been registered.
    pub fn ui_agent_identity() -> Option<Arc<AgentIdentity>> {
        UI_AGENT.get().cloned()
    }
}

#[cfg(feature = "server")]
pub use ui_identity_store::*;

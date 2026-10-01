//! Server-side state for Dioxus server functions.

#[cfg(feature = "server")]
mod inner {
    use std::sync::{Arc, OnceLock};

    use memvault_api::MemvaultClient;

    static CLIENT: OnceLock<Arc<dyn MemvaultClient>> = OnceLock::new();
    static LOCAL_CLIENT: OnceLock<Arc<memvault_api::LocalClient>> = OnceLock::new();
    /// Serializes the fallible lazy init so concurrent callers don't all run
    /// `init_local_client` at once and collide on the redb file lock — the
    /// source of flaky 500s when API tests run in parallel. (OnceLock has no
    /// stable fallible get-or-init, so we double-check under this mutex.)
    static INIT_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// Set the client explicitly (used by the daemon). Populates both the
    /// trait-object and concrete handles so grant/ACL server functions work.
    pub fn set_client(client: Arc<memvault_api::LocalClient>) {
        let _ = LOCAL_CLIENT.set(Arc::clone(&client));
        let _ = CLIENT.set(client as Arc<dyn MemvaultClient>);
    }

    /// Get the shared client. If not set explicitly (standalone dx serve mode),
    /// lazily opens a local redb database on first call.
    /// How the web UI signs people in (`MEMVAULT_UI_AUTH`):
    ///
    /// - `open` (default): everyone is the daemon's generated `_ui` agent,
    ///   with its full rights.
    /// - `jwt`: a proxy in front of memvault puts an agent JWT in the
    ///   `Authorization` header of every request; the UI signs in with it
    ///   and acts as that agent.
    /// - `oidc`: people sign in with an OpenID Connect provider (configured
    ///   by `MEMVAULT_OIDC_*` variables) and act as the `_ui` agent, or as a
    ///   local agent their address is mapped to.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum UiAuth {
        Open,
        Jwt,
        Oidc,
    }

    static UI_AUTH: OnceLock<UiAuth> = OnceLock::new();
    static SELF_URL: OnceLock<String> = OnceLock::new();

    /// The UI's sign-in mode, from `MEMVAULT_UI_AUTH` (read once).
    pub fn ui_auth() -> UiAuth {
        *UI_AUTH.get_or_init(
            || match std::env::var("MEMVAULT_UI_AUTH").as_deref().map(str::trim) {
                Ok("jwt") => UiAuth::Jwt,
                Ok("oidc") => UiAuth::Oidc,
                Ok("open") | Ok("") | Err(_) => UiAuth::Open,
                Ok(other) => panic!("MEMVAULT_UI_AUTH={other:?}: use open, jwt or oidc"),
            },
        )
    }

    /// Sets the mode explicitly (tests, embedders); the first call wins.
    pub fn set_ui_auth(mode: UiAuth) {
        let _ = UI_AUTH.set(mode);
    }

    /// The daemon's own API (`http://127.0.0.1:<port>`): in `jwt` and
    /// `oidc` modes the UI's server functions go through it as the signed-in
    /// agent, so they get exactly that agent's rights.
    pub fn set_self_url(url: String) {
        let _ = SELF_URL.set(url);
    }

    /// The agent JWT of the request being served: the proxy's
    /// `Authorization` header, else the UI's session cookie.
    pub fn request_token() -> Option<String> {
        let ctx = dioxus::fullstack::FullstackContext::current()?;
        let parts = ctx.parts_mut();
        if let Some(t) = parts
            .headers
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
        {
            return Some(t.to_string());
        }
        let cookies = parts.headers.get("cookie")?.to_str().ok()?;
        cookies
            .split(';')
            .filter_map(|c| c.trim().split_once('='))
            .find(|(k, _)| *k == "memvault_session")
            .map(|(_, v)| v.to_string())
    }

    /// The client the UI works with: in `open` mode the daemon's own (full
    /// rights); otherwise the daemon's REST API as the signed-in agent.
    pub fn client() -> Result<Arc<dyn MemvaultClient>, dioxus::prelude::ServerFnError> {
        if ui_auth() == UiAuth::Open {
            return full_client();
        }
        let token =
            request_token().ok_or_else(|| dioxus::prelude::ServerFnError::new("not signed in"))?;
        let url = SELF_URL
            .get()
            .ok_or_else(|| dioxus::prelude::ServerFnError::new("the daemon's own URL isn't set"))?;
        let c = memvault_api::HttpApiClient::with_token(url, &token)
            .map_err(|e| dioxus::prelude::ServerFnError::new(e.to_string()))?;
        Ok(Arc::new(c))
    }

    /// The daemon's local client for UI pages that need its own rights
    /// (trust, bucket administration): only in `open` mode.
    pub fn ui_local_client()
    -> Result<Arc<memvault_api::LocalClient>, dioxus::prelude::ServerFnError> {
        if ui_auth() != UiAuth::Open {
            return Err(dioxus::prelude::ServerFnError::new(
                "this page needs the daemon's own rights; it's only available with MEMVAULT_UI_AUTH=open",
            ));
        }
        local_client()
    }

    /// The daemon's own client (full rights).
    pub fn full_client() -> Result<Arc<dyn MemvaultClient>, dioxus::prelude::ServerFnError> {
        if let Some(c) = CLIENT.get() {
            return Ok(c.clone());
        }

        // Lazy init for standalone mode (dx serve). Serialize via INIT_LOCK so
        // only one thread opens the redb; concurrent callers wait and then see
        // the populated OnceLock (double-checked locking).
        let _guard = INIT_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(c) = CLIENT.get() {
            return Ok(c.clone());
        }
        let client = init_local_client()
            .map_err(|e| dioxus::prelude::ServerFnError::new(format!("memvault init: {e}")))?;
        let _ = CLIENT.set(client);
        CLIENT
            .get()
            .cloned()
            .ok_or_else(|| dioxus::prelude::ServerFnError::new("memvault client init race"))
    }

    /// Get the concrete LocalClient (for grant/ACL operations).
    pub fn local_client() -> Result<Arc<memvault_api::LocalClient>, dioxus::prelude::ServerFnError>
    {
        // Ensure lazy init happened
        let _ = full_client()?;
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

    /// Build a `QueryScope` from the top-bar filter trio. The bucket selection
    /// is a *set* (`buckets`), so the web layer is multi-bucket-capable; a
    /// single-bucket top-bar passes a one-element vec, and an empty vec / `None`
    /// means all accessible buckets.
    pub fn query_scope(
        view: Option<String>,
        buckets_hex: Vec<String>,
        show_retracted: bool,
        kind: Option<memvault_core::NodeKind>,
    ) -> memvault_core::QueryScope {
        use memvault_core::{BucketId, BucketSelector, QueryScope, RetractionMode};

        let parse = |h: &str| -> Option<BucketId> {
            let bytes = hex::decode(h).ok()?;
            if bytes.len() != 32 {
                return None;
            }
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            Some(BucketId(arr))
        };
        let ids: Vec<BucketId> = buckets_hex.iter().filter_map(|h| parse(h)).collect();
        let buckets = if ids.is_empty() {
            BucketSelector::Accessible
        } else {
            BucketSelector::Only(ids)
        };
        QueryScope {
            view,
            buckets,
            retraction: if show_retracted {
                RetractionMode::IncludeRetracted
            } else {
                RetractionMode::ActiveOnly
            },
            kind,
            entity_kind: None,
            // Default to lean summaries; callers needing per-node detail
            // (mtime, attachment count, …) opt in via `.with_detail(Full)`.
            detail: memvault_core::DetailLevel::Summary,
        }
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

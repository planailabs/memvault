fn main() {
    // When running standalone (dx serve), initialize a local memvault client
    // so server functions work without the full daemon.
    #[cfg(feature = "server")]
    {
        use std::sync::Arc;
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

        // Ensure parent directory exists.
        if let Some(parent) = db_path.parent() {
            if let Err(e) = std::fs::create_dir_all(parent) {
                eprintln!("memvault: cannot create {}: {e}", parent.display());
            }
        }

        match memvault_store::MemvaultStore::open(&db_path) {
            Ok(store) => {
                let store = Arc::new(store);
                let client = Arc::new(memvault_api::LocalClient::new(
                    store,
                    Arc::new(RwLock::new(memvault_query::TextIndex::new())),
                    Arc::new(RwLock::new(memvault_query::QuotaManager::new(Default::default()))),
                    Arc::new(memvault_api::EventBus::new(64)),
                    vec![0u8; 32],
                    vec![0u8; 32],
                ));

                // Load or rebuild the text index.
                let index_cache = db_path.with_extension("text_index.json");
                let client_clone = Arc::clone(&client);
                std::thread::spawn(move || {
                    let rt = tokio::runtime::Runtime::new().unwrap();
                    let _ = rt.block_on(client_clone.load_or_rebuild_index(&index_cache));
                })
                .join()
                .ok();

                memvault_web::ui::state::set_client(client);
                eprintln!("memvault: initialized local client (db={})", db_path.display());
            }
            Err(e) => {
                eprintln!("memvault: could not open {}: {e}", db_path.display());
                eprintln!("memvault: server functions will fail — run 'memctl genesis' first or set MEMVAULT_DB");
            }
        }
    }

    dioxus::launch(memvault_web::ui::app::App);
}

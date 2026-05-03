fn main() {
    // When running standalone (dx serve), initialize a local memvault client
    // so server functions work without the full daemon.
    #[cfg(feature = "server")]
    {
        use std::sync::Arc;
        use tokio::sync::RwLock;

        let data_dir = dirs::data_local_dir()
            .unwrap_or_else(|| std::path::PathBuf::from("."))
            .join("memvault");
        let _ = std::fs::create_dir_all(&data_dir);
        let db_path = data_dir.join("blocks.redb");

        if let Ok(store) = memvault_store::MemvaultStore::open(&db_path) {
            let store = Arc::new(store);
            let client = Arc::new(memvault_api::LocalClient::new(
                store,
                Arc::new(RwLock::new(memvault_query::TextIndex::new())),
                Arc::new(RwLock::new(memvault_query::QuotaManager::new(Default::default()))),
                Arc::new(memvault_api::EventBus::new(64)),
                vec![0u8; 32],
                vec![0u8; 32],
            ));

            // Load or rebuild the text index in a blocking context.
            let index_cache = data_dir.join("text_index.json");
            let client_clone = Arc::clone(&client);
            std::thread::spawn(move || {
                let rt = tokio::runtime::Runtime::new().unwrap();
                let _ = rt.block_on(client_clone.load_or_rebuild_index(&index_cache));
            })
            .join()
            .ok();

            memvault_web::ui::state::set_client(client);
            eprintln!("memvault: initialized local client (db={})", db_path.display());
        } else {
            eprintln!("memvault: could not open {}, server functions will fail", db_path.display());
        }
    }

    dioxus::launch(memvault_web::ui::app::App);
}

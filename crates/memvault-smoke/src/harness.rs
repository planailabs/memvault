//! Test harness: creates nodes (store + client) for smoke tests.

use std::sync::Arc;
use tokio::sync::RwLock;

use memvault_api::{EventBus, LocalClient};
use memvault_core::ClusterId;
use memvault_query::QuotaManager;
use memvault_store::MemvaultStore;

/// A test node: owns a tempdir, store, and client.
pub struct TestNode {
    pub _dir: tempfile::TempDir,
    pub store: Arc<MemvaultStore>,
    pub client: LocalClient,
    pub cluster_id: ClusterId,
}

impl TestNode {
    /// Create a fresh node with a random cluster_id.
    pub fn new() -> Self {
        Self::with_cluster(&ClusterId::random())
    }

    /// Create a node that shares the given cluster_id.
    pub fn with_cluster(cluster_id: &ClusterId) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let store = Arc::new(MemvaultStore::open(dir.path().join("blocks.redb")).unwrap());
        store.set_local_cluster_id(&cluster_id.0).unwrap();

        let mut peer_id = vec![0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut peer_id);
        store.set_local_peer_id(&peer_id).unwrap();

        let client = LocalClient::new(
            Arc::clone(&store),
            Arc::new(RwLock::new(QuotaManager::default())),
            Arc::new(EventBus::new(64)),
            peer_id,
            cluster_id.0.to_vec(),
        );

        // Admin key for token issuance
        let mut seed = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut seed);
        let admin_sk = ed25519_dalek::SigningKey::from_bytes(&seed);
        client.set_admin_signing_key(admin_sk.clone());

        // Pin a self-signed AdminGenesis so this node represents a real,
        // set-up (post-genesis) cluster — required to issue admin/node
        // membership tokens, mirroring a node created via `memctl genesis`.
        let genesis = memvault_auth::sign_admin_genesis(
            &admin_sk,
            cluster_id.clone(),
            memvault_core::wall_ns(),
        )
        .unwrap();
        client.set_pinned_admin_genesis(genesis);

        // Node signing key — without one, every write goes down the
        // unsigned fallback path in build_signed_envelope. That uses a
        // different shape for `tags` than the real (Signed<T>) path,
        // hiding tag-related parsing bugs that only show up against the
        // daemon. Setting a key here makes smoke tests exercise the
        // production envelope shape.
        let mut node_seed = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut node_seed);
        client.set_node_signing_key(ed25519_dalek::SigningKey::from_bytes(&node_seed));

        Self {
            _dir: dir,
            store,
            client,
            cluster_id: cluster_id.clone(),
        }
    }

    /// Create a two-node cluster (both nodes share the same cluster_id).
    pub fn cluster_pair() -> (Self, Self) {
        let cluster_id = ClusterId::random();
        (
            Self::with_cluster(&cluster_id),
            Self::with_cluster(&cluster_id),
        )
    }
}

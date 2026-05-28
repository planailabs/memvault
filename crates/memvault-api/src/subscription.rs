//! Event subscription using tokio broadcast channel.

use memvault_core::{BucketId, DocId, EntityId};

/// Events published by the memvault system.
#[derive(Debug, Clone)]
pub enum MemvaultEvent {
    DocCreated { doc_id: DocId, cid: Vec<u8> },
    DocUpdated { doc_id: DocId, cid: Vec<u8> },
    FileAttached { doc_id: DocId, name: String },
    EntityCreated { entity_id: EntityId },
    BucketCreated { bucket_id: BucketId, cid: Vec<u8> },
    Retracted { cid: Vec<u8> },
    TokenConsumed { token_cid: Vec<u8> },
    /// A new sigchain block was persisted (locally created or received from
    /// a peer via RBSR sync). Watchers update their in-memory trust tables
    /// without restarting the daemon.
    SigchainBlock {
        /// Label as written in the `sigchain/<label>` tag (e.g. `node_att`,
        /// `agent_att`, `agent_rev`, `node_rev`, `envelope_auth`).
        label: String,
        cid: Vec<u8>,
    },
}

/// Event broadcaster using tokio broadcast channel.
pub struct EventBus {
    sender: tokio::sync::broadcast::Sender<MemvaultEvent>,
}

impl EventBus {
    pub fn new(capacity: usize) -> Self {
        let (sender, _) = tokio::sync::broadcast::channel(capacity);
        Self { sender }
    }

    pub fn publish(&self, event: MemvaultEvent) {
        // Ignore error (no receivers is fine)
        let _ = self.sender.send(event);
    }

    pub fn subscribe(&self) -> tokio::sync::broadcast::Receiver<MemvaultEvent> {
        self.sender.subscribe()
    }
}

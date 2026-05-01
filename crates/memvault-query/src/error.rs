//! Error types for the query layer.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum QueryError {
    #[error("store error: {0}")]
    Store(#[from] memvault_store::StoreError),

    #[error("block not found: {}", hex::encode(.0))]
    NotFound(Vec<u8>),

    #[error("deserialization error: {0}")]
    Deserialize(String),

    #[error("already retracted")]
    AlreadyRetracted,

    #[error("{0}")]
    Other(String),
}

/// Minimal hex encoding (avoids adding the `hex` crate).
mod hex {
    pub fn encode(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }
}

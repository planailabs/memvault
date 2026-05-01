//! Error types for the API layer.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum ApiError {
    #[error("store error: {0}")]
    Store(#[from] memvault_store::StoreError),

    #[error("doc error: {0}")]
    Doc(#[from] memvault_doc::DocError),

    #[error("query error: {0}")]
    Query(#[from] memvault_query::QueryError),

    #[error("quota exceeded: {0}")]
    QuotaExceeded(#[from] memvault_query::QuotaExceeded),

    #[error("not found: {0}")]
    NotFound(String),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("serialization error: {0}")]
    Serialization(String),

    #[error("rpc error: {0}")]
    Rpc(String),

    #[error("{0}")]
    Other(String),
}

pub type Result<T> = std::result::Result<T, ApiError>;

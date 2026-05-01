//! Error types for memvault-attach.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum AttachError {
    #[error("block not found: {0}")]
    BlockNotFound(String),

    #[error("invalid DAG-PB encoding: {0}")]
    InvalidDagPb(String),

    #[error("invalid UnixFS data: {0}")]
    InvalidUnixFs(String),

    #[error("store error: {0}")]
    Store(#[from] memvault_store::StoreError),

    #[error("protobuf decode error: {0}")]
    ProtoDecode(#[from] prost::DecodeError),

    #[error("range out of bounds: requested {start}..{end} but file size is {size}")]
    RangeOutOfBounds { start: u64, end: u64, size: u64 },

    #[error("empty input")]
    EmptyInput,
}

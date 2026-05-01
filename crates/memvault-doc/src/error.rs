use thiserror::Error;

#[derive(Debug, Error)]
pub enum DocError {
    #[error("document not found: {0}")]
    DocNotFound(String),

    #[error("entity not found: {0}")]
    EntityNotFound(String),

    #[error("edge not found: {0}")]
    EdgeNotFound(String),

    #[error("text patch out of bounds: position {pos} in text of length {len}")]
    PatchOutOfBounds { pos: usize, len: usize },

    #[error("chunk not found: {0}")]
    ChunkNotFound(String),

    #[error("integrity error: {0}")]
    Integrity(String),

    #[error("encode error: {0}")]
    Encode(String),

    #[error("decode error: {0}")]
    Decode(String),

    #[error("invalid operation: {0}")]
    InvalidOp(String),

    #[error("index out of bounds: {index} (max {max})")]
    IndexOutOfBounds { index: usize, max: usize },
}

pub type Result<T> = std::result::Result<T, DocError>;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum ExtractError {
    #[error("unsupported MIME type: {0}")]
    UnsupportedMime(String),

    #[error("extraction failed: {0}")]
    ExtractionFailed(String),

    #[error("content too large: {size} bytes (max {max})")]
    ContentTooLarge { size: usize, max: usize },

    #[error("timeout after {0}ms")]
    Timeout(u64),

    #[error("invalid content: {0}")]
    InvalidContent(String),
}

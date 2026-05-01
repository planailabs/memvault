use thiserror::Error;

/// Errors that can occur during summarization.
#[derive(Debug, Error)]
pub enum SummarizeError {
    #[error("LLM request failed: {0}")]
    LlmError(String),

    #[error("no source content provided")]
    NoSources,

    #[error("input exceeds maximum token budget ({max} tokens)")]
    InputTooLarge { max: usize },

    #[error("serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
}

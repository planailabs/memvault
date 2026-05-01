use thiserror::Error;

#[derive(Debug, Error)]
pub enum PolicyError {
    #[error("invalid regex pattern: {0}")]
    InvalidPattern(#[from] regex::Error),

    #[error("invalid classification level: {0}")]
    InvalidClassification(String),

    #[error("configuration error: {0}")]
    Config(String),
}

use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("codec error: {0}")]
    Codec(String),

    #[error("signature verification failed")]
    SignatureInvalid,

    #[error("signing failed: {0}")]
    SigningFailed(String),

    #[error("CID error: {0}")]
    Cid(String),

    #[error("tag lint error: {0}")]
    TagLint(String),

    #[error("invalid input: {0}")]
    InvalidInput(String),
}

pub type Result<T> = std::result::Result<T, Error>;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum NetError {
    #[error("transport error: {0}")]
    Transport(String),

    #[error("codec error: {0}")]
    Codec(String),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("gossipsub: {0}")]
    Gossipsub(String),

    #[error("serialization error: {0}")]
    Serialization(String),
}

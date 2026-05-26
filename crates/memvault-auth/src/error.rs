use thiserror::Error;

#[derive(Debug, Error)]
pub enum AuthError {
    #[error("signature verification failed")]
    SignatureInvalid,

    #[error("attestation expired at {expired_at_ns}")]
    AttestationExpired { expired_at_ns: u64 },

    #[error("attestation revoked: {reason}")]
    AttestationRevoked { reason: String },

    #[error(
        "peer mismatch: attestation member {attestation_member} != connecting peer {connecting_peer}"
    )]
    PeerMismatch {
        attestation_member: String,
        connecting_peer: String,
    },

    #[error("no valid admin key found for the signing time")]
    NoValidKeyAtTime,

    #[error("token decode error: {0}")]
    TokenDecode(String),

    #[error("token encode error: {0}")]
    TokenEncode(String),

    #[error("invalid token prefix")]
    InvalidTokenPrefix,

    #[error("grant expired")]
    GrantExpired,

    #[error("grant not yet valid")]
    GrantNotYetValid,

    #[error("insufficient permissions")]
    InsufficientPermissions,

    #[error("rotation overlap expired")]
    RotationOverlapExpired,

    #[error("codec error: {0}")]
    Codec(String),
}

pub type Result<T> = std::result::Result<T, AuthError>;

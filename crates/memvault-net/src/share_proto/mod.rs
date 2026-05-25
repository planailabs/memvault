//! Cross-cluster share protocol: `/ai-memvault/share/1.0`.
//!
//! This is a request-response protocol for proposing bucket shares between
//! clusters. It is the second protocol (alongside `/join/1.0`) allowed on
//! connections that have NOT completed `/auth/1.0`.

pub mod codec;

pub use codec::ShareCodec;

use serde::{Deserialize, Serialize};

/// Protocol identifier for the share protocol.
pub const SHARE_PROTOCOL: &str = "/ai-memvault/share/1.0";

/// A share request sent from the proposing cluster to the receiving cluster.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShareRequest {
    pub version: u8,
    /// Serialized `Signed<ShareProposal>` (DAG-CBOR).
    pub proposal_block: Vec<u8>,
}

/// The response from the receiving cluster.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShareResponse {
    pub version: u8,
    pub result: ShareResult,
}

/// The result of processing a share request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ShareResult {
    /// Proposal was accepted into the inbox; decision is async.
    Queued { proposal_cid: Vec<u8> },
    /// Receiving peer does not hold a recipient-eligible identity.
    NotRecipient { try_peers: Vec<String> },
    /// Proposal failed validation (bad signature, expired, etc.).
    Invalid { reason: String },
    /// Cluster has not authorized cross-cluster sharing.
    Refused { reason: String },
}

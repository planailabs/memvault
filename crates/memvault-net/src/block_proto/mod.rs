//! Block exchange protocol — request blocks by CID, receive block data.
//!
//! Used for syncing: when a peer announces a new head via gossipsub,
//! other peers that don't have it use this protocol to fetch the block.

pub mod codec;

pub use memvault_core::BLOCKSTORE_VERSION;

pub use codec::BlockCodec;

use serde::{Deserialize, Serialize};

/// Protocol identifier for block exchange.
pub const BLOCK_PROTOCOL: &str = "/ai-memvault/block/1.0";

/// Hard per-connection ceiling on concurrent block-exchange substreams
/// (inbound + outbound combined), enforced by libp2p request-response.
///
/// The sync driver already caps our *outbound* requests at one in-flight per
/// peer ([`memvault_swarm::MemvaultDriver`]'s outbound gate), so this is the
/// transport-level backstop that also bounds *inbound* streams a peer can open
/// against us. Without a cap, libp2p's default is 100, which let a buggy or
/// busy peer pin a problematic number of open block streams per connection.
/// Small headroom over one keeps a stray inbound request from starving our
/// one outbound slot.
pub const MAX_CONCURRENT_BLOCK_STREAMS: usize = 4;

// ── Range-based set reconciliation (RBSR) ──────────────────────────

/// A fingerprint over a time-range window, used for RBSR.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RangeFingerprint {
    /// Window start (wall_ns, inclusive).
    pub start_ns: u64,
    /// Window end (wall_ns, exclusive).
    pub end_ns: u64,
    /// Number of blocks in this window.
    pub count: u32,
    /// XOR of all CID bytes (first 32 bytes) in the window.
    pub xor: [u8; 32],
}

// ── Block Access Tokens (BATs) ─────────────────────────────────────

/// A capability token granting access to blocks in a specific bucket.
/// Signed by the bucket's admin, time-limited, tied to a grantee peer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockAccessToken {
    /// Bucket this token grants access to.
    pub bucket_id: [u8; 32],
    /// Public key of the peer this token is issued to (non-transferable).
    pub grantee_peer: Vec<u8>,
    /// Cluster that issued this token.
    pub issuer_cluster: [u8; 32],
    /// Expiry timestamp (nanoseconds).
    pub not_after_ns: u64,
    /// Ed25519 signature over the above fields (64 bytes).
    pub signature: Vec<u8>,
}

impl BlockAccessToken {
    /// Build the signing payload (all fields except signature).
    pub fn signing_payload(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(128);
        buf.extend_from_slice(&self.bucket_id);
        buf.extend_from_slice(&self.grantee_peer);
        buf.extend_from_slice(&self.issuer_cluster);
        buf.extend_from_slice(&self.not_after_ns.to_be_bytes());
        buf
    }

    /// Sign the token with an admin signing key.
    pub fn sign(mut self, key: &ed25519_dalek::SigningKey) -> Self {
        use ed25519_dalek::Signer;
        let payload = self.signing_payload();
        self.signature = key.sign(&payload).to_bytes().to_vec();
        self
    }

    /// Verify the token's signature against an admin verifying key.
    pub fn verify(&self, key: &ed25519_dalek::VerifyingKey) -> bool {
        use ed25519_dalek::Verifier;
        if self.signature.len() != 64 {
            return false;
        }
        let payload = self.signing_payload();
        let mut sig_bytes = [0u8; 64];
        sig_bytes.copy_from_slice(&self.signature);
        let sig = ed25519_dalek::Signature::from_bytes(&sig_bytes);
        key.verify(&payload, &sig).is_ok()
    }

    /// Check if the token is valid: not expired, and signature verifies.
    pub fn is_valid(&self, key: &ed25519_dalek::VerifyingKey, now_ns: u64) -> bool {
        now_ns <= self.not_after_ns && self.verify(key)
    }
}

/// Request one or more blocks by CID, or list recent heads.
///
/// Two modes:
/// - **Fetch**: `cids` is non-empty → response contains block data.
/// - **List heads**: `cids` is empty and `since_ns` is set → response
///   contains recent CIDs (with `found=true, data=[]`) so the requester
///   can pick which ones to fetch in a follow-up request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockRequest {
    pub cids: Vec<Vec<u8>>,
    /// When set and `cids` is empty, return CIDs of blocks stored since
    /// this wall-clock timestamp (nanoseconds). Added for initial sync.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub since_ns: Option<u64>,
    /// Max number of CIDs to return in a list-heads response.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<usize>,

    /// Range fingerprints for RBSR reconciliation.
    /// When non-empty, the responder compares each window against its own
    /// store and returns CIDs from mismatched windows.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub range_fingerprints: Vec<RangeFingerprint>,

    /// Optional block access token for cross-cluster requests.
    /// When present, the server validates the token before serving blocks
    /// from the specified bucket.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token: Option<BlockAccessToken>,

    /// Blockstore version of the requester. The responder MUST reject
    /// requests where this doesn't match its own version to prevent
    /// cross-version sync poisoning.
    #[serde(default)]
    pub store_version: u32,
}

/// Response with the requested blocks.
/// Each entry is `(cid, data)`. If a CID is not found, data is empty.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockResponse {
    pub blocks: Vec<BlockEntry>,
}

/// A single block in a response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockEntry {
    pub cid: Vec<u8>,
    pub data: Vec<u8>,
    /// True if the block was found. When false, `data` is empty.
    pub found: bool,
}

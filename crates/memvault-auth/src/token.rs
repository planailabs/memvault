use cid::Cid;
use data_encoding::BASE32_NOPAD;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use memvault_core::{ClusterId, PeerId};
use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;

use crate::admin_genesis::AdminGenesis;
use crate::error::{AuthError, Result};
use crate::role::Role;

/// The prefix for encoded join tokens.
const TOKEN_PREFIX: &str = "mvjoin1:";

/// A join token that can be shared out-of-band to invite new members.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JoinToken {
    pub issuer: PeerId,
    pub cluster_id: ClusterId,
    pub role: Role,
    pub initial_grants: Vec<Cid>,
    pub not_before_ns: u64,
    pub not_after_ns: u64,
    pub max_uses: u32,
    pub nonce: [u8; 16],
    pub label: Option<String>,
    /// The cluster's `AdminGenesis` block. Lets the joining peer pin
    /// the cluster admin pubkey out-of-band (via this token, which is
    /// itself admin-signed). Required for join to bootstrap trust
    /// without consulting sync. `None` only on legacy tokens issued
    /// before this field existed.
    #[serde(default)]
    pub admin_genesis: Option<AdminGenesis>,
    /// Opt-in capability: when true, redeeming this token may also admit
    /// the joiner's supplied admin key as a co-equal cluster admin (in
    /// addition to minting the node attestation), provided the join
    /// request carries a valid proof-of-possession. Default false — a
    /// normal join confers no admin authority.
    #[serde(default)]
    pub admit_as_admin: bool,
    /// Optional dialable multiaddrs for the issuing node, so a joiner can
    /// connect directly instead of waiting for the issuer's peer id (derived
    /// from `issuer`) to surface via mDNS/Kademlia. Advisory hints — the
    /// joiner still verifies the responder against the pinned admin key.
    /// `None`/empty on tokens issued without `--addr`.
    #[serde(default)]
    pub issuer_addrs: Vec<String>,
    #[serde(with = "BigArray")]
    pub signature: [u8; 64],
}

#[derive(Serialize)]
struct TokenSigningPayload<'a> {
    issuer: &'a PeerId,
    cluster_id: &'a ClusterId,
    role: &'a Role,
    initial_grants: &'a [Cid],
    not_before_ns: u64,
    not_after_ns: u64,
    max_uses: u32,
    nonce: &'a [u8; 16],
    label: &'a Option<String>,
    admin_genesis: &'a Option<AdminGenesis>,
    admit_as_admin: bool,
    issuer_addrs: &'a [String],
}

impl JoinToken {
    /// Compute the bytes that are signed.
    pub fn signing_bytes(&self) -> Result<Vec<u8>> {
        let payload = TokenSigningPayload {
            issuer: &self.issuer,
            cluster_id: &self.cluster_id,
            role: &self.role,
            initial_grants: &self.initial_grants,
            not_before_ns: self.not_before_ns,
            not_after_ns: self.not_after_ns,
            max_uses: self.max_uses,
            nonce: &self.nonce,
            label: &self.label,
            admin_genesis: &self.admin_genesis,
            admit_as_admin: self.admit_as_admin,
            issuer_addrs: &self.issuer_addrs,
        };
        crate::domain_sign(b"memvault/sig/join-token/v1", &payload)
    }

    /// Verify the token signature against the issuer's key.
    pub fn verify_signature(&self, issuer_key: &VerifyingKey) -> Result<()> {
        let bytes = self.signing_bytes()?;
        let sig = Signature::from_bytes(&self.signature);
        issuer_key
            .verify(&bytes, &sig)
            .map_err(|_| AuthError::SignatureInvalid)
    }

    /// Check temporal validity of the token.
    pub fn verify_time_bounds(&self, now_ns: u64) -> Result<()> {
        if now_ns < self.not_before_ns {
            return Err(AuthError::GrantNotYetValid);
        }
        if now_ns > self.not_after_ns {
            return Err(AuthError::GrantExpired);
        }
        Ok(())
    }
}

/// Records the consumption of a join token by a peer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenConsumption {
    pub token_cid: Cid,
    pub consumer: PeerId,
    pub consumed_at_ns: u64,
    pub issued_attestation: Cid,
    #[serde(with = "BigArray")]
    pub signature: [u8; 64],
}

#[derive(Serialize)]
struct ConsumptionSigningPayload<'a> {
    token_cid: &'a Cid,
    consumer: &'a PeerId,
    consumed_at_ns: u64,
    issued_attestation: &'a Cid,
}

impl TokenConsumption {
    /// Compute the bytes that are signed.
    pub fn signing_bytes(&self) -> Result<Vec<u8>> {
        let payload = ConsumptionSigningPayload {
            token_cid: &self.token_cid,
            consumer: &self.consumer,
            consumed_at_ns: self.consumed_at_ns,
            issued_attestation: &self.issued_attestation,
        };
        crate::domain_sign(b"memvault/sig/token-consumption/v1", &payload)
    }

    /// Verify the consumption record signature.
    pub fn verify_signature(&self, key: &VerifyingKey) -> Result<()> {
        let bytes = self.signing_bytes()?;
        let sig = Signature::from_bytes(&self.signature);
        key.verify(&bytes, &sig)
            .map_err(|_| AuthError::SignatureInvalid)
    }
}

/// Encode a `JoinToken` to the wire-format string: `mvjoin1:<base32(cbor(token))>`.
pub fn encode_token_string(token: &JoinToken) -> Result<String> {
    let cbor_bytes =
        serde_ipld_dagcbor::to_vec(token).map_err(|e| AuthError::TokenEncode(e.to_string()))?;
    let encoded = BASE32_NOPAD.encode(&cbor_bytes);
    Ok(format!("{}{}", TOKEN_PREFIX, encoded))
}

/// Decode a wire-format token string back to a `JoinToken`.
pub fn decode_token_string(s: &str) -> Result<JoinToken> {
    let rest = s
        .strip_prefix(TOKEN_PREFIX)
        .ok_or(AuthError::InvalidTokenPrefix)?;
    let cbor_bytes = BASE32_NOPAD
        .decode(rest.as_bytes())
        .map_err(|e| AuthError::TokenDecode(e.to_string()))?;
    serde_ipld_dagcbor::from_slice(&cbor_bytes).map_err(|e| AuthError::TokenDecode(e.to_string()))
}

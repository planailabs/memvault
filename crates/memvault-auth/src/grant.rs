use cid::Cid;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use memvault_core::{AgentId, BucketId, ClusterId, PeerId, TagPattern};
use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;

use crate::error::{AuthError, Result};
use crate::role::Role;

/// Who the grant is addressed to.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum GrantAudience {
    Cluster(ClusterId),
    Peer(PeerId),
    Agent(AgentId),
    Role(Role),
}

/// Actions that can be granted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Action {
    Read,
    Write,
    Admin,
    Egress,
}

/// A capability grant authorizing actions on scoped data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Grant {
    pub issuer: PeerId,
    pub issuing_cluster: ClusterId,
    /// The admin (or founder) pubkey whose key signed this grant. Bound
    /// into [`Grant::signing_bytes`] so the signer's identity is
    /// cryptographically authenticated — a forger cannot claim a grant
    /// was admin-signed without holding that admin's secret. ACL
    /// enforcement (`memvault_api::acl::check_bucket_access`) verifies
    /// the signature against this key and checks the key was a
    /// cluster-valid admin at `not_before_ns`.
    ///
    /// Legacy grants written before this field existed deserialize with
    /// `[0u8; 32]` via `#[serde(default)]`; they cannot be retro-signed
    /// (the field is part of the signed payload) and are treated per the
    /// daemon's `strict_grant_verify` policy.
    #[serde(default)]
    pub admin_pubkey: [u8; 32],
    pub audience: GrantAudience,
    pub scopes: Vec<TagPattern>,
    pub actions: Vec<Action>,
    pub not_before_ns: u64,
    pub not_after_ns: u64,
    pub parent: Option<Cid>,
    pub nonce: [u8; 16],
    /// Bucket-scoped grants — OR'd with tag scopes.
    /// Added in B2. Old grants deserialize with empty vec via #[serde(default)].
    #[serde(default)]
    pub bucket_scopes: Vec<BucketId>,
    #[serde(with = "BigArray")]
    pub signature: [u8; 64],
}

#[derive(Serialize)]
struct GrantSigningPayload<'a> {
    issuer: &'a PeerId,
    issuing_cluster: &'a ClusterId,
    admin_pubkey: &'a [u8; 32],
    audience: &'a GrantAudience,
    scopes: &'a [TagPattern],
    actions: &'a [Action],
    not_before_ns: u64,
    not_after_ns: u64,
    parent: &'a Option<Cid>,
    nonce: &'a [u8; 16],
    bucket_scopes: &'a Vec<BucketId>,
}

impl Grant {
    /// Compute the bytes that are signed.
    pub fn signing_bytes(&self) -> Result<Vec<u8>> {
        let payload = GrantSigningPayload {
            issuer: &self.issuer,
            issuing_cluster: &self.issuing_cluster,
            admin_pubkey: &self.admin_pubkey,
            audience: &self.audience,
            scopes: &self.scopes,
            actions: &self.actions,
            not_before_ns: self.not_before_ns,
            not_after_ns: self.not_after_ns,
            parent: &self.parent,
            nonce: &self.nonce,
            bucket_scopes: &self.bucket_scopes,
        };
        serde_ipld_dagcbor::to_vec(&payload).map_err(|e| AuthError::Codec(e.to_string()))
    }

    /// Check whether this grant covers a specific bucket.
    pub fn covers_bucket(&self, bucket_id: &BucketId) -> bool {
        // If no bucket_scopes, the grant applies to all buckets (legacy behavior)
        self.bucket_scopes.is_empty() || self.bucket_scopes.contains(bucket_id)
    }

    /// Verify the grant signature against the issuer's key.
    pub fn verify_signature(&self, issuer_key: &VerifyingKey) -> Result<()> {
        let bytes = self.signing_bytes()?;
        let sig = Signature::from_bytes(&self.signature);
        issuer_key
            .verify(&bytes, &sig)
            .map_err(|_| AuthError::SignatureInvalid)
    }

    /// True if this grant predates the `admin_pubkey` field (i.e. it was
    /// signed under the old payload shape and carries the all-zero
    /// default). Such grants cannot be signature-verified under the new
    /// scheme and are governed by the daemon's `strict_grant_verify`
    /// policy.
    pub fn is_legacy_unsigned(&self) -> bool {
        self.admin_pubkey == [0u8; 32]
    }

    /// Verify the grant signature against its own embedded
    /// [`Grant::admin_pubkey`]. This authenticates *that the named admin
    /// key signed this exact grant*; the caller is still responsible for
    /// confirming `admin_pubkey` was a cluster-valid admin at
    /// `not_before_ns` (see `AdminKeyState::is_key_valid_at`).
    pub fn verify_admin_signature(&self) -> Result<()> {
        if self.is_legacy_unsigned() {
            return Err(AuthError::SignatureInvalid);
        }
        let key = VerifyingKey::from_bytes(&self.admin_pubkey)
            .map_err(|_| AuthError::SignatureInvalid)?;
        self.verify_signature(&key)
    }

    /// Check temporal validity of the grant.
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

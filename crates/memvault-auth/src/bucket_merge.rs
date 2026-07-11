//! Bucket merge alias record.
//!
//! A [`BucketMergeRecord`] aliases a **source** bucket id onto a
//! **canonical** bucket id. Reads/queries scoped to the canonical return
//! the union of the canonical's own blocks plus every source's blocks;
//! the source's signed blocks are never re-homed or re-signed (their
//! envelope `bucket_id` is part of the signature). See
//! `design-docs/bucket-merge.md`.
//!
//! Unlike a `View`, a merge **changes access**, so the record carries its
//! own authority signature. It is accepted only if `issued_by_pubkey` is,
//! for both source and canonical, a cluster `AgentRole::Admin` agent or
//! the bucket owner (owner agent pubkey / attesting node) — enforced at
//! the storage layer (`LocalClient::bucket_merge_sync`), not here. This
//! type only proves *the named key signed this exact edge*; authority of
//! that key is the caller's responsibility, exactly as with `Grant`.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use memvault_core::BucketId;
use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;

use crate::error::{AuthError, Result};

/// A signed `source → canonical` bucket-merge edge. Stored as a typed
/// side block tagged `("bucket_merge", <source_hex>)` (one record per
/// source), mirroring `View`/grant storage: the stored block IS this
/// struct (DAG-CBOR), not a `Signed<T>` envelope.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BucketMergeRecord {
    /// The bucket whose content is folded into `canonical`.
    pub source: BucketId,
    /// The bucket that surfaces the union and receives new writes.
    pub canonical: BucketId,
    /// Unix nanoseconds at which the merge was authorised.
    pub created_ns: u64,
    /// Admin or bucket-owner pubkey that authorised the merge. Bound into
    /// [`BucketMergeRecord::signing_bytes`] so the signer is authenticated.
    pub issued_by_pubkey: [u8; 32],
    /// Ed25519 signature over [`BucketMergeRecord::signing_bytes`].
    #[serde(with = "BigArray")]
    pub signature: [u8; 64],
}

#[derive(Serialize)]
struct BucketMergeSigningPayload<'a> {
    source: &'a BucketId,
    canonical: &'a BucketId,
    created_ns: u64,
    issued_by_pubkey: &'a [u8; 32],
}

impl BucketMergeRecord {
    /// Compute the canonical bytes the issuer signs.
    pub fn signing_bytes(&self) -> Result<Vec<u8>> {
        let payload = BucketMergeSigningPayload {
            source: &self.source,
            canonical: &self.canonical,
            created_ns: self.created_ns,
            issued_by_pubkey: &self.issued_by_pubkey,
        };
        crate::domain_sign(b"memvault/sig/bucket-merge/v1", &payload)
    }

    /// Verify the signature against the embedded `issued_by_pubkey`. This
    /// authenticates *that the named key signed this exact edge*; the
    /// caller must separately confirm that key was an admin or bucket
    /// owner authorised to merge these buckets.
    pub fn verify_signature(&self) -> Result<()> {
        let bytes = self.signing_bytes()?;
        let sig = Signature::from_bytes(&self.signature);
        let pubkey = VerifyingKey::from_bytes(&self.issued_by_pubkey)
            .map_err(|_| AuthError::SignatureInvalid)?;
        pubkey
            .verify(&bytes, &sig)
            .map_err(|_| AuthError::SignatureInvalid)
    }
}

/// Build and sign a [`BucketMergeRecord`] under `issuer_key` (an admin or
/// bucket-owner key). `created_ns` is passed in so callers control the
/// timestamp (and so it is deterministic in tests).
pub fn sign_bucket_merge(
    issuer_key: &SigningKey,
    source: BucketId,
    canonical: BucketId,
    created_ns: u64,
) -> Result<BucketMergeRecord> {
    let mut rec = BucketMergeRecord {
        source,
        canonical,
        created_ns,
        issued_by_pubkey: issuer_key.verifying_key().to_bytes(),
        signature: [0u8; 64],
    };
    let bytes = rec.signing_bytes()?;
    rec.signature = issuer_key.sign(&bytes).to_bytes();
    Ok(rec)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::RngCore;

    fn make_key() -> SigningKey {
        let mut seed = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut seed);
        SigningKey::from_bytes(&seed)
    }

    fn bid(b: u8) -> BucketId {
        BucketId([b; 32])
    }

    #[test]
    fn roundtrip_sign_verify() {
        let issuer = make_key();
        let rec = sign_bucket_merge(&issuer, bid(1), bid(2), 42).unwrap();
        assert_eq!(rec.issued_by_pubkey, issuer.verifying_key().to_bytes());
        assert_eq!(rec.source, bid(1));
        assert_eq!(rec.canonical, bid(2));
        rec.verify_signature().unwrap();
    }

    #[test]
    fn rejects_tampered_canonical() {
        let issuer = make_key();
        let mut rec = sign_bucket_merge(&issuer, bid(1), bid(2), 42).unwrap();
        rec.canonical = bid(9);
        assert!(rec.verify_signature().is_err());
    }

    #[test]
    fn rejects_tampered_source() {
        let issuer = make_key();
        let mut rec = sign_bucket_merge(&issuer, bid(1), bid(2), 42).unwrap();
        rec.source = bid(9);
        assert!(rec.verify_signature().is_err());
    }

    #[test]
    fn rejects_wrong_signer() {
        let issuer = make_key();
        let other = make_key();
        let mut rec = sign_bucket_merge(&issuer, bid(1), bid(2), 42).unwrap();
        // Claim a different issuer without holding their key.
        rec.issued_by_pubkey = other.verifying_key().to_bytes();
        assert!(rec.verify_signature().is_err());
    }

    /// The record must survive a DAG-CBOR round-trip with stable signing
    /// bytes so a signed merge still verifies after sync.
    #[test]
    fn dagcbor_round_trip_stable_signing_bytes() {
        let issuer = make_key();
        let rec = sign_bucket_merge(&issuer, bid(3), bid(7), 99).unwrap();
        let bytes = serde_ipld_dagcbor::to_vec(&rec).expect("encode");
        let decoded: BucketMergeRecord = serde_ipld_dagcbor::from_slice(&bytes).expect("decode");
        assert_eq!(
            rec.signing_bytes().unwrap(),
            decoded.signing_bytes().unwrap()
        );
        decoded.verify_signature().unwrap();
    }
}

//! Multi-admin key management envelopes.
//!
//! The cluster's root of trust is a single **anchor** admin key, pinned
//! out-of-band at genesis/join (see `AdminGenesis` + the pinned
//! `cluster_admin_genesis.cbor`). Additional operators are admitted as
//! co-equal admins via [`AdminKeyAdmission`] envelopes that chain back to
//! the anchor, and removed via [`AdminKeyRetirement`].
//!
//! ## Why not reuse [`crate::AdminKeyRotation`]?
//!
//! Rotation requires *both* the old and new key to sign the *same*
//! payload, which forces the incoming key to be online during the
//! ceremony. Admission only needs a **proof of possession** (POP) the
//! new operator can produce offline, plus the admitting admin's
//! signature. Rotation stays for 1-for-1 key replacement; admission is
//! the multi-admin path.
//!
//! ## Trust-chain validation (security-critical)
//!
//! Admin state is **always** rebuilt by a full, deterministically-sorted
//! rescan — never applied incrementally from arrival order — so that a
//! retirement can never be observed before the admission that introduced
//! its target (which would otherwise leave a retired key valid). Each
//! envelope's signer must be a key that is valid *at that envelope's
//! timestamp* according to the state built so far, anchored at the
//! pinned genesis key. A non-admin therefore cannot inject either
//! envelope: they hold no key that is valid in the chain. See
//! `memvault_api::sigchain::rebuild_admin_key_state`.

use cid::Cid;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use memvault_core::ClusterId;
use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;

use crate::error::{AuthError, Result};

/// Domain separator for the proof-of-possession signature. Versioned so
/// the POP format can evolve without colliding with old signatures.
const POP_DOMAIN: &[u8] = b"memvault/admin-key-pop/v1";

/// Compute the canonical proof-of-possession bytes a prospective admin
/// signs to prove they hold the secret for `new_pubkey` and intend to be
/// an admin of `cluster_id`. Generated offline by the incoming operator;
/// shared out-of-band with an existing admin who then issues the
/// [`AdminKeyAdmission`].
/// `pop_not_after_ns` is bound into the POP and the admission so a
/// captured POP cannot be reused indefinitely: the admitting admin must
/// issue the admission (and the rescan must accept it) before this
/// deadline, which the incoming operator chooses when generating the POP.
pub fn admin_pop_signing_bytes(
    cluster_id: &ClusterId,
    new_pubkey: &[u8; 32],
    pop_not_after_ns: u64,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(POP_DOMAIN.len() + 32 + 32 + 8);
    out.extend_from_slice(POP_DOMAIN);
    out.extend_from_slice(&cluster_id.0);
    out.extend_from_slice(new_pubkey);
    out.extend_from_slice(&pop_not_after_ns.to_be_bytes());
    out
}

/// Produce a proof-of-possession signature with the incoming admin's
/// key, valid until `pop_not_after_ns`. The operator runs this offline
/// and hands the resulting 64 bytes (plus their pubkey and the expiry)
/// to an existing admin.
pub fn sign_admin_pop(
    new_key: &SigningKey,
    cluster_id: &ClusterId,
    pop_not_after_ns: u64,
) -> [u8; 64] {
    let bytes = admin_pop_signing_bytes(
        cluster_id,
        &new_key.verifying_key().to_bytes(),
        pop_not_after_ns,
    );
    new_key.sign(&bytes).to_bytes()
}

/// Verify a proof-of-possession signature against the claimed new pubkey
/// and expiry.
pub fn verify_admin_pop(
    cluster_id: &ClusterId,
    new_pubkey: &[u8; 32],
    pop_not_after_ns: u64,
    pop: &[u8; 64],
) -> Result<()> {
    let key = VerifyingKey::from_bytes(new_pubkey).map_err(|_| AuthError::SignatureInvalid)?;
    let bytes = admin_pop_signing_bytes(cluster_id, new_pubkey, pop_not_after_ns);
    let sig = Signature::from_bytes(pop);
    key.verify(&bytes, &sig)
        .map_err(|_| AuthError::SignatureInvalid)
}

/// Admits a new co-equal admin key to the cluster. Signed by an existing
/// admin (`admitting_pubkey`) and accompanied by the incoming admin's
/// POP. Verifiers accept only if `admitting_pubkey` was a cluster-valid
/// admin at `admitted_at_ns` (enforced during the sorted rescan).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminKeyAdmission {
    /// Existing admin authorizing the admission.
    pub admitting_pubkey: [u8; 32],
    /// The admin key being admitted.
    pub new_pubkey: [u8; 32],
    pub cluster_id: ClusterId,
    /// When the new key becomes valid for signing.
    pub valid_from_ns: u64,
    /// When the admission was issued — used for deterministic chain
    /// ordering during rescan and for signer-validity checks.
    pub admitted_at_ns: u64,
    /// POP expiry chosen by the incoming admin; the admission is only
    /// valid if `admitted_at_ns <= pop_not_after_ns`. Bounds replay of a
    /// captured POP.
    pub pop_not_after_ns: u64,
    /// CID of the admin envelope the issuer believed was current, for
    /// audit and tie-breaking. Not hard-required (it may not have synced
    /// yet); ordering security comes from the sorted-rescan +
    /// signer-valid-at-time invariant.
    pub parent: Option<Cid>,
    /// Incoming admin's proof of possession of `new_pubkey`.
    #[serde(with = "BigArray")]
    pub pop: [u8; 64],
    /// Admitting admin's signature over [`AdminKeyAdmission::signing_bytes`].
    #[serde(with = "BigArray")]
    pub signature: [u8; 64],
}

#[derive(Serialize)]
struct AdmissionSigningPayload<'a> {
    admitting_pubkey: &'a [u8; 32],
    new_pubkey: &'a [u8; 32],
    cluster_id: &'a ClusterId,
    valid_from_ns: u64,
    admitted_at_ns: u64,
    pop_not_after_ns: u64,
    parent: &'a Option<Cid>,
    /// Slice view of the 64-byte POP — `[u8; 64]` has no `Serialize`
    /// impl, but a slice does, and it canonicalises identically.
    pop: &'a [u8],
}

impl AdminKeyAdmission {
    pub fn signing_bytes(&self) -> Result<Vec<u8>> {
        let payload = AdmissionSigningPayload {
            admitting_pubkey: &self.admitting_pubkey,
            new_pubkey: &self.new_pubkey,
            cluster_id: &self.cluster_id,
            valid_from_ns: self.valid_from_ns,
            admitted_at_ns: self.admitted_at_ns,
            pop_not_after_ns: self.pop_not_after_ns,
            parent: &self.parent,
            pop: &self.pop[..],
        };
        crate::domain_sign(b"memvault/sig/admin-admission/v1", &payload)
    }

    /// Verify the admitting admin's signature. Does NOT check that
    /// `admitting_pubkey` is currently a valid admin — that is the
    /// caller's job (the rescan checks it against state-at-`admitted_at_ns`).
    pub fn verify_admitting_signature(&self) -> Result<()> {
        let key = VerifyingKey::from_bytes(&self.admitting_pubkey)
            .map_err(|_| AuthError::SignatureInvalid)?;
        let bytes = self.signing_bytes()?;
        let sig = Signature::from_bytes(&self.signature);
        key.verify(&bytes, &sig)
            .map_err(|_| AuthError::SignatureInvalid)
    }

    /// Verify the incoming admin's proof of possession.
    pub fn verify_pop(&self) -> Result<()> {
        verify_admin_pop(
            &self.cluster_id,
            &self.new_pubkey,
            self.pop_not_after_ns,
            &self.pop,
        )
    }

    /// Verify both the admitting signature and the POP. Caller still must
    /// confirm `admitting_pubkey` was admin-valid at `admitted_at_ns` and
    /// that `admitted_at_ns <= pop_not_after_ns` (POP not expired).
    pub fn verify(&self) -> Result<()> {
        self.verify_admitting_signature()?;
        self.verify_pop()
    }
}

/// Build and sign an [`AdminKeyAdmission`].
#[allow(clippy::too_many_arguments)]
pub fn sign_admin_admission(
    admitting_key: &SigningKey,
    new_pubkey: [u8; 32],
    cluster_id: ClusterId,
    valid_from_ns: u64,
    admitted_at_ns: u64,
    pop_not_after_ns: u64,
    parent: Option<Cid>,
    pop: [u8; 64],
) -> Result<AdminKeyAdmission> {
    let mut adm = AdminKeyAdmission {
        admitting_pubkey: admitting_key.verifying_key().to_bytes(),
        new_pubkey,
        cluster_id,
        valid_from_ns,
        admitted_at_ns,
        pop_not_after_ns,
        parent,
        pop,
        signature: [0u8; 64],
    };
    let bytes = adm.signing_bytes()?;
    adm.signature = admitting_key.sign(&bytes).to_bytes();
    Ok(adm)
}

/// Retires an admin key. Signed by a *surviving* admin. Grants signed by
/// the retired key before `retired_at_ns` stay valid (their
/// `not_before_ns` falls inside the key's old validity window); the key
/// can no longer sign anything new. Verifiers enforce that the signer is
/// not the retired key and that at least one signing-valid admin remains
/// afterwards (no admin lockout).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminKeyRetirement {
    /// Surviving admin authorizing the retirement.
    pub retiring_pubkey: [u8; 32],
    /// The admin key being retired.
    pub retired_pubkey: [u8; 32],
    pub cluster_id: ClusterId,
    pub retired_at_ns: u64,
    pub reason: String,
    pub parent: Option<Cid>,
    #[serde(with = "BigArray")]
    pub signature: [u8; 64],
}

#[derive(Serialize)]
struct RetirementSigningPayload<'a> {
    retiring_pubkey: &'a [u8; 32],
    retired_pubkey: &'a [u8; 32],
    cluster_id: &'a ClusterId,
    retired_at_ns: u64,
    reason: &'a str,
    parent: &'a Option<Cid>,
}

impl AdminKeyRetirement {
    pub fn signing_bytes(&self) -> Result<Vec<u8>> {
        let payload = RetirementSigningPayload {
            retiring_pubkey: &self.retiring_pubkey,
            retired_pubkey: &self.retired_pubkey,
            cluster_id: &self.cluster_id,
            retired_at_ns: self.retired_at_ns,
            reason: &self.reason,
            parent: &self.parent,
        };
        crate::domain_sign(b"memvault/sig/admin-retirement/v1", &payload)
    }

    /// Verify the retiring admin's signature. Caller must separately
    /// confirm `retiring_pubkey` was admin-valid at `retired_at_ns`, that
    /// `retiring_pubkey != retired_pubkey`, and that a signing-valid admin
    /// survives.
    pub fn verify_retiring_signature(&self) -> Result<()> {
        let key = VerifyingKey::from_bytes(&self.retiring_pubkey)
            .map_err(|_| AuthError::SignatureInvalid)?;
        let bytes = self.signing_bytes()?;
        let sig = Signature::from_bytes(&self.signature);
        key.verify(&bytes, &sig)
            .map_err(|_| AuthError::SignatureInvalid)
    }
}

/// Build and sign an [`AdminKeyRetirement`].
pub fn sign_admin_retirement(
    retiring_key: &SigningKey,
    retired_pubkey: [u8; 32],
    cluster_id: ClusterId,
    retired_at_ns: u64,
    reason: impl Into<String>,
    parent: Option<Cid>,
) -> Result<AdminKeyRetirement> {
    let mut ret = AdminKeyRetirement {
        retiring_pubkey: retiring_key.verifying_key().to_bytes(),
        retired_pubkey,
        cluster_id,
        retired_at_ns,
        reason: reason.into(),
        parent,
        signature: [0u8; 64],
    };
    let bytes = ret.signing_bytes()?;
    ret.signature = retiring_key.sign(&bytes).to_bytes();
    Ok(ret)
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

    fn cluster() -> ClusterId {
        ClusterId([7u8; 32])
    }

    #[test]
    fn pop_roundtrip() {
        let new = make_key();
        let cid = cluster();
        let pop = sign_admin_pop(&new, &cid, u64::MAX);
        verify_admin_pop(&cid, &new.verifying_key().to_bytes(), u64::MAX, &pop).unwrap();
    }

    #[test]
    fn pop_rejects_wrong_cluster() {
        let new = make_key();
        let pop = sign_admin_pop(&new, &cluster(), u64::MAX);
        let other = ClusterId([9u8; 32]);
        assert!(verify_admin_pop(&other, &new.verifying_key().to_bytes(), u64::MAX, &pop).is_err());
    }

    #[test]
    fn pop_rejects_wrong_expiry() {
        let new = make_key();
        let cid = cluster();
        let pop = sign_admin_pop(&new, &cid, 1000);
        // POP bound to expiry 1000 must not verify under a different expiry.
        assert!(verify_admin_pop(&cid, &new.verifying_key().to_bytes(), 2000, &pop).is_err());
    }

    #[test]
    fn admission_roundtrip() {
        let admin = make_key();
        let new = make_key();
        let cid = cluster();
        let pop = sign_admin_pop(&new, &cid, u64::MAX);
        let adm = sign_admin_admission(
            &admin,
            new.verifying_key().to_bytes(),
            cid,
            100,
            100,
            u64::MAX,
            None,
            pop,
        )
        .unwrap();
        adm.verify().unwrap();
        assert_eq!(adm.admitting_pubkey, admin.verifying_key().to_bytes());
        assert_eq!(adm.new_pubkey, new.verifying_key().to_bytes());
    }

    #[test]
    fn signing_bytes_are_domain_separated() {
        let admin = make_key();
        let cid = cluster();
        let pop = sign_admin_pop(&make_key(), &cid, u64::MAX);
        let adm =
            sign_admin_admission(&admin, [1u8; 32], cid.clone(), 1, 1, u64::MAX, None, pop)
                .unwrap();
        let ret = sign_admin_retirement(&admin, [1u8; 32], cid, 1, "x", None).unwrap();
        // Each type's signed bytes start with its own domain tag, so a
        // signature over one can never verify as the other.
        assert!(
            adm.signing_bytes()
                .unwrap()
                .starts_with(b"memvault/sig/admin-admission/v1")
        );
        assert!(
            ret.signing_bytes()
                .unwrap()
                .starts_with(b"memvault/sig/admin-retirement/v1")
        );
    }

    #[test]
    fn admission_rejects_forged_pop() {
        let admin = make_key();
        let new = make_key();
        let imposter = make_key();
        let cid = cluster();
        // POP signed by a DIFFERENT key than new_pubkey.
        let bad_pop = sign_admin_pop(&imposter, &cid, u64::MAX);
        let adm = sign_admin_admission(
            &admin,
            new.verifying_key().to_bytes(),
            cid,
            100,
            100,
            u64::MAX,
            None,
            bad_pop,
        )
        .unwrap();
        // Admitting signature is valid, but POP must fail.
        adm.verify_admitting_signature().unwrap();
        assert!(adm.verify_pop().is_err());
        assert!(adm.verify().is_err());
    }

    #[test]
    fn admission_rejects_tampered_new_pubkey() {
        let admin = make_key();
        let new = make_key();
        let cid = cluster();
        let pop = sign_admin_pop(&new, &cid, u64::MAX);
        let mut adm = sign_admin_admission(
            &admin,
            new.verifying_key().to_bytes(),
            cid,
            100,
            100,
            u64::MAX,
            None,
            pop,
        )
        .unwrap();
        adm.new_pubkey = make_key().verifying_key().to_bytes();
        assert!(adm.verify_admitting_signature().is_err());
    }

    #[test]
    fn retirement_roundtrip() {
        let surviving = make_key();
        let retired = make_key().verifying_key().to_bytes();
        let ret = sign_admin_retirement(
            &surviving,
            retired,
            cluster(),
            200,
            "offboarding",
            None,
        )
        .unwrap();
        ret.verify_retiring_signature().unwrap();
        assert_eq!(ret.retired_pubkey, retired);
    }

    #[test]
    fn retirement_rejects_tampered_target() {
        let surviving = make_key();
        let retired = make_key().verifying_key().to_bytes();
        let mut ret =
            sign_admin_retirement(&surviving, retired, cluster(), 200, "x", None).unwrap();
        ret.retired_pubkey = make_key().verifying_key().to_bytes();
        assert!(ret.verify_retiring_signature().is_err());
    }
}

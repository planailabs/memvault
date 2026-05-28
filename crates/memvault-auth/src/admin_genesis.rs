//! Cluster admin pubkey of record.
//!
//! Solves the chicken-and-egg problem: every other trust block in the chain
//! is admin-signed and must be verified against admin's pubkey — but peers
//! that didn't run genesis have no way to know which key that is.
//!
//! At genesis the admin publishes a single `AdminGenesis` block, self-signed,
//! into the sigchain. Peers pick it up via RBSR sync and consult it to find
//! the cluster admin pubkey. Self-signature is the only thing we can verify
//! at first contact — the trust root has to ground out somewhere; here.
//!
//! `cluster_id` is bound into the signed payload so an AdminGenesis from
//! cluster X cannot be accepted under cluster Y.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;

use memvault_core::ClusterId;

use crate::error::{AuthError, Result};

/// Self-signed declaration "this is the cluster admin pubkey for cluster X."
/// Published once at genesis; the verifier loads the earliest valid copy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminGenesis {
    /// Cluster this admin pubkey is bound to.
    pub cluster_id: ClusterId,
    /// The admin's ed25519 verifying key.
    pub admin_pubkey: [u8; 32],
    /// Unix nanoseconds the block was issued. Earliest wins on ties — see
    /// [`pick_earliest`].
    pub created_ns: u64,
    /// Ed25519 signature over [`signing_bytes`] using the admin's own
    /// private key.
    #[serde(with = "BigArray")]
    pub signature: [u8; 64],
}

#[derive(Serialize)]
struct AdminGenesisSigningPayload<'a> {
    cluster_id: &'a [u8; 32],
    admin_pubkey: &'a [u8; 32],
    created_ns: u64,
}

impl AdminGenesis {
    /// Canonical bytes the admin signs.
    pub fn signing_bytes(&self) -> Result<Vec<u8>> {
        let payload = AdminGenesisSigningPayload {
            cluster_id: &self.cluster_id.0,
            admin_pubkey: &self.admin_pubkey,
            created_ns: self.created_ns,
        };
        serde_ipld_dagcbor::to_vec(&payload).map_err(|e| AuthError::Codec(e.to_string()))
    }

    /// Verify the self-signature: signature must verify against the
    /// embedded `admin_pubkey`. Caller is responsible for confirming
    /// `cluster_id` matches the cluster they expect.
    pub fn verify_self_signature(&self) -> Result<()> {
        let bytes = self.signing_bytes()?;
        let sig = Signature::from_bytes(&self.signature);
        let pubkey = VerifyingKey::from_bytes(&self.admin_pubkey)
            .map_err(|_| AuthError::SignatureInvalid)?;
        pubkey
            .verify(&bytes, &sig)
            .map_err(|_| AuthError::SignatureInvalid)
    }
}

/// Build and sign an [`AdminGenesis`] with the admin's key.
pub fn sign_admin_genesis(
    admin_key: &SigningKey,
    cluster_id: ClusterId,
    created_ns: u64,
) -> Result<AdminGenesis> {
    let mut g = AdminGenesis {
        cluster_id,
        admin_pubkey: admin_key.verifying_key().to_bytes(),
        created_ns,
        signature: [0u8; 64],
    };
    let bytes = g.signing_bytes()?;
    g.signature = admin_key.sign(&bytes).to_bytes();
    Ok(g)
}

/// Pick the canonical AdminGenesis from a set of candidates. If two
/// genesis blocks for the same cluster exist (e.g. operator mistakenly
/// genesis'd twice), the **earliest** `created_ns` wins — once anyone
/// has stored data signed by admin A, "demoting" A by re-genesis is not
/// observable on the sigchain, so we always agree on the original.
pub fn pick_earliest(candidates: impl IntoIterator<Item = AdminGenesis>) -> Option<AdminGenesis> {
    candidates.into_iter().min_by_key(|g| g.created_ns)
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

    #[test]
    fn roundtrip_sign_verify() {
        let admin = make_key();
        let cluster_id = ClusterId([7u8; 32]);
        let g = sign_admin_genesis(&admin, cluster_id.clone(), 1_000).unwrap();
        assert_eq!(g.admin_pubkey, admin.verifying_key().to_bytes());
        assert_eq!(g.cluster_id.0, cluster_id.0);
        g.verify_self_signature().unwrap();
    }

    #[test]
    fn rejects_tampered_admin_pubkey() {
        let admin = make_key();
        let mut g = sign_admin_genesis(&admin, ClusterId([1u8; 32]), 1).unwrap();
        g.admin_pubkey = make_key().verifying_key().to_bytes();
        assert!(g.verify_self_signature().is_err());
    }

    #[test]
    fn rejects_tampered_cluster_id() {
        let admin = make_key();
        let mut g = sign_admin_genesis(&admin, ClusterId([1u8; 32]), 1).unwrap();
        g.cluster_id = ClusterId([2u8; 32]);
        assert!(g.verify_self_signature().is_err());
    }

    #[test]
    fn pick_earliest_wins() {
        let admin = make_key();
        let cid = ClusterId([3u8; 32]);
        let a = sign_admin_genesis(&admin, cid.clone(), 200).unwrap();
        let b = sign_admin_genesis(&admin, cid.clone(), 100).unwrap();
        let c = sign_admin_genesis(&admin, cid, 300).unwrap();
        let picked = pick_earliest([a, b.clone(), c]).unwrap();
        assert_eq!(picked.created_ns, b.created_ns);
    }
}

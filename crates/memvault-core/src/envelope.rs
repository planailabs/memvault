use cid::Cid;
use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};

use crate::codec;
use crate::error::{Error, Result};
use crate::ids::PeerId;
use crate::tags::Tag;
use crate::visibility::Visibility;

/// The signed envelope wrapping all memvault data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Signed<T> {
    pub version: u8,
    pub payload: T,
    pub author: PeerId,
    pub causal: Vec<Cid>,
    pub provenance: Vec<Cid>,
    pub tags: Vec<Tag>,
    pub visibility: Visibility,
    pub lamport: u64,
    pub wall_ns: u64,
    pub capability: Option<Cid>,
    #[serde(with = "serde_bytes")]
    pub signature: Vec<u8>,
}

/// All fields that are covered by the signature (everything except signature itself).
#[derive(Serialize)]
struct SigningPayload<'a, T: Serialize> {
    version: u8,
    payload: &'a T,
    author: &'a PeerId,
    causal: &'a [Cid],
    provenance: &'a [Cid],
    tags: &'a [Tag],
    visibility: &'a Visibility,
    lamport: u64,
    wall_ns: u64,
    capability: &'a Option<Cid>,
}

impl<T: Serialize + for<'de> Deserialize<'de>> Signed<T> {
    /// Create and sign a new envelope.
    pub fn sign(
        payload: T,
        signing_key: &SigningKey,
        author: PeerId,
        causal: Vec<Cid>,
        provenance: Vec<Cid>,
        tags: Vec<Tag>,
        visibility: Visibility,
        lamport: u64,
        wall_ns: u64,
        capability: Option<Cid>,
    ) -> Result<Self> {
        let signing_payload = SigningPayload {
            version: 1,
            payload: &payload,
            author: &author,
            causal: &causal,
            provenance: &provenance,
            tags: &tags,
            visibility: &visibility,
            lamport,
            wall_ns,
            capability: &capability,
        };

        let bytes = codec::encode(&signing_payload)?;
        let sig = signing_key.sign(&bytes);

        Ok(Self {
            version: 1,
            payload,
            author,
            causal,
            provenance,
            tags,
            visibility,
            lamport,
            wall_ns,
            capability,
            signature: sig.to_bytes().to_vec(),
        })
    }

    /// Verify the signature against the provided verifying key.
    pub fn verify(&self, verifying_key: &VerifyingKey) -> Result<()> {
        let signing_payload = SigningPayload {
            version: self.version,
            payload: &self.payload,
            author: &self.author,
            causal: &self.causal,
            provenance: &self.provenance,
            tags: &self.tags,
            visibility: &self.visibility,
            lamport: self.lamport,
            wall_ns: self.wall_ns,
            capability: &self.capability,
        };

        let bytes = codec::encode(&signing_payload)?;
        let sig_bytes: [u8; 64] = self
            .signature
            .as_slice()
            .try_into()
            .map_err(|_| Error::SignatureInvalid)?;
        let sig = ed25519_dalek::Signature::from_bytes(&sig_bytes);
        verifying_key
            .verify(&bytes, &sig)
            .map_err(|_| Error::SignatureInvalid)
    }

    /// Compute the CID of this envelope (the full signed structure).
    pub fn cid(&self) -> Result<Cid> {
        let bytes = codec::encode(self)?;
        Ok(crate::cid::cid_from_bytes(&bytes))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tags::Tag;

    #[test]
    fn sign_and_verify_roundtrip() {
        let mut secret = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut secret);
        let signing_key = SigningKey::from_bytes(&secret);
        let verifying_key = signing_key.verifying_key();

        let envelope = Signed::sign(
            "hello world".to_string(),
            &signing_key,
            PeerId(verifying_key.as_bytes().to_vec()),
            vec![],
            vec![],
            vec![Tag::new("classification", "internal")],
            Visibility::Internal,
            1,
            crate::time::wall_ns(),
            None,
        )
        .unwrap();

        assert!(envelope.verify(&verifying_key).is_ok());
    }

    #[test]
    fn tampered_payload_fails_verify() {
        let mut secret = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut secret);
        let signing_key = SigningKey::from_bytes(&secret);
        let verifying_key = signing_key.verifying_key();

        let mut envelope = Signed::sign(
            "original".to_string(),
            &signing_key,
            PeerId(verifying_key.as_bytes().to_vec()),
            vec![],
            vec![],
            vec![Tag::new("classification", "public")],
            Visibility::Internal,
            1,
            0,
            None,
        )
        .unwrap();

        envelope.payload = "tampered".to_string();
        assert!(envelope.verify(&verifying_key).is_err());
    }

    #[test]
    fn cid_is_deterministic() {
        let mut secret = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut secret);
        let signing_key = SigningKey::from_bytes(&secret);
        let verifying_key = signing_key.verifying_key();

        let envelope = Signed::sign(
            42u64,
            &signing_key,
            PeerId(verifying_key.as_bytes().to_vec()),
            vec![],
            vec![],
            vec![Tag::new("classification", "confidential")],
            Visibility::Federated,
            5,
            1000,
            None,
        )
        .unwrap();

        let c1 = envelope.cid().unwrap();
        let c2 = envelope.cid().unwrap();
        assert_eq!(c1, c2);
    }
}

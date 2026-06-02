//! Wire encoding helpers — the single place that turns memvault's byte-newtype
//! IDs into the hex strings used on the wire.
//!
//! See `standards/` (api-wire-conventions.md, wire-dtos.md). The rule: a domain
//! type has one wire shape, transmitted with `serde`; IDs are hex strings,
//! never raw `[u8; 32]` JSON arrays. Core ID types and graph block types keep
//! their byte `serde` (load-bearing for dag-cbor CIDs), so API return types
//! carry these `#[serde(with = "…")]` helpers on their ID fields instead.
//!
//! Usage:
//! ```ignore
//! #[serde(with = "crate::wire::hex_id")]            id: BucketId,
//! #[serde(with = "crate::wire::hex_id_opt", default)] cluster_id: Option<ClusterId>,
//! #[serde(with = "crate::wire::hex_array32_opt", default)] pubkey: Option<[u8; 32]>,
//! #[serde(with = "crate::wire::hex_bytes")]         cid: Vec<u8>,
//! ```

use memvault_core::{BucketId, ClusterId, DocId, EdgeId, EntityId};
use serde::{Deserialize, Deserializer, Serializer};

/// A 32-byte ID newtype that round-trips through a lowercase hex string.
pub trait HexId: Sized {
    fn id_bytes(&self) -> [u8; 32];
    fn from_id_bytes(bytes: [u8; 32]) -> Self;
}

macro_rules! impl_hex_id {
    ($($t:ty),* $(,)?) => {$(
        impl HexId for $t {
            fn id_bytes(&self) -> [u8; 32] { self.0 }
            fn from_id_bytes(bytes: [u8; 32]) -> Self { Self(bytes) }
        }
    )*};
}
impl_hex_id!(BucketId, ClusterId, DocId, EdgeId, EntityId);

fn decode_32<E: serde::de::Error>(s: &str) -> Result<[u8; 32], E> {
    let bytes = hex::decode(s).map_err(serde::de::Error::custom)?;
    bytes
        .try_into()
        .map_err(|_| serde::de::Error::custom("expected 32-byte hex id"))
}

/// `#[serde(with = "hex_id")]` for a 32-byte ID newtype.
pub mod hex_id {
    use super::*;

    pub fn serialize<S: Serializer, T: HexId>(v: &T, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(v.id_bytes()))
    }
    pub fn deserialize<'de, D: Deserializer<'de>, T: HexId>(d: D) -> Result<T, D::Error> {
        let s = String::deserialize(d)?;
        Ok(T::from_id_bytes(decode_32(&s)?))
    }
}

/// `#[serde(with = "hex_id_opt")]` for `Option<IdNewtype>`.
pub mod hex_id_opt {
    use super::*;

    pub fn serialize<S: Serializer, T: HexId>(v: &Option<T>, s: S) -> Result<S::Ok, S::Error> {
        match v {
            Some(id) => s.serialize_some(&hex::encode(id.id_bytes())),
            None => s.serialize_none(),
        }
    }
    pub fn deserialize<'de, D: Deserializer<'de>, T: HexId>(d: D) -> Result<Option<T>, D::Error> {
        let opt = Option::<String>::deserialize(d)?;
        match opt {
            Some(s) => Ok(Some(T::from_id_bytes(decode_32(&s)?))),
            None => Ok(None),
        }
    }
}

/// `#[serde(with = "hex_array32_opt")]` for `Option<[u8; 32]>` (e.g. pubkeys).
pub mod hex_array32_opt {
    use super::*;

    pub fn serialize<S: Serializer>(v: &Option<[u8; 32]>, s: S) -> Result<S::Ok, S::Error> {
        match v {
            Some(b) => s.serialize_some(&hex::encode(b)),
            None => s.serialize_none(),
        }
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<[u8; 32]>, D::Error> {
        let opt = Option::<String>::deserialize(d)?;
        match opt {
            Some(s) => Ok(Some(decode_32(&s)?)),
            None => Ok(None),
        }
    }
}

/// `#[serde(with = "hex_bytes")]` for opaque `Vec<u8>` keys (NOT CIDs — use
/// `cid_str` for content identifiers).
pub mod hex_bytes {
    use super::*;

    pub fn serialize<S: Serializer>(v: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(v))
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        hex::decode(s).map_err(serde::de::Error::custom)
    }
}

/// `#[serde(with = "hex_array16")]` for a `[u8; 16]` (e.g. a 16-byte proposal id).
pub mod hex_array16 {
    use super::*;

    pub fn serialize<S: Serializer>(v: &[u8; 16], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(v))
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 16], D::Error> {
        let s = String::deserialize(d)?;
        let bytes = hex::decode(s).map_err(serde::de::Error::custom)?;
        bytes
            .try_into()
            .map_err(|_| serde::de::Error::custom("expected 16-byte hex"))
    }
}

/// `#[serde(with = "peer_hex")]` for a `memvault_core::PeerId`.
///
/// Peer ids are libp2p multihashes; base58 is their canonical form (a FIX
/// noted in standards/). Hex here keeps it a string (never a byte array) in
/// the meantime.
pub mod peer_hex {
    use super::*;
    use memvault_core::PeerId;

    pub fn serialize<S: Serializer>(v: &PeerId, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(&v.0))
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<PeerId, D::Error> {
        let s = String::deserialize(d)?;
        Ok(PeerId(hex::decode(s).map_err(serde::de::Error::custom)?))
    }
}

/// `#[serde(with = "cid_str")]` for a `Vec<u8>` that holds **CID bytes**.
///
/// Encodes as the canonical multibase CID string (`bafy…`) via
/// `memvault_core::cid_*`, per `standards/api-wire-conventions.md` §1b — CIDs
/// are IPLD multihashes, not bare hex.
pub mod cid_str {
    use super::*;

    pub fn serialize<S: Serializer>(v: &[u8], s: S) -> Result<S::Ok, S::Error> {
        let cid = memvault_core::cid_string_from_bytes(v).map_err(serde::ser::Error::custom)?;
        s.serialize_str(&cid)
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        memvault_core::cid_bytes_from_string(&s).map_err(serde::de::Error::custom)
    }
}

/// `#[serde(with = "cid_str_opt")]` for `Option<Vec<u8>>` CID bytes.
pub mod cid_str_opt {
    use super::*;

    pub fn serialize<S: Serializer>(v: &Option<Vec<u8>>, s: S) -> Result<S::Ok, S::Error> {
        match v {
            Some(bytes) => {
                let cid =
                    memvault_core::cid_string_from_bytes(bytes).map_err(serde::ser::Error::custom)?;
                s.serialize_some(&cid)
            }
            None => s.serialize_none(),
        }
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<Vec<u8>>, D::Error> {
        match Option::<String>::deserialize(d)? {
            Some(s) => Ok(Some(
                memvault_core::cid_bytes_from_string(&s).map_err(serde::de::Error::custom)?,
            )),
            None => Ok(None),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use memvault_core::BucketId;

    #[derive(serde::Serialize, serde::Deserialize, PartialEq, Debug)]
    struct Sample {
        #[serde(with = "hex_id")]
        id: BucketId,
        #[serde(with = "cid_str")]
        cid: Vec<u8>,
        #[serde(with = "hex_id_opt", default)]
        cluster: Option<memvault_core::ClusterId>,
    }

    #[test]
    fn hex_id_is_lowercase_hex_not_array() {
        let s = Sample {
            id: BucketId([0xAB; 32]),
            cid: memvault_core::cid_from_bytes(b"hello").to_bytes(),
            cluster: None,
        };
        let json = serde_json::to_value(&s).unwrap();
        assert_eq!(json["id"], "ab".repeat(32));
        assert!(json["id"].is_string(), "ids must be hex strings, not arrays");
    }

    #[test]
    fn cid_field_is_canonical_cid_string_not_hex() {
        let cid_bytes = memvault_core::cid_from_bytes(b"hello").to_bytes();
        let s = Sample { id: BucketId([0; 32]), cid: cid_bytes.clone(), cluster: None };
        let json = serde_json::to_value(&s).unwrap();
        let cid_field = json["cid"].as_str().unwrap();
        // Canonical CIDv1 multibase strings begin with 'b'; never raw hex.
        assert!(cid_field.starts_with('b'), "cid must be a CID string: {cid_field}");
        assert_ne!(cid_field, hex::encode(&cid_bytes), "cid must not be bare hex");
    }

    #[test]
    fn round_trips_through_json() {
        let s = Sample {
            id: BucketId([7; 32]),
            cid: memvault_core::cid_from_bytes(b"x").to_bytes(),
            cluster: Some(memvault_core::ClusterId([9; 32])),
        };
        let json = serde_json::to_string(&s).unwrap();
        let back: Sample = serde_json::from_str(&json).unwrap();
        assert_eq!(s, back);
    }
}

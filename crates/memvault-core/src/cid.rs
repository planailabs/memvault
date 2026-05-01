use cid::Cid;
use multihash_codetable::{Code, MultihashDigest};

use crate::error::{Error, Result};

/// DAG-CBOR codec code for CID.
const DAG_CBOR: u64 = 0x71;

/// Compute a CID from raw bytes using BLAKE3 hash and DAG-CBOR codec.
pub fn cid_from_bytes(data: &[u8]) -> Cid {
    let hash = Code::Blake3_256.digest(data);
    Cid::new_v1(DAG_CBOR, hash)
}

/// Compute a CID from a serializable value (encodes to DAG-CBOR first).
pub fn cid_from_value<T: serde::Serialize>(value: &T) -> Result<Cid> {
    let bytes = crate::codec::encode(value)?;
    Ok(cid_from_bytes(&bytes))
}

/// Encode a CID to its base58btc string representation.
pub fn cid_to_string(cid: &Cid) -> String {
    cid.to_string()
}

/// Parse a CID from a string.
pub fn cid_from_string(s: &str) -> Result<Cid> {
    s.parse::<Cid>().map_err(|e| Error::Cid(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_cid() {
        let data = b"hello memvault";
        let c1 = cid_from_bytes(data);
        let c2 = cid_from_bytes(data);
        assert_eq!(c1, c2);
    }

    #[test]
    fn different_data_different_cid() {
        let c1 = cid_from_bytes(b"aaa");
        let c2 = cid_from_bytes(b"bbb");
        assert_ne!(c1, c2);
    }

    #[test]
    fn string_roundtrip() {
        let c = cid_from_bytes(b"test");
        let s = cid_to_string(&c);
        let parsed = cid_from_string(&s).unwrap();
        assert_eq!(c, parsed);
    }
}

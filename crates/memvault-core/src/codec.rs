use crate::error::{Error, Result};
use serde::{Serialize, de::DeserializeOwned};

/// Encode a value to DAG-CBOR bytes.
pub fn encode<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    serde_ipld_dagcbor::to_vec(value).map_err(|e| Error::Codec(e.to_string()))
}

/// Decode DAG-CBOR bytes to a value.
pub fn decode<T: DeserializeOwned>(bytes: &[u8]) -> Result<T> {
    serde_ipld_dagcbor::from_slice(bytes).map_err(|e| Error::Codec(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::{Deserialize, Serialize};

    #[derive(Debug, PartialEq, Serialize, Deserialize)]
    struct TestStruct {
        name: String,
        value: u64,
    }

    #[test]
    fn roundtrip() {
        let original = TestStruct {
            name: "hello".into(),
            value: 42,
        };
        let bytes = encode(&original).unwrap();
        let decoded: TestStruct = decode(&bytes).unwrap();
        assert_eq!(original, decoded);
    }
}

//! Property-based fuzz tests for the DAG-CBOR codec.

use rand::Rng;

/// Property test: arbitrary bytes should not panic the DAG-CBOR decoder.
/// It may return an error, but should never panic.
#[test]
fn fuzz_dagcbor_decode_does_not_panic() {
    let mut rng = rand::thread_rng();

    for _ in 0..10_000 {
        let len = rng.gen_range(0..1024);
        let data: Vec<u8> = (0..len).map(|_| rng.r#gen()).collect();
        // Should not panic — errors are fine
        let _ = memvault_core::codec::decode::<serde_json::Value>(&data);
    }
}

/// Property test: encode then decode should round-trip.
#[test]
fn fuzz_encode_decode_roundtrip() {
    let mut rng = rand::thread_rng();

    for _ in 0..1_000 {
        let value = random_json_value(&mut rng, 3);
        let encoded = memvault_core::codec::encode(&value).unwrap();
        let decoded: serde_json::Value = memvault_core::codec::decode(&encoded).unwrap();
        assert_eq!(value, decoded);
    }
}

fn random_json_value(rng: &mut impl Rng, depth: usize) -> serde_json::Value {
    if depth == 0 {
        return random_leaf(rng);
    }

    match rng.gen_range(0..6) {
        0 => serde_json::Value::Null,
        1 => serde_json::Value::Bool(rng.r#gen()),
        2 => {
            // Integer (DAG-CBOR roundtrips integers, not floats)
            let n: i64 = rng.gen_range(-1_000_000..1_000_000);
            serde_json::Value::Number(n.into())
        }
        3 => {
            // String
            let len = rng.gen_range(0..32);
            let s: String = (0..len)
                .map(|_| rng.gen_range(b'a'..=b'z') as char)
                .collect();
            serde_json::Value::String(s)
        }
        4 => {
            // Array
            let len = rng.gen_range(0..4);
            let arr: Vec<serde_json::Value> = (0..len)
                .map(|_| random_json_value(rng, depth - 1))
                .collect();
            serde_json::Value::Array(arr)
        }
        5 => {
            // Object
            let len = rng.gen_range(0..4);
            let mut map = serde_json::Map::new();
            for _ in 0..len {
                let key_len = rng.gen_range(1..8);
                let key: String = (0..key_len)
                    .map(|_| rng.gen_range(b'a'..=b'z') as char)
                    .collect();
                map.insert(key, random_json_value(rng, depth - 1));
            }
            serde_json::Value::Object(map)
        }
        _ => unreachable!(),
    }
}

fn random_leaf(rng: &mut impl Rng) -> serde_json::Value {
    match rng.gen_range(0..4) {
        0 => serde_json::Value::Null,
        1 => serde_json::Value::Bool(rng.r#gen()),
        2 => {
            let n: i64 = rng.gen_range(-1000..1000);
            serde_json::Value::Number(n.into())
        }
        3 => {
            let len = rng.gen_range(0..16);
            let s: String = (0..len)
                .map(|_| rng.gen_range(b'a'..=b'z') as char)
                .collect();
            serde_json::Value::String(s)
        }
        _ => unreachable!(),
    }
}

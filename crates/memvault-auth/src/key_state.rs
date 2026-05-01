use std::collections::BTreeMap;

use cid::Cid;
use serde::{Deserialize, Serialize};

use crate::rotation::AdminKeyRotation;

/// Tracks the validity window of a single admin key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyValidity {
    pub valid_from_ns: u64,
    /// `u64::MAX` means the key is still active.
    pub valid_until_ns: u64,
    /// The rotation record that introduced this key, if any.
    pub introduced_by: Option<Cid>,
}

impl KeyValidity {
    /// Check if this key is valid at a given time.
    pub fn valid_at(&self, time_ns: u64) -> bool {
        time_ns >= self.valid_from_ns && time_ns <= self.valid_until_ns
    }
}

/// Tracks all admin keys for a cluster and their validity windows.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AdminKeyState {
    pub keys: BTreeMap<[u8; 32], KeyValidity>,
}

impl AdminKeyState {
    /// Create a new state with an initial bootstrap key.
    pub fn new_with_bootstrap(key: [u8; 32], valid_from_ns: u64) -> Self {
        let mut keys = BTreeMap::new();
        keys.insert(
            key,
            KeyValidity {
                valid_from_ns,
                valid_until_ns: u64::MAX,
                introduced_by: None,
            },
        );
        Self { keys }
    }

    /// Apply a key rotation, updating the old key's validity window and adding the new key.
    pub fn apply_rotation(&mut self, rotation: &AdminKeyRotation, rotation_cid: Option<Cid>) {
        // End the old key's validity at the overlap deadline.
        if let Some(old_entry) = self.keys.get_mut(&rotation.old_key) {
            old_entry.valid_until_ns = rotation.overlap_until_ns;
        }

        // Insert the new key starting from valid_from_ns.
        self.keys.insert(
            rotation.new_key,
            KeyValidity {
                valid_from_ns: rotation.valid_from_ns,
                valid_until_ns: u64::MAX,
                introduced_by: rotation_cid,
            },
        );
    }

    /// Find any key that is valid at the given time.
    pub fn valid_keys_at(&self, time_ns: u64) -> Vec<[u8; 32]> {
        self.keys
            .iter()
            .filter(|(_, v)| v.valid_at(time_ns))
            .map(|(k, _)| *k)
            .collect()
    }

    /// Check if a specific key is valid at the given time.
    pub fn is_key_valid_at(&self, key: &[u8; 32], time_ns: u64) -> bool {
        self.keys.get(key).is_some_and(|v| v.valid_at(time_ns))
    }
}

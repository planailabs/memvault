use std::collections::BTreeMap;

use cid::Cid;
use serde::{Deserialize, Serialize};

use crate::admin_keys::{AdminKeyAdmission, AdminKeyRetirement};
use crate::rotation::AdminKeyRotation;

/// Tracks the validity window of a single admin key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyValidity {
    pub valid_from_ns: u64,
    /// `u64::MAX` means the key is still active.
    pub valid_until_ns: u64,
    /// The rotation/admission record that introduced this key, if any.
    pub introduced_by: Option<Cid>,
}

impl KeyValidity {
    /// Check if this key is valid at a given time.
    pub fn valid_at(&self, time_ns: u64) -> bool {
        time_ns >= self.valid_from_ns && time_ns <= self.valid_until_ns
    }
}

/// Tracks all admin keys for a cluster and their validity windows.
///
/// The `anchor` key is the genesis/pinned root of trust. It remains the
/// chain-validation root even after its *signing* validity ends — but it
/// is just another entry in `keys` for `valid_at` purposes. The
/// distinction matters for the "cannot retire the last signing-valid
/// admin" invariant enforced at rebuild time.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AdminKeyState {
    pub keys: BTreeMap<[u8; 32], KeyValidity>,
    /// The genesis/pinned admin pubkey, if known. Trust root for the
    /// admission chain.
    pub anchor: Option<[u8; 32]>,
}

impl AdminKeyState {
    /// Create a new state with an initial bootstrap (anchor) key.
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
        Self {
            keys,
            anchor: Some(key),
        }
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

    /// Apply an admin-key admission: add `new_pubkey` as a co-equal admin
    /// valid from `valid_from_ns`. Idempotent on the key identity — a
    /// repeat admission keeps the earliest `valid_from_ns` so an attacker
    /// cannot push a key's validity *later* by re-admitting it.
    pub fn apply_admission(&mut self, admission: &AdminKeyAdmission, admission_cid: Option<Cid>) {
        self.keys
            .entry(admission.new_pubkey)
            .and_modify(|e| {
                if admission.valid_from_ns < e.valid_from_ns {
                    e.valid_from_ns = admission.valid_from_ns;
                }
            })
            .or_insert(KeyValidity {
                valid_from_ns: admission.valid_from_ns,
                valid_until_ns: u64::MAX,
                introduced_by: admission_cid,
            });
    }

    /// Apply an admin-key retirement: cap the retired key's validity at
    /// `retired_at_ns`. Only shortens — a later retirement cannot *extend*
    /// a window, and re-applying keeps the earliest retirement time.
    pub fn apply_retirement(&mut self, retirement: &AdminKeyRetirement) {
        if let Some(entry) = self.keys.get_mut(&retirement.retired_pubkey) {
            if retirement.retired_at_ns < entry.valid_until_ns {
                entry.valid_until_ns = retirement.retired_at_ns;
            }
        }
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

    /// Count keys whose validity window is still open at `time_ns`. Used
    /// by the retirement invariant ("at least one signing-valid admin
    /// must survive").
    pub fn signing_valid_count_at(&self, time_ns: u64) -> usize {
        self.keys.values().filter(|v| v.valid_at(time_ns)).count()
    }
}

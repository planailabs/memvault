//! Federation protocol logic for cross-cluster cooperation.

use std::collections::BTreeMap;

use memvault_core::Visibility;
use serde::{Deserialize, Serialize};

/// Announcements sent over federation gossipsub topics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FederationAnnouncement {
    /// A new document head is available for federated sharing.
    HeadAvailable {
        head_cid: Vec<u8>,
        visibility: Visibility,
        scope_tags: Vec<(String, String)>,
        /// Bucket this head belongs to (added B3). None = default bucket.
        #[serde(default)]
        bucket_id: Option<Vec<u8>>,
    },
    /// A new grant was issued for cross-cluster access.
    GrantIssued { grant_cid: Vec<u8> },
    /// A grant was revoked.
    GrantRevoked { revocation_cid: Vec<u8> },
    /// Trust relationship revoked.
    TrustRevoked { revocation_cid: Vec<u8> },
    /// Admin key rotation in the originating cluster.
    AdminKeyRotated { rotation_cid: Vec<u8> },
    // ── Bucket federation (added B3) ────────────────────────────
    /// A cross-cluster BucketTrust was established.
    BucketTrustEstablished { trust_cid: Vec<u8> },
    /// A cross-cluster BucketTrust was revoked.
    BucketTrustRevoked { revocation_cid: Vec<u8> },
}

/// Information about a trusted remote cluster.
#[derive(Debug, Clone)]
pub struct TrustedClusterInfo {
    pub cluster_id: Vec<u8>,
    pub admin_keys: Vec<[u8; 32]>,
    pub federated_since_ns: u64,
    pub not_after_ns: u64,
}

/// Tracks trusted clusters and federation state for the local node.
pub struct FederationState {
    pub local_cluster_id: Vec<u8>,
    pub trusted_clusters: BTreeMap<Vec<u8>, TrustedClusterInfo>,
}

impl FederationState {
    pub fn new(local_cluster_id: Vec<u8>) -> Self {
        Self {
            local_cluster_id,
            trusted_clusters: BTreeMap::new(),
        }
    }

    pub fn add_trust(&mut self, info: TrustedClusterInfo) {
        self.trusted_clusters.insert(info.cluster_id.clone(), info);
    }

    pub fn remove_trust(&mut self, cluster_id: &[u8]) {
        self.trusted_clusters.remove(cluster_id);
    }

    pub fn is_trusted(&self, cluster_id: &[u8]) -> bool {
        self.trusted_clusters.contains_key(cluster_id)
    }

    pub fn update_admin_keys(&mut self, cluster_id: &[u8], new_keys: Vec<[u8; 32]>) {
        if let Some(info) = self.trusted_clusters.get_mut(cluster_id) {
            info.admin_keys = new_keys;
        }
    }

    pub fn get_trust(&self, cluster_id: &[u8]) -> Option<&TrustedClusterInfo> {
        self.trusted_clusters.get(cluster_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_add_remove_trust() {
        let mut state = FederationState::new(b"local-cluster".to_vec());

        let info = TrustedClusterInfo {
            cluster_id: b"remote-cluster".to_vec(),
            admin_keys: vec![[1u8; 32]],
            federated_since_ns: 1000,
            not_after_ns: 9999,
        };

        state.add_trust(info);
        assert!(state.is_trusted(b"remote-cluster"));
        assert!(!state.is_trusted(b"unknown-cluster"));

        state.remove_trust(b"remote-cluster");
        assert!(!state.is_trusted(b"remote-cluster"));
    }

    #[test]
    fn test_update_admin_keys() {
        let mut state = FederationState::new(b"local".to_vec());
        state.add_trust(TrustedClusterInfo {
            cluster_id: b"remote".to_vec(),
            admin_keys: vec![[1u8; 32]],
            federated_since_ns: 0,
            not_after_ns: u64::MAX,
        });

        state.update_admin_keys(b"remote", vec![[2u8; 32], [3u8; 32]]);
        let trust = state.get_trust(b"remote").unwrap();
        assert_eq!(trust.admin_keys.len(), 2);
        assert_eq!(trust.admin_keys[0], [2u8; 32]);
    }

    #[test]
    fn test_get_trust() {
        let mut state = FederationState::new(b"local".to_vec());
        assert!(state.get_trust(b"nope").is_none());

        state.add_trust(TrustedClusterInfo {
            cluster_id: b"peer".to_vec(),
            admin_keys: vec![],
            federated_since_ns: 42,
            not_after_ns: 100,
        });

        let info = state.get_trust(b"peer").unwrap();
        assert_eq!(info.federated_since_ns, 42);
    }

    #[test]
    fn test_announcement_serde_roundtrip() {
        let announcements = vec![
            FederationAnnouncement::HeadAvailable {
                head_cid: b"cid123".to_vec(),
                visibility: Visibility::Federated,
                scope_tags: vec![("ns".into(), "docs".into())],
                bucket_id: None,
            },
            FederationAnnouncement::GrantIssued {
                grant_cid: b"grant1".to_vec(),
            },
            FederationAnnouncement::GrantRevoked {
                revocation_cid: b"rev1".to_vec(),
            },
            FederationAnnouncement::TrustRevoked {
                revocation_cid: b"rev2".to_vec(),
            },
            FederationAnnouncement::AdminKeyRotated {
                rotation_cid: b"rot1".to_vec(),
            },
        ];

        for ann in &announcements {
            let encoded = serde_ipld_dagcbor::to_vec(ann).unwrap();
            let decoded: FederationAnnouncement = serde_ipld_dagcbor::from_slice(&encoded).unwrap();
            // Verify basic structure preserved
            match (ann, &decoded) {
                (FederationAnnouncement::HeadAvailable { head_cid, .. },
                 FederationAnnouncement::HeadAvailable { head_cid: decoded_cid, .. }) => {
                    assert_eq!(head_cid, decoded_cid);
                }
                (FederationAnnouncement::GrantIssued { grant_cid },
                 FederationAnnouncement::GrantIssued { grant_cid: decoded_cid }) => {
                    assert_eq!(grant_cid, decoded_cid);
                }
                (FederationAnnouncement::GrantRevoked { revocation_cid },
                 FederationAnnouncement::GrantRevoked { revocation_cid: decoded_cid }) => {
                    assert_eq!(revocation_cid, decoded_cid);
                }
                (FederationAnnouncement::TrustRevoked { revocation_cid },
                 FederationAnnouncement::TrustRevoked { revocation_cid: decoded_cid }) => {
                    assert_eq!(revocation_cid, decoded_cid);
                }
                (FederationAnnouncement::AdminKeyRotated { rotation_cid },
                 FederationAnnouncement::AdminKeyRotated { rotation_cid: decoded_cid }) => {
                    assert_eq!(rotation_cid, decoded_cid);
                }
                _ => panic!("variant mismatch after roundtrip"),
            }
        }
    }
}

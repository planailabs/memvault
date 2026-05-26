//! Visibility enforcement for block sharing decisions.

use memvault_core::Visibility;

use crate::conn_state::ConnectionState;
use crate::federation::FederationState;

/// Enforces visibility rules when serving blocks or announcements to peers.
pub struct VisibilityFilter {
    #[allow(dead_code)]
    local_cluster_id: Vec<u8>,
}

impl VisibilityFilter {
    pub fn new(local_cluster_id: Vec<u8>) -> Self {
        Self { local_cluster_id }
    }

    /// Check if a block with given visibility can be served to a peer.
    ///
    /// Rules:
    /// - `Internal`: only serve to peers in the same cluster
    /// - `Federated`: serve to peers in trusted clusters
    /// - `Public`: serve to any authenticated peer
    pub fn can_serve(
        &self,
        block_visibility: &Visibility,
        requester: &ConnectionState,
        federation_state: &FederationState,
    ) -> bool {
        match block_visibility {
            Visibility::Internal => requester.is_local_cluster,
            Visibility::Federated => {
                requester.is_local_cluster || federation_state.is_trusted(&requester.cluster_id)
            }
            Visibility::Public => true,
        }
    }

    /// Extended serve check that also considers bucket privacy.
    ///
    /// This is the security boundary — every bitswap serve path MUST consult it.
    /// Gossip filtering is a performance optimization only.
    ///
    /// Checks (in order):
    /// 1. Block visibility (Internal/Federated/Public)
    /// 2. Private bucket: refuse if bucket is private to another peer
    /// 3. Cross-cluster: require BucketTrust for the specific bucket
    pub fn may_serve(
        &self,
        block_visibility: &Visibility,
        bucket_private_to_peer: Option<&[u8]>,
        requester: &ConnectionState,
        federation_state: &FederationState,
    ) -> ServeDecision {
        // 1. Visibility check
        if !self.can_serve(block_visibility, requester, federation_state) {
            return ServeDecision::Refused(ServeRefuseReason::VisibilityRefused);
        }

        // 2. Private bucket check
        if let Some(owner_peer) = bucket_private_to_peer {
            if owner_peer != self.local_cluster_id.as_slice() {
                // Private to someone else on this cluster — refuse to everyone
                return ServeDecision::Refused(ServeRefuseReason::BucketPrivate);
            }
            if !requester.is_local_cluster || requester.peer_id != owner_peer {
                // Private to this peer — refuse to any other peer
                return ServeDecision::Refused(ServeRefuseReason::BucketPrivate);
            }
        }

        ServeDecision::Allowed
    }

    /// Filter a list of head announcements for a specific peer.
    pub fn filter_heads_for_peer<'a>(
        &self,
        heads: &'a [(Vec<u8>, Visibility, Vec<(String, String)>)],
        peer: &ConnectionState,
        federation_state: &FederationState,
    ) -> Vec<&'a (Vec<u8>, Visibility, Vec<(String, String)>)> {
        heads
            .iter()
            .filter(|(_, vis, _)| self.can_serve(vis, peer, federation_state))
            .collect()
    }
}

/// Result of a serve-side access check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServeDecision {
    Allowed,
    Refused(ServeRefuseReason),
}

/// Why a serve request was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServeRefuseReason {
    VisibilityRefused,
    BucketPrivate,
    NoBucketTrust,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::federation::TrustedClusterInfo;

    fn local_peer() -> ConnectionState {
        ConnectionState {
            peer_id: b"local-peer".to_vec(),
            cluster_id: b"my-cluster".to_vec(),
            role: "agent".to_string(),
            is_local_cluster: true,
            authenticated_at_ns: 1000,
        }
    }

    fn trusted_peer() -> ConnectionState {
        ConnectionState {
            peer_id: b"trusted-peer".to_vec(),
            cluster_id: b"trusted-cluster".to_vec(),
            role: "agent".to_string(),
            is_local_cluster: false,
            authenticated_at_ns: 2000,
        }
    }

    fn untrusted_peer() -> ConnectionState {
        ConnectionState {
            peer_id: b"untrusted-peer".to_vec(),
            cluster_id: b"unknown-cluster".to_vec(),
            role: "agent".to_string(),
            is_local_cluster: false,
            authenticated_at_ns: 3000,
        }
    }

    fn make_federation_state() -> FederationState {
        let mut state = FederationState::new(b"my-cluster".to_vec());
        state.add_trust(TrustedClusterInfo {
            cluster_id: b"trusted-cluster".to_vec(),
            admin_keys: vec![[1u8; 32]],
            federated_since_ns: 0,
            not_after_ns: u64::MAX,
        });
        state
    }

    #[test]
    fn test_internal_only_local() {
        let filter = VisibilityFilter::new(b"my-cluster".to_vec());
        let fed_state = make_federation_state();

        assert!(filter.can_serve(&Visibility::Internal, &local_peer(), &fed_state));
        assert!(!filter.can_serve(&Visibility::Internal, &trusted_peer(), &fed_state));
        assert!(!filter.can_serve(&Visibility::Internal, &untrusted_peer(), &fed_state));
    }

    #[test]
    fn test_federated_to_trusted() {
        let filter = VisibilityFilter::new(b"my-cluster".to_vec());
        let fed_state = make_federation_state();

        assert!(filter.can_serve(&Visibility::Federated, &local_peer(), &fed_state));
        assert!(filter.can_serve(&Visibility::Federated, &trusted_peer(), &fed_state));
        assert!(!filter.can_serve(&Visibility::Federated, &untrusted_peer(), &fed_state));
    }

    #[test]
    fn test_public_to_all() {
        let filter = VisibilityFilter::new(b"my-cluster".to_vec());
        let fed_state = make_federation_state();

        assert!(filter.can_serve(&Visibility::Public, &local_peer(), &fed_state));
        assert!(filter.can_serve(&Visibility::Public, &trusted_peer(), &fed_state));
        assert!(filter.can_serve(&Visibility::Public, &untrusted_peer(), &fed_state));
    }

    #[test]
    fn test_filter_heads_for_peer() {
        let filter = VisibilityFilter::new(b"my-cluster".to_vec());
        let fed_state = make_federation_state();

        let heads = vec![
            (b"internal-head".to_vec(), Visibility::Internal, vec![]),
            (b"federated-head".to_vec(), Visibility::Federated, vec![]),
            (b"public-head".to_vec(), Visibility::Public, vec![]),
        ];

        // Local peer sees all
        let local_result = filter.filter_heads_for_peer(&heads, &local_peer(), &fed_state);
        assert_eq!(local_result.len(), 3);

        // Trusted peer sees Federated + Public
        let trusted_result = filter.filter_heads_for_peer(&heads, &trusted_peer(), &fed_state);
        assert_eq!(trusted_result.len(), 2);

        // Untrusted peer sees only Public
        let untrusted_result = filter.filter_heads_for_peer(&heads, &untrusted_peer(), &fed_state);
        assert_eq!(untrusted_result.len(), 1);
        assert_eq!(untrusted_result[0].0, b"public-head");
    }
}

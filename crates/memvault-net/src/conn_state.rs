//! Per-connection state tracking for memvault peers.

use std::collections::BTreeMap;

/// State of an authenticated peer connection.
#[derive(Debug, Clone)]
pub struct ConnectionState {
    pub peer_id: Vec<u8>,
    pub cluster_id: Vec<u8>,
    pub role: String,
    pub is_local_cluster: bool,
    pub authenticated_at_ns: u64,
}

/// Registry mapping peer IDs to their connection state.
pub struct ConnectionRegistry {
    connections: BTreeMap<Vec<u8>, ConnectionState>,
}

impl ConnectionRegistry {
    pub fn new() -> Self {
        Self {
            connections: BTreeMap::new(),
        }
    }

    pub fn register(&mut self, peer_id: Vec<u8>, state: ConnectionState) {
        self.connections.insert(peer_id, state);
    }

    pub fn remove(&mut self, peer_id: &[u8]) -> Option<ConnectionState> {
        self.connections.remove(peer_id)
    }

    pub fn get(&self, peer_id: &[u8]) -> Option<&ConnectionState> {
        self.connections.get(peer_id)
    }

    pub fn peers_in_cluster(&self, cluster_id: &[u8]) -> Vec<&ConnectionState> {
        self.connections
            .values()
            .filter(|s| s.cluster_id == cluster_id)
            .collect()
    }

    /// Returns peers that are NOT in the local cluster (federation peers).
    pub fn federation_peers(&self) -> Vec<&ConnectionState> {
        self.connections
            .values()
            .filter(|s| !s.is_local_cluster)
            .collect()
    }

    /// Returns peers that ARE in the local cluster.
    pub fn local_peers(&self) -> Vec<&ConnectionState> {
        self.connections
            .values()
            .filter(|s| s.is_local_cluster)
            .collect()
    }
}

impl Default for ConnectionRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_state(peer_id: &[u8], cluster_id: &[u8], is_local: bool) -> ConnectionState {
        ConnectionState {
            peer_id: peer_id.to_vec(),
            cluster_id: cluster_id.to_vec(),
            role: "agent".to_string(),
            is_local_cluster: is_local,
            authenticated_at_ns: 1000,
        }
    }

    #[test]
    fn test_register_and_get() {
        let mut reg = ConnectionRegistry::new();
        let state = make_state(b"peer1", b"cluster-a", true);
        reg.register(b"peer1".to_vec(), state);

        let got = reg.get(b"peer1").unwrap();
        assert_eq!(got.cluster_id, b"cluster-a");
        assert!(reg.get(b"peer2").is_none());
    }

    #[test]
    fn test_remove() {
        let mut reg = ConnectionRegistry::new();
        reg.register(b"peer1".to_vec(), make_state(b"peer1", b"c", true));

        let removed = reg.remove(b"peer1");
        assert!(removed.is_some());
        assert!(reg.get(b"peer1").is_none());
        assert!(reg.remove(b"peer1").is_none());
    }

    #[test]
    fn test_peers_in_cluster() {
        let mut reg = ConnectionRegistry::new();
        reg.register(b"p1".to_vec(), make_state(b"p1", b"cluster-a", true));
        reg.register(b"p2".to_vec(), make_state(b"p2", b"cluster-a", true));
        reg.register(b"p3".to_vec(), make_state(b"p3", b"cluster-b", false));

        let in_a = reg.peers_in_cluster(b"cluster-a");
        assert_eq!(in_a.len(), 2);

        let in_b = reg.peers_in_cluster(b"cluster-b");
        assert_eq!(in_b.len(), 1);
    }

    #[test]
    fn test_federation_vs_local_peers() {
        let mut reg = ConnectionRegistry::new();
        reg.register(b"local1".to_vec(), make_state(b"local1", b"mine", true));
        reg.register(b"local2".to_vec(), make_state(b"local2", b"mine", true));
        reg.register(b"fed1".to_vec(), make_state(b"fed1", b"theirs", false));
        reg.register(b"fed2".to_vec(), make_state(b"fed2", b"other", false));

        assert_eq!(reg.local_peers().len(), 2);
        assert_eq!(reg.federation_peers().len(), 2);
    }
}

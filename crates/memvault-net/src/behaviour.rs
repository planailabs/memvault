//! Composed `MemvaultBehaviour` for embedding in an external (daemon) swarm.
//!
//! This behaviour includes only the memvault-specific protocols:
//! Kademlia (for peer routing), auth, and join request-response.
//! Ping, identify, mDNS, and gossipsub are expected from the host swarm.

use libp2p::identity::PeerId;
use libp2p::kad;
use libp2p::request_response::{self, ProtocolSupport};
use libp2p::swarm::NetworkBehaviour;
use libp2p::StreamProtocol;

use crate::auth_proto::{AuthCodec, AUTH_PROTOCOL};
use crate::join_proto::{JoinCodec, JOIN_PROTOCOL};

/// Composed behaviour for embedding into an external swarm.
/// Does NOT include ping/identify/mdns/gossipsub — those come from the host.
#[derive(NetworkBehaviour)]
pub struct MemvaultBehaviour {
    pub kad: kad::Behaviour<kad::store::MemoryStore>,
    pub auth: request_response::Behaviour<AuthCodec>,
    pub join: request_response::Behaviour<JoinCodec>,
}

impl MemvaultBehaviour {
    /// Create a new `MemvaultBehaviour` for the given local peer.
    pub fn new(local_peer_id: PeerId) -> Self {
        let kad_store = kad::store::MemoryStore::new(local_peer_id);
        let kad = kad::Behaviour::new(local_peer_id, kad_store);

        let auth = request_response::Behaviour::new(
            [(
                StreamProtocol::new(AUTH_PROTOCOL),
                ProtocolSupport::Full,
            )],
            request_response::Config::default(),
        );

        let join = request_response::Behaviour::new(
            [(
                StreamProtocol::new(JOIN_PROTOCOL),
                ProtocolSupport::Full,
            )],
            request_response::Config::default(),
        );

        Self { kad, auth, join }
    }
}

//! Composed `MemvaultBehaviour` for embedding in an external (daemon) swarm.
//!
//! This behaviour includes only the memvault-specific protocols:
//! Kademlia (for peer routing), auth, join, and block-exchange
//! request-response. Ping, identify, mDNS, and gossipsub are expected from
//! the host swarm — in particular gossipsub is *shared*, since two
//! `gossipsub::Behaviour`s in one swarm would collide on `/meshsub`. The host
//! subscribes its gossipsub to [`crate::gossip::heads_topic`] /
//! [`crate::gossip::admin_topic`] and routes those messages to the driver.
//!
//! The protocol set mirrors [`crate::standalone::StandaloneMemvaultBehaviour`]
//! minus the host-provided behaviours, so the same `memvault-swarm` driver
//! works against either swarm.

use std::time::Duration;

use libp2p::StreamProtocol;
use libp2p::identity::PeerId;
use libp2p::kad;
use libp2p::request_response::{self, ProtocolSupport};
use libp2p::swarm::NetworkBehaviour;

use crate::auth_proto::{AUTH_PROTOCOL, AuthCodec};
use crate::block_proto::{BLOCK_PROTOCOL, BlockCodec};
use crate::join_proto::{JOIN_PROTOCOL, JoinCodec};

/// Composed behaviour for embedding into an external swarm.
/// Does NOT include ping/identify/mdns/gossipsub — those come from the host.
#[derive(NetworkBehaviour)]
pub struct MemvaultBehaviour {
    pub kad: kad::Behaviour<kad::store::MemoryStore>,
    pub auth: request_response::Behaviour<AuthCodec>,
    pub join: request_response::Behaviour<JoinCodec>,
    pub block_exchange: request_response::Behaviour<BlockCodec>,
}

impl MemvaultBehaviour {
    /// Create a new `MemvaultBehaviour` for the given local peer.
    pub fn new(local_peer_id: PeerId) -> Self {
        let kad_store = kad::store::MemoryStore::new(local_peer_id);
        let kad = kad::Behaviour::new(local_peer_id, kad_store);

        let auth = request_response::Behaviour::new(
            [(StreamProtocol::new(AUTH_PROTOCOL), ProtocolSupport::Full)],
            request_response::Config::default(),
        );

        let join = request_response::Behaviour::new(
            [(StreamProtocol::new(JOIN_PROTOCOL), ProtocolSupport::Full)],
            request_response::Config::default(),
        );

        // Mirror the standalone block-exchange config (120s request timeout).
        let block_exchange = request_response::Behaviour::new(
            [(StreamProtocol::new(BLOCK_PROTOCOL), ProtocolSupport::Full)],
            request_response::Config::default().with_request_timeout(Duration::from_secs(120)),
        );

        Self {
            kad,
            auth,
            join,
            block_exchange,
        }
    }
}

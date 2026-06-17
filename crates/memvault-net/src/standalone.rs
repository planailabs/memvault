//! Standalone swarm builder for non-daemon use (e.g. `memctl` CLI).

use libp2p::gossipsub::{self, MessageAuthenticity};
use libp2p::identity::Keypair;
use libp2p::kad;
use libp2p::request_response::{self, ProtocolSupport};
use libp2p::swarm::NetworkBehaviour;
use libp2p::{Multiaddr, StreamProtocol, Swarm, SwarmBuilder};

use crate::auth_proto::{AUTH_PROTOCOL, AuthCodec};
use crate::block_proto::{BLOCK_PROTOCOL, BlockCodec};
use crate::error::NetError;
use crate::gossip;
use crate::join_proto::{JOIN_PROTOCOL, JoinCodec};

/// Standalone behaviour that includes everything needed for independent operation.
#[derive(NetworkBehaviour)]
pub struct StandaloneMemvaultBehaviour {
    pub ping: libp2p::ping::Behaviour,
    pub identify: libp2p::identify::Behaviour,
    pub mdns: libp2p::mdns::tokio::Behaviour,
    pub kad: kad::Behaviour<kad::store::MemoryStore>,
    pub auth: request_response::Behaviour<AuthCodec>,
    pub join: request_response::Behaviour<JoinCodec>,
    pub block_exchange: request_response::Behaviour<BlockCodec>,
    pub gossipsub: gossipsub::Behaviour,
}

/// Build a standalone swarm suitable for CLI tools or tests. `cluster_id`
/// scopes the heads/admin gossip topics so the node meshes only with
/// same-cluster peers (genesis/join happens before this is built, so the
/// id is stable for the swarm's lifetime).
pub async fn standalone_swarm(
    keypair: Keypair,
    listen_addr: Multiaddr,
    bootstrap_peers: Vec<Multiaddr>,
    cluster_id: Vec<u8>,
) -> Result<Swarm<StandaloneMemvaultBehaviour>, NetError> {
    let local_peer_id = keypair.public().to_peer_id();

    let mut swarm = SwarmBuilder::with_existing_identity(keypair.clone())
        .with_tokio()
        .with_tcp(
            Default::default(),
            libp2p::noise::Config::new,
            libp2p::yamux::Config::default,
        )
        .map_err(|e| NetError::Transport(e.to_string()))?
        .with_quic()
        .with_behaviour(|key| {
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

            let block_exchange = request_response::Behaviour::new(
                [(StreamProtocol::new(BLOCK_PROTOCOL), ProtocolSupport::Full)],
                request_response::Config::default()
                    .with_request_timeout(std::time::Duration::from_secs(120)),
            );

            // Enable gossipsub Peer eXchange: on PRUNE a node hands the pruned
            // peer a set of alternative mesh members, so peers discover more of
            // the cluster through the gossip mesh itself (not just mDNS/Kademlia).
            // `prune_peers > 0` is what actually turns PX on for outgoing prunes.
            let gossipsub_config = gossipsub::ConfigBuilder::default()
                .do_px()
                .prune_peers(16)
                .build()
                .map_err(|e| NetError::Gossipsub(e.to_string()))?;
            let mut gs = gossipsub::Behaviour::new(
                MessageAuthenticity::Signed(key.clone()),
                gossipsub_config,
            )
            .map_err(|e| NetError::Gossipsub(e.to_string()))?;

            // Subscribe to the cluster-scoped memvault topics.
            gs.subscribe(&gossip::heads_topic_for(&cluster_id))
                .map_err(|e| NetError::Gossipsub(e.to_string()))?;
            gs.subscribe(&gossip::admin_topic_for(&cluster_id))
                .map_err(|e| NetError::Gossipsub(e.to_string()))?;

            let identify_config =
                libp2p::identify::Config::new("/ai-memvault/id/1.0".to_string(), key.public());
            let identify = libp2p::identify::Behaviour::new(identify_config);

            let mdns =
                libp2p::mdns::tokio::Behaviour::new(libp2p::mdns::Config::default(), local_peer_id)
                    .map_err(|e| NetError::Transport(e.to_string()))?;

            Ok(StandaloneMemvaultBehaviour {
                ping: libp2p::ping::Behaviour::default(),
                identify,
                mdns,
                kad,
                auth,
                join,
                block_exchange,
                gossipsub: gs,
            })
        })
        .map_err(|e| NetError::Transport(e.to_string()))?
        .build();

    swarm
        .listen_on(listen_addr.clone())
        .map_err(|e| NetError::Transport(e.to_string()))?;
    // Also bind QUIC on the same family, and — when the address is a wildcard —
    // the opposite IP family over both transports, so the node is reachable
    // dual-stack (IPv4 + IPv6) and dual-transport (TCP + QUIC), matching the
    // mac-mgmt daemon. Best-effort: IPv6 may be unavailable on the host.
    for addr in companion_listen_addrs(&listen_addr) {
        if let Err(e) = swarm.listen_on(addr.clone()) {
            tracing::warn!(%addr, error = %e, "could not also listen (best-effort)");
        }
    }

    // Seed bootstrap peers: register in Kademlia when the multiaddr carries a
    // /p2p/<peer> component (so bootstrap() has routing entries before Identify
    // completes), then dial.
    for addr in bootstrap_peers {
        if let Some(peer) = addr.iter().find_map(|p| match p {
            libp2p::multiaddr::Protocol::P2p(id) => Some(id),
            _ => None,
        }) {
            swarm.behaviour_mut().kad.add_address(&peer, addr.clone());
        }
        let _ = swarm.dial(addr);
    }

    Ok(swarm)
}

/// Extra listen addresses to bind best-effort alongside a (TCP) listen address:
/// QUIC on the same IP family, plus — when the address is a wildcard — the
/// opposite IP family over both TCP and QUIC. The UDP port mirrors the TCP port
/// (0 = ephemeral). Empty if the address has no leading IP component.
fn companion_listen_addrs(addr: &Multiaddr) -> Vec<Multiaddr> {
    use libp2p::multiaddr::Protocol::{self, Ip4, Ip6, QuicV1, Tcp, Udp};
    use std::net::{Ipv4Addr, Ipv6Addr};

    let Some(ip) = addr.iter().next() else {
        return Vec::new();
    };
    let port = addr.iter().find_map(|p| if let Tcp(n) = p { Some(n) } else { None }).unwrap_or(0);
    let tcp = |f: Protocol| Multiaddr::empty().with(f).with(Tcp(port));
    let quic = |f: Protocol| Multiaddr::empty().with(f).with(Udp(port)).with(QuicV1);

    // QUIC on the requested family (its TCP is already bound by the caller).
    let mut out = vec![quic(ip.clone())];
    // Wildcard → also the opposite family, both transports.
    let companion = match ip {
        Ip4(a) if a.is_unspecified() => Some(Ip6(Ipv6Addr::UNSPECIFIED)),
        Ip6(a) if a.is_unspecified() => Some(Ip4(Ipv4Addr::UNSPECIFIED)),
        _ => None,
    };
    if let Some(f) = companion {
        out.push(tcp(f.clone()));
        out.push(quic(f));
    }
    out
}

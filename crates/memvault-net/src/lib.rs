//! memvault-net: libp2p networking layer for the memvault p2p memory store.
//!
//! Provides two operating modes:
//! - **Composed mode**: `MemvaultBehaviour` for embedding into an external swarm (daemon)
//! - **Standalone mode**: `standalone_swarm()` for independent operation (CLI tools)

pub mod auth_proto;
pub mod behaviour;
pub mod error;
pub mod gossip;
pub mod join_proto;
pub mod standalone;

pub use auth_proto::{AuthCodec, AuthRequest, AuthResponse, AUTH_PROTOCOL};
pub use behaviour::MemvaultBehaviour;
pub use error::NetError;
pub use gossip::{AdminAnnouncement, ADMIN_TOPIC, HEADS_TOPIC};
pub use join_proto::{
    JoinCodec, JoinRefuseReason, JoinRequest, JoinResponse, JoinResult, JOIN_PROTOCOL,
};
pub use standalone::{standalone_swarm, StandaloneMemvaultBehaviour};

//! memvault-net: libp2p networking layer for the memvault p2p memory store.
//!
//! Provides two operating modes:
//! - **Composed mode**: `MemvaultBehaviour` for embedding into an external swarm (daemon)
//! - **Standalone mode**: `standalone_swarm()` for independent operation (CLI tools)

pub mod auth_proto;
pub mod behaviour;
pub mod conn_state;
pub mod error;
pub mod federation;
pub mod gossip;
pub mod join_proto;
pub mod share_proto;
pub mod standalone;
pub mod visibility;

pub use auth_proto::{AuthCodec, AuthRequest, AuthResponse, AUTH_PROTOCOL};
pub use behaviour::MemvaultBehaviour;
pub use conn_state::{ConnectionRegistry, ConnectionState};
pub use error::NetError;
pub use federation::{FederationAnnouncement, FederationState, TrustedClusterInfo};
pub use gossip::{
    AdminAnnouncement, federation_ident_topic, federation_topic, ADMIN_TOPIC,
    FEDERATION_TOPIC_PREFIX, HEADS_TOPIC,
};
pub use join_proto::{
    JoinCodec, JoinRefuseReason, JoinRequest, JoinResponse, JoinResult, JOIN_PROTOCOL,
};
pub use standalone::{standalone_swarm, StandaloneMemvaultBehaviour};
pub use share_proto::{
    ShareCodec, ShareRequest, ShareResponse, ShareResult, SHARE_PROTOCOL,
};
pub use visibility::{ServeDecision, ServeRefuseReason, VisibilityFilter};

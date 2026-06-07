//! memvault-net: libp2p networking layer for the memvault p2p memory store.
//!
//! Provides two operating modes:
//! - **Composed mode**: `MemvaultBehaviour` for embedding into an external swarm (daemon)
//! - **Standalone mode**: `standalone_swarm()` for independent operation (CLI tools)

pub mod auth_proto;
pub mod behaviour;
pub mod block_proto;
pub mod conn_state;
pub mod error;
pub mod federation;
pub mod gossip;
pub mod join_proto;
pub mod share_proto;
pub mod standalone;
pub mod visibility;

pub use auth_proto::{AUTH_PROTOCOL, AuthCodec, AuthRequest, AuthResponse};
pub use behaviour::{MemvaultBehaviour, MemvaultBehaviourEvent};
pub use block_proto::{
    BLOCK_PROTOCOL, BlockAccessToken, BlockCodec, BlockEntry, BlockRequest, BlockResponse,
    RangeFingerprint,
};
pub use conn_state::{ConnectionRegistry, ConnectionState};
pub use error::NetError;
pub use federation::{FederationAnnouncement, FederationState, TrustedClusterInfo};
pub use gossip::{
    ADMIN_TOPIC, AdminAnnouncement, FEDERATION_TOPIC_PREFIX, HEADS_TOPIC, HeadAnnouncement,
    federation_ident_topic, federation_topic,
};
pub use join_proto::{
    JOIN_PROTOCOL, JoinCodec, JoinRefuseReason, JoinRequest, JoinResponse, JoinResult,
};
pub use share_proto::{SHARE_PROTOCOL, ShareCodec, ShareRequest, ShareResponse, ShareResult};
pub use standalone::{
    StandaloneMemvaultBehaviour, StandaloneMemvaultBehaviourEvent, standalone_swarm,
};
pub use visibility::{ServeDecision, ServeRefuseReason, VisibilityFilter};

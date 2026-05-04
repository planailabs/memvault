//! `memvault-api` — Agent-facing API, RPC layer, and client trait for memvault.

pub mod client;
pub mod docs;
pub mod error;
pub mod files;
pub mod health;
pub mod local;
pub mod memctl;
pub mod metrics;
pub mod otel;
pub mod quotas;
pub mod rotation;
pub mod rpc;
pub mod subscription;
pub mod tokens;
pub mod types;
pub mod vfs;

pub use client::MemvaultClient;
pub use error::{ApiError, Result};
pub use local::LocalClient;
pub use subscription::{EventBus, MemvaultEvent};
pub use types::{DocSummary, NodeStatus, RotationInfo, TokenStatus, TraversalHit, View};

//! memvault-smoke — Comprehensive smoke tests for the memvault stack.
//!
//! Tests two independent nodes sharing a cluster_id, exercising every
//! API operation to verify correctness.

pub mod harness;

#[cfg(test)]
mod tests {
    pub mod acl;
    pub mod agent_enrollment;
    pub mod agent_rename;
    pub mod basic;
    pub mod block_sync_divergence;
    pub mod bucket_sync;
    pub mod buckets;
    pub mod docs;
    pub mod entities;
    pub mod files;
    pub mod graph;
    pub mod identity;
    pub mod join_protocol;
    pub mod lifecycle;
    pub mod links;
    pub mod list_visibility;
    pub mod migrations;
    pub mod p2p;
    pub mod sharing;
    pub mod signed_envelope_indexing;
    pub mod tokens;
    pub mod views;
}

//! Sig-chain persistence — node attestations, admin rotations, and
//! agent/node revocations stored as tagged blocks in the blockstore.
//!
//! Blocks written through these helpers participate in the existing RBSR
//! sync (phase 5b — actual peer-to-peer broadcast on create is a follow-up).
//! On startup, the daemon scans the blockstore for these tags and rebuilds
//! its in-memory `node_trust`, `revoked_agents`, and `revoked_nodes` tables.
//!
//! Tag layout (kind / label):
//! - `("sigchain", "node_att")` — values are CBOR-encoded `MembershipAttestation`
//! - `("sigchain", "agent_rev")` — CBOR `AgentRevocation`
//! - `("sigchain", "node_rev")` — CBOR `NodeRevocation`

use std::collections::{HashMap, HashSet};

use crate::error::{ApiError, Result};
use crate::local::LocalClient;
use memvault_auth::jwt::NodeTrust;
use memvault_auth::{AgentRevocation, MembershipAttestation, NodeRevocation};
use memvault_store::insert::EnvelopeMeta;

const KIND: &str = "sigchain";
const LABEL_NODE_ATT: &str = "node_att";
const LABEL_AGENT_REV: &str = "agent_rev";
const LABEL_NODE_REV: &str = "node_rev";

fn write_block(client: &LocalClient, label: &str, bytes: &[u8]) -> Result<Vec<u8>> {
    let cid = memvault_core::cid_from_bytes(bytes);
    let cid_bytes = cid.to_bytes();
    let meta = EnvelopeMeta {
        author: client.peer_id().to_vec(),
        tags: vec![(KIND.to_string(), label.to_string())],
        wall_ns: memvault_core::wall_ns(),
        cluster_id: Some(client.cluster_id().to_vec()),
        ..Default::default()
    };
    client
        .store()
        .insert_envelope(&cid_bytes, bytes, &meta)
        .map_err(|e| ApiError::Other(format!("write {label}: {e}")))?;
    Ok(cid_bytes)
}

/// Persist a node `MembershipAttestation` so it survives daemon restart and
/// can be picked up by other peers via RBSR sync.
pub fn publish_node_attestation(
    client: &LocalClient,
    attestation: &MembershipAttestation,
) -> Result<Vec<u8>> {
    let bytes = serde_ipld_dagcbor::to_vec(attestation)
        .map_err(|e| ApiError::Serialization(e.to_string()))?;
    write_block(client, LABEL_NODE_ATT, &bytes)
}

/// Persist an `AgentRevocation`.
pub fn publish_agent_revocation(
    client: &LocalClient,
    revocation: &AgentRevocation,
) -> Result<Vec<u8>> {
    let bytes = serde_ipld_dagcbor::to_vec(revocation)
        .map_err(|e| ApiError::Serialization(e.to_string()))?;
    write_block(client, LABEL_AGENT_REV, &bytes)
}

/// Persist a `NodeRevocation`.
pub fn publish_node_revocation(
    client: &LocalClient,
    revocation: &NodeRevocation,
) -> Result<Vec<u8>> {
    let bytes = serde_ipld_dagcbor::to_vec(revocation)
        .map_err(|e| ApiError::Serialization(e.to_string()))?;
    write_block(client, LABEL_NODE_REV, &bytes)
}

fn load_blocks_by_label(
    client: &LocalClient,
    label: &str,
) -> Result<Vec<Vec<u8>>> {
    let cids = client
        .store()
        .query_by_tag(KIND, label, 0, usize::MAX)
        .map_err(|e| ApiError::Other(format!("query {label}: {e}")))?;
    let mut out = Vec::with_capacity(cids.len());
    for cid in cids {
        if let Ok(Some(bytes)) = client.store().get_block(&cid) {
            out.push(bytes);
        }
    }
    Ok(out)
}

/// Walk the blockstore and reconstruct the trust map keyed by node pubkey.
/// Each entry is `NodeTrust::Attested(_)`; pre-genesis entries are
/// in-memory only and don't show up here.
pub fn scan_trusted_nodes(client: &LocalClient) -> Result<HashMap<[u8; 32], NodeTrust>> {
    let mut out = HashMap::new();
    for bytes in load_blocks_by_label(client, LABEL_NODE_ATT)? {
        let att: MembershipAttestation = match serde_ipld_dagcbor::from_slice(&bytes) {
            Ok(a) => a,
            Err(e) => {
                tracing::warn!(error = %e, "skipping corrupt node attestation block");
                continue;
            }
        };
        if att.member.0.len() != 32 {
            continue;
        }
        let mut pk = [0u8; 32];
        pk.copy_from_slice(&att.member.0);
        out.insert(pk, NodeTrust::Attested(att));
    }
    Ok(out)
}

/// Walk the blockstore and reconstruct the revoked-agents and revoked-nodes
/// sets. Caller is responsible for verifying signatures against the relevant
/// pubkeys (node for `AgentRevocation`, admin for `NodeRevocation`).
pub fn scan_revocations(
    client: &LocalClient,
) -> Result<(HashSet<[u8; 32]>, HashSet<[u8; 32]>)> {
    let mut agents = HashSet::new();
    let mut nodes = HashSet::new();
    for bytes in load_blocks_by_label(client, LABEL_AGENT_REV)? {
        if let Ok(rev) = serde_ipld_dagcbor::from_slice::<AgentRevocation>(&bytes) {
            agents.insert(rev.agent_pubkey);
        }
    }
    for bytes in load_blocks_by_label(client, LABEL_NODE_REV)? {
        if let Ok(rev) = serde_ipld_dagcbor::from_slice::<NodeRevocation>(&bytes) {
            nodes.insert(rev.node_pubkey);
        }
    }
    Ok((agents, nodes))
}

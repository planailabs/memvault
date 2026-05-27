//! Sig-chain persistence — node attestations, admin rotations, and
//! agent/node revocations stored as tagged blocks in the blockstore.
//!
//! Blocks written through these helpers participate in the existing RBSR
//! sync (phase 5b — actual peer-to-peer broadcast on create is a follow-up).
//! On startup, the daemon scans the blockstore for these tags and rebuilds
//! its in-memory `node_trust`, `revoked_agents`, and `revoked_nodes` tables.
//!
//! Tag layout (kind / label):
//! - `("sigchain", "node_att")` — values are CBOR-encoded `NodeAttestation`
//! - `("sigchain", "agent_rev")` — CBOR `AgentRevocation`
//! - `("sigchain", "node_rev")` — CBOR `NodeRevocation`

use std::collections::{HashMap, HashSet};

use crate::error::{ApiError, Result};
use crate::local::LocalClient;
use memvault_auth::jwt::NodeTrust;
use memvault_auth::{AgentRevocation, NodeAttestation, NodeRevocation};
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

/// Persist a node `NodeAttestation` so it survives daemon restart and
/// can be picked up by other peers via RBSR sync.
pub fn publish_node_attestation(
    client: &LocalClient,
    attestation: &NodeAttestation,
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
/// Each entry is `NodeTrust::Attested(_)`. When `admin_pubkey` is `Some`,
/// each attestation's signature is verified against it; failures are
/// logged and the entry is skipped. When `None` (pre-genesis), unverified
/// entries are dropped — only the local self-trust seed counts.
pub fn scan_trusted_nodes(
    client: &LocalClient,
    admin_pubkey: Option<&ed25519_dalek::VerifyingKey>,
) -> Result<HashMap<[u8; 32], NodeTrust>> {
    let mut out = HashMap::new();
    let Some(pk) = admin_pubkey else {
        // Pre-genesis: no trust root, so no attestation can be verified.
        return Ok(out);
    };
    for bytes in load_blocks_by_label(client, LABEL_NODE_ATT)? {
        let att: NodeAttestation = match serde_ipld_dagcbor::from_slice(&bytes) {
            Ok(a) => a,
            Err(e) => {
                tracing::warn!(error = %e, "skipping corrupt node attestation block");
                continue;
            }
        };
        if let Err(e) = att.verify_signature(pk) {
            tracing::warn!(
                error = %e,
                member = %hex::encode(&att.member.0),
                "skipping node attestation: signature does not verify against current admin"
            );
            continue;
        }
        if att.member.0.len() != 32 {
            continue;
        }
        let mut pkbytes = [0u8; 32];
        pkbytes.copy_from_slice(&att.member.0);
        out.insert(pkbytes, NodeTrust::Attested(att));
    }
    Ok(out)
}

/// Walk the blockstore and reconstruct the revoked-agents and revoked-nodes
/// sets, verifying every revocation signature.
///
/// `node_trust` is the trust map produced by [`scan_trusted_nodes`] — used
/// to look up the issuing node's pubkey when verifying `AgentRevocation`
/// signatures (the revocation must be signed by the same node that
/// originally attested the agent).
///
/// `admin_pubkey` (post-genesis only) verifies `NodeRevocation` signatures.
pub fn scan_revocations(
    client: &LocalClient,
    admin_pubkey: Option<&ed25519_dalek::VerifyingKey>,
    node_trust: &HashMap<[u8; 32], NodeTrust>,
) -> Result<(HashSet<[u8; 32]>, HashSet<[u8; 32]>)> {
    let mut agents = HashSet::new();
    let mut nodes = HashSet::new();

    for bytes in load_blocks_by_label(client, LABEL_AGENT_REV)? {
        let rev: AgentRevocation = match serde_ipld_dagcbor::from_slice(&bytes) {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!(error = %e, "skipping corrupt agent revocation block");
                continue;
            }
        };
        // The revocation must be signed by a node that's currently trusted.
        if !node_trust.contains_key(&rev.node_pubkey) {
            tracing::warn!(
                node = %hex::encode(rev.node_pubkey),
                "skipping agent revocation from unknown node"
            );
            continue;
        }
        if let Err(e) = rev.verify_signature() {
            tracing::warn!(
                error = %e,
                agent = %hex::encode(rev.agent_pubkey),
                "skipping agent revocation: bad signature"
            );
            continue;
        }
        agents.insert(rev.agent_pubkey);
    }

    if let Some(admin_pk) = admin_pubkey {
        for bytes in load_blocks_by_label(client, LABEL_NODE_REV)? {
            let rev: NodeRevocation = match serde_ipld_dagcbor::from_slice(&bytes) {
                Ok(r) => r,
                Err(e) => {
                    tracing::warn!(error = %e, "skipping corrupt node revocation block");
                    continue;
                }
            };
            // Embedded admin_pubkey must match current admin AND signature
            // must verify against it.
            if rev.admin_pubkey != admin_pk.to_bytes() {
                tracing::warn!(
                    node = %hex::encode(rev.node_pubkey),
                    "skipping node revocation: admin_pubkey doesn't match current admin"
                );
                continue;
            }
            if let Err(e) = rev.verify_signature() {
                tracing::warn!(
                    error = %e,
                    node = %hex::encode(rev.node_pubkey),
                    "skipping node revocation: bad signature"
                );
                continue;
            }
            nodes.insert(rev.node_pubkey);
        }
    }

    Ok((agents, nodes))
}

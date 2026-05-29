//! Shape-only detection for sigchain blocks.
//!
//! Recognises a raw CBOR block as one of the known sigchain types by
//! attempting structural deserialization. This lets two callers stay
//! in sync without duplicating per-type CBOR shape checks:
//!
//! - `memvault-swarm::vet_sync_block` — uses detection + per-type
//!   signature verification to gate incoming sync ingress.
//! - `memvault-api::rebuild::rebuild_store` — uses detection alone to
//!   re-tag locally-stored sigchain blocks after a blockstore version
//!   bump (which wipes `BY_TAG`). Trusts the contents because the
//!   block was already in our store, having previously passed either a
//!   local mint or sync's signature check.
//!
//! When adding a new sigchain block type, extend [`SigchainKind`],
//! [`sigchain_label_for`], and [`detect_sigchain_shape`].

use crate::{
    AdminGenesis, AdminKeyAdmission, AdminKeyRetirement, AgentAttestation, AgentRevocation,
    NodeAttestation, NodeRevocation,
};

/// Discriminator for the recognised sigchain block types. Mirrors the
/// `sigchain/<label>` tags emitted by `memvault_api::sigchain::publish_*`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SigchainKind {
    AdminGenesis,
    AdminKeyAdmission,
    AdminKeyRetirement,
    NodeAttestation,
    AgentAttestation,
    AgentRevocation,
    NodeRevocation,
}

impl SigchainKind {
    /// Tag label for this kind — same string `publish_*` writes.
    pub fn label(self) -> &'static str {
        match self {
            Self::AdminGenesis => "admin_genesis",
            Self::AdminKeyAdmission => "admin_admission",
            Self::AdminKeyRetirement => "admin_retirement",
            Self::NodeAttestation => "node_att",
            Self::AgentAttestation => "agent_att",
            Self::AgentRevocation => "agent_rev",
            Self::NodeRevocation => "node_rev",
        }
    }
}

/// Detect the sigchain shape of a CBOR-encoded block, returning the
/// canonical tag label if recognised. Does NOT verify signatures.
///
/// Try-order matters: more-discriminating shapes go first (those with
/// distinguishing required fields). The CBOR shapes are mutually
/// exclusive at the field-name level when there's no `#[serde(rename)]`,
/// so a clean serde_ipld_dagcbor deserialization into the wrong type is
/// unlikely — but the cluster_id / pubkey heuristics add belt-and-braces.
pub fn sigchain_label_for(bytes: &[u8]) -> Option<&'static str> {
    detect_sigchain_shape(bytes).map(SigchainKind::label)
}

/// Like [`sigchain_label_for`], but returns the typed kind. Useful when
/// the caller wants to branch on the shape (e.g. to dispatch
/// signature verification).
pub fn detect_sigchain_shape(bytes: &[u8]) -> Option<SigchainKind> {
    // AdminGenesis: cluster_id + admin_pubkey + created_ns + signature.
    if let Ok(g) = serde_ipld_dagcbor::from_slice::<AdminGenesis>(bytes) {
        // Discriminate: AdminGenesis is the only shape with this exact
        // field set; require admin_pubkey present (non-zero is too
        // strict — admin pubkey could theoretically be zeros in tests).
        if g.cluster_id.0.len() == 32 {
            return Some(SigchainKind::AdminGenesis);
        }
    }
    // AdminKeyAdmission: admitting_pubkey + new_pubkey + pop (unique
    // fields; no other shape carries them).
    if let Ok(adm) = serde_ipld_dagcbor::from_slice::<AdminKeyAdmission>(bytes) {
        if adm.new_pubkey.iter().any(|&b| b != 0) {
            return Some(SigchainKind::AdminKeyAdmission);
        }
    }
    // AdminKeyRetirement: retiring_pubkey + retired_pubkey + reason.
    if let Ok(ret) = serde_ipld_dagcbor::from_slice::<AdminKeyRetirement>(bytes) {
        if ret.retired_pubkey.iter().any(|&b| b != 0) {
            return Some(SigchainKind::AdminKeyRetirement);
        }
    }
    // NodeAttestation: cluster_id + member + role + issued_via.
    if let Ok(att) = serde_ipld_dagcbor::from_slice::<NodeAttestation>(bytes) {
        if !att.member.0.is_empty() {
            return Some(SigchainKind::NodeAttestation);
        }
    }
    // AgentAttestation: node_pubkey + agent_id + agent_pubkey + role.
    if let Ok(att) = serde_ipld_dagcbor::from_slice::<AgentAttestation>(bytes) {
        if !att.agent_id.0.is_empty() {
            return Some(SigchainKind::AgentAttestation);
        }
    }
    // NodeRevocation: admin_pubkey + node_pubkey + reason + revoked_at_ns.
    // Try before AgentRevocation: shapes differ in `admin_pubkey` vs
    // `node_pubkey` field name pair — distinct.
    if let Ok(rev) = serde_ipld_dagcbor::from_slice::<NodeRevocation>(bytes) {
        // `reason` is required; if it deserialises and we have non-zero
        // node_pubkey, accept.
        if rev.node_pubkey.iter().any(|&b| b != 0) {
            return Some(SigchainKind::NodeRevocation);
        }
    }
    // AgentRevocation: node_pubkey + agent_pubkey + reason + revoked_at_ns.
    if let Ok(rev) = serde_ipld_dagcbor::from_slice::<AgentRevocation>(bytes) {
        if rev.agent_pubkey.iter().any(|&b| b != 0) {
            return Some(SigchainKind::AgentRevocation);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        sign_admin_genesis, sign_agent_attestation, sign_agent_revocation, sign_node_revocation,
    };
    use ed25519_dalek::SigningKey;
    use memvault_core::{AgentId, ClusterId, PeerId};
    use rand::RngCore;

    fn make_key() -> SigningKey {
        let mut seed = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut seed);
        SigningKey::from_bytes(&seed)
    }

    #[test]
    fn detects_admin_genesis() {
        let admin = make_key();
        let g = sign_admin_genesis(&admin, ClusterId([1u8; 32]), 1).unwrap();
        let bytes = serde_ipld_dagcbor::to_vec(&g).unwrap();
        assert_eq!(
            detect_sigchain_shape(&bytes),
            Some(SigchainKind::AdminGenesis)
        );
        assert_eq!(sigchain_label_for(&bytes), Some("admin_genesis"));
    }

    #[test]
    fn detects_node_attestation() {
        let att = NodeAttestation {
            cluster_id: ClusterId([1u8; 32]),
            member: PeerId(vec![2u8; 32]),
            role: crate::Role::AgentHost,
            not_after_ns: u64::MAX,
            issued_via: crate::AttestationOrigin::Direct,
            signature: [3u8; 64],
        };
        let bytes = serde_ipld_dagcbor::to_vec(&att).unwrap();
        assert_eq!(sigchain_label_for(&bytes), Some("node_att"));
    }

    #[test]
    fn detects_agent_attestation() {
        let node = make_key();
        let agent_pk = make_key().verifying_key().to_bytes();
        let att = sign_agent_attestation(
            &node,
            AgentId("u".into()),
            agent_pk,
            crate::Role::AgentHost,
            u64::MAX,
        )
        .unwrap();
        let bytes = serde_ipld_dagcbor::to_vec(&att).unwrap();
        assert_eq!(sigchain_label_for(&bytes), Some("agent_att"));
    }

    #[test]
    fn detects_agent_revocation() {
        let node = make_key();
        let agent_pk = make_key().verifying_key().to_bytes();
        let rev = sign_agent_revocation(&node, agent_pk, "compromised").unwrap();
        let bytes = serde_ipld_dagcbor::to_vec(&rev).unwrap();
        assert_eq!(sigchain_label_for(&bytes), Some("agent_rev"));
    }

    #[test]
    fn detects_node_revocation() {
        let admin = make_key();
        let node_pk = make_key().verifying_key().to_bytes();
        let rev = sign_node_revocation(&admin, node_pk, "compromised").unwrap();
        let bytes = serde_ipld_dagcbor::to_vec(&rev).unwrap();
        assert_eq!(sigchain_label_for(&bytes), Some("node_rev"));
    }

    #[test]
    fn detects_admin_admission() {
        use crate::{sign_admin_admission, sign_admin_pop};
        let admin = make_key();
        let new = make_key();
        let cluster = ClusterId([1u8; 32]);
        let pop = sign_admin_pop(&new, &cluster);
        let adm = sign_admin_admission(
            &admin,
            new.verifying_key().to_bytes(),
            cluster,
            10,
            10,
            None,
            pop,
        )
        .unwrap();
        let bytes = serde_ipld_dagcbor::to_vec(&adm).unwrap();
        assert_eq!(sigchain_label_for(&bytes), Some("admin_admission"));
    }

    #[test]
    fn detects_admin_retirement() {
        use crate::sign_admin_retirement;
        let surviving = make_key();
        let retired = make_key().verifying_key().to_bytes();
        let ret =
            sign_admin_retirement(&surviving, retired, ClusterId([1u8; 32]), 20, "x", None).unwrap();
        let bytes = serde_ipld_dagcbor::to_vec(&ret).unwrap();
        assert_eq!(sigchain_label_for(&bytes), Some("admin_retirement"));
    }

    #[test]
    fn ignores_arbitrary_bytes() {
        assert_eq!(sigchain_label_for(b"not even cbor"), None);
        assert_eq!(sigchain_label_for(&[0xa0]), None); // empty CBOR map
    }
}

use serde::{Deserialize, Serialize};

/// Capability an **agent** holds in a cluster. Lives on an
/// [`AgentAttestation`](crate::AgentAttestation) and is the selector for
/// `GrantAudience::Role(_)` grants — a capability *label*, not a hardcoded
/// permission set. Distinct from [`NodeRole`]: agents (API identities) and
/// nodes (P2P peers) do not share a role space.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AgentRole {
    /// Hosts agents and reads/writes data on their behalf (the default member
    /// role; auto-granted Read+Write on the legacy bucket).
    AgentHost,
    /// Read-only / observability member. Bypasses retraction filtering on
    /// reads (sees retracted entries).
    Auditor,
    /// Service / automation account.
    Service,
    /// API admin — full API access. ACL-EXEMPT: an `Admin` agent bypasses
    /// bucket/grant checks. This is an *API* admin, distinct from a cluster
    /// admin (which is an admin signing key + admin attestation, not a role).
    Admin,
}

/// What a [`JoinToken`](crate::JoinToken)'s node half mints. Token-only — a
/// [`NodeAttestation`](crate::NodeAttestation) carries no role; the mere
/// existence of a valid node attestation confers block-serving trust, and
/// cluster-admin authority comes from the admin-attestation chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum NodeRole {
    /// Plain peer-node join → mints a node attestation.
    Node,
    /// Admin-node join → mints a node attestation AND, when the join request
    /// carries a valid proof-of-possession, admits the joiner's admin key as a
    /// cluster admin (subsumes the legacy `admit_as_admin` token flag).
    Admin,
}

/// The role a join token carries, tagged by which redemption flow it is for.
/// A node-join token (`/join/1.0`) and an agent-enrolment token are distinct
/// and cannot be confused at the type level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TokenRole {
    /// Redeemed via `/join/1.0` → mints a [`NodeAttestation`](crate::NodeAttestation).
    Node(NodeRole),
    /// Redeemed via `agent enroll` → mints an [`AgentAttestation`](crate::AgentAttestation).
    Agent(AgentRole),
}

#[cfg(test)]
mod tests {
    use super::{AgentRole, NodeRole, TokenRole};

    #[test]
    fn agent_role_serde_is_lowercase_roundtrip() {
        for (role, s) in [
            (AgentRole::AgentHost, "\"agenthost\""),
            (AgentRole::Auditor, "\"auditor\""),
            (AgentRole::Service, "\"service\""),
            (AgentRole::Admin, "\"admin\""),
        ] {
            assert_eq!(serde_json::to_string(&role).unwrap(), s);
            assert_eq!(serde_json::from_str::<AgentRole>(s).unwrap(), role);
        }
    }

    #[test]
    fn node_role_serde_is_lowercase_roundtrip() {
        for (role, s) in [(NodeRole::Node, "\"node\""), (NodeRole::Admin, "\"admin\"")] {
            assert_eq!(serde_json::to_string(&role).unwrap(), s);
            assert_eq!(serde_json::from_str::<NodeRole>(s).unwrap(), role);
        }
    }

    #[test]
    fn token_role_roundtrip() {
        for role in [
            TokenRole::Node(NodeRole::Node),
            TokenRole::Node(NodeRole::Admin),
            TokenRole::Agent(AgentRole::AgentHost),
            TokenRole::Agent(AgentRole::Admin),
        ] {
            let s = serde_json::to_string(&role).unwrap();
            assert_eq!(serde_json::from_str::<TokenRole>(&s).unwrap(), role);
        }
    }
}

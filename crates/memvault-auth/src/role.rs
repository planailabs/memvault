use serde::{Deserialize, Serialize};

/// Roles a member can hold in a cluster. The role is carried in the member's
/// attestation and is the selector for `GrantAudience::Role(_)` grants — it is
/// a capability *label*, not a hardcoded permission set.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    /// Cluster admin. Combined with a cluster-admitted admin signing key,
    /// can issue grants, attest nodes, and admit co-admins.
    Admin,
    /// Hosts agents and reads/writes data on their behalf (the default member
    /// role; auto-granted Read+Write on the legacy bucket).
    AgentHost,
    /// Read-only / observability member.
    Auditor,
    /// Service / automation account.
    Service,
    /// A cluster peer node (replicates data over P2P). Distinct from an
    /// agent: nodes join via `cluster-join`, agents enrol via `agent enroll`.
    Node,
}

#[cfg(test)]
mod tests {
    use super::Role;

    #[test]
    fn serde_is_lowercase_roundtrip() {
        for (role, s) in [
            (Role::Admin, "\"admin\""),
            (Role::AgentHost, "\"agenthost\""),
            (Role::Auditor, "\"auditor\""),
            (Role::Service, "\"service\""),
            (Role::Node, "\"node\""),
        ] {
            assert_eq!(serde_json::to_string(&role).unwrap(), s);
            assert_eq!(serde_json::from_str::<Role>(s).unwrap(), role);
        }
    }
}

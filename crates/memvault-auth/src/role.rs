use serde::{Deserialize, Serialize};

/// Roles a member can hold in a cluster.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    Admin,
    AgentHost,
    Auditor,
    Service,
}

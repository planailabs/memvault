use serde::{Deserialize, Serialize};

/// Controls how widely a piece of data is shared.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Visibility {
    /// Only visible within the local cluster.
    Internal,
    /// Shared with federated clusters.
    Federated,
    /// Publicly accessible.
    Public,
}

impl Default for Visibility {
    fn default() -> Self {
        Self::Internal
    }
}

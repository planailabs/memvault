//! Token lifecycle helpers (issue, redeem, revoke, list).

use memvault_auth::Role;
use memvault_store::MemvaultStore;

use crate::error::Result;
use crate::types::TokenStatus;

/// List all tokens stored in the system (stub for now - tokens are tracked via blocks).
pub fn list_tokens(_store: &MemvaultStore) -> Result<Vec<TokenStatus>> {
    // In a full implementation, we'd query blocks tagged with "token" scope.
    // For now, return empty.
    Ok(Vec::new())
}

/// Issue a new token and return its encoded string form.
/// Placeholder: in production this needs a signing key.
pub fn issue_token_placeholder(
    _role: Role,
    _ttl_secs: u64,
    _max_uses: u32,
    _label: Option<String>,
) -> Result<String> {
    // Stub: real implementation needs the cluster's signing key
    Ok("mvjoin1:placeholder".to_string())
}

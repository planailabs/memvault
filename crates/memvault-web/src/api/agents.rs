//! Agent HTTP endpoints + shared agent-attestation helpers for the WebUI.
//!
//! Multiple surfaces (audit, notes history, file detail, entity
//! detail) all need to resolve `Signed<T>.agent_attestation` cids to
//! human-readable agent IDs. Building the cid → agent_id map is a
//! small scan of the sigchain; this module centralises it so callers
//! don't reimplement the lookup.

use std::sync::Arc;

use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use serde::Deserialize;

use crate::AppState;
use crate::api::auth::RequireAuth;

#[derive(Debug, Deserialize)]
pub struct RenameAgentRequest {
    /// New display label. Display-only — does not affect access control.
    pub label: String,
}

/// `PATCH /agents/{pubkey}` — set an agent's display label.
///
/// Authorised for **the agent itself** (its JWT `sub` equals the target pubkey)
/// or a cluster **Admin** agent. The relabel is node-signed by the daemon and
/// only takes effect on the agent's attesting node (see `sigchain::agent_label`).
pub async fn rename_agent(
    auth: RequireAuth,
    State(state): State<Arc<AppState>>,
    Path(pubkey_hex): Path<String>,
    Json(req): Json<RenameAgentRequest>,
) -> Result<StatusCode, StatusCode> {
    let target: [u8; 32] = hex::decode(&pubkey_hex)
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or(StatusCode::BAD_REQUEST)?;

    // Authorisation: the agent renaming itself, or a cluster Admin.
    let is_self = auth.claims.sub.eq_ignore_ascii_case(&pubkey_hex);
    let is_admin = crate::api::auth::caller_role(&state, &auth.claims)
        == Some(memvault_auth::AgentRole::Admin);
    if !is_self && !is_admin {
        return Err(StatusCode::FORBIDDEN);
    }

    state
        .client
        .agent_rename(&target, &req.label)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(StatusCode::NO_CONTENT)
}

#[cfg(feature = "server")]
pub fn build_agent_id_index(
    local: &memvault_api::LocalClient,
) -> std::collections::HashMap<Vec<u8>, String> {
    let mut out = std::collections::HashMap::new();
    if let Ok(atts) = memvault_api::sigchain::scan_agent_attestations(local) {
        for att in atts {
            if let Ok(bytes) = memvault_core::encode(&att) {
                let cid = memvault_core::cid_from_bytes(&bytes).to_bytes();
                out.insert(cid, att.agent_id.0);
            }
        }
    }
    out
}

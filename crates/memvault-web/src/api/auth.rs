//! Bearer JWT authentication middleware.
//!
//! Every request to /api/v1/* (except `/auth/session-token`, which serves the
//! web UI) carries `Authorization: Bearer <jwt>` where `<jwt>` is an
//! ed25519-signed token (see `memvault_auth::jwt`) issued by an agent
//! identity. The token embeds the agent's `MembershipAttestation` inline,
//! so verification is stateless:
//!
//! 1. Verify attestation signature against the cluster admin's pubkey.
//! 2. Verify JWT signature against the agent's pubkey from the attestation.
//! 3. Check the token has not expired.
//!
//! Handlers can require a particular scope via the `RequireAuth` extractor's
//! `claims.has_scope(...)` once the request is in scope.

use axum::extract::FromRequestParts;
use axum::http::StatusCode;
use axum::http::request::Parts;
use axum::response::{IntoResponse, Response};

use std::sync::Arc;

use memvault_auth::jwt::AgentTokenClaims;

use crate::AppState;

/// Issues a fresh JWT for the daemon's built-in web-ui agent identity.
/// Returns the token + its expiry so the WASM client can renew before it lapses.
///
/// The web UI is served by the same process as the API, so the daemon trusts
/// the UI agent unconditionally (its identity is auto-generated at daemon
/// start). Cross-origin / external clients should issue tokens from their own
/// agent identities, not via this endpoint.
pub async fn get_session_token(
    axum::extract::State(state): axum::extract::State<Arc<AppState>>,
) -> Result<axum::Json<serde_json::Value>, axum::http::StatusCode> {
    let identity = crate::ui::state::ui_agent_identity()
        .ok_or(axum::http::StatusCode::SERVICE_UNAVAILABLE)?;
    let token = identity
        .issue_jwt("read write admin", 3600)
        .map_err(|_| axum::http::StatusCode::INTERNAL_SERVER_ERROR)?;
    // Don't expose state in the response — keep it minimal.
    let _ = state.client.status().await.ok();
    Ok(axum::Json(serde_json::json!({
        "token": token,
        "ttl_secs": 3600,
        "api_base": "/api/v1",
    })))
}

/// Extracted auth context: the verified JWT claims.
/// Handlers can read `claims.iss` (agent_id) for audit logging and
/// `claims.has_scope(...)` for per-scope authorization.
#[derive(Clone)]
pub struct RequireAuth {
    pub claims: AgentTokenClaims,
}

#[derive(Debug)]
pub struct AuthRejection(String);

impl IntoResponse for AuthRejection {
    fn into_response(self) -> Response {
        (
            StatusCode::UNAUTHORIZED,
            axum::Json(serde_json::json!({
                "error": "Unauthorized",
                "status": 401,
                "reason": self.0,
            })),
        )
            .into_response()
    }
}

impl FromRequestParts<Arc<AppState>> for RequireAuth {
    type Rejection = AuthRejection;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &Arc<AppState>,
    ) -> Result<Self, Self::Rejection> {
        let header = parts
            .headers
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .ok_or_else(|| AuthRejection("missing authorization header".into()))?;

        let token = header
            .strip_prefix("Bearer ")
            .ok_or_else(|| AuthRejection("expected Bearer scheme".into()))?;

        let claims = memvault_auth::jwt::verify(token, &state.admin_pubkey)
            .map_err(|e| AuthRejection(format!("token: {e}")))?;

        Ok(RequireAuth { claims })
    }
}

//! Bearer JWT authentication middleware.
//!
//! Every request to /api/v1/* (except `/auth/session-token`, which serves the
//! web UI) carries `Authorization: Bearer <jwt>` where `<jwt>` is an
//! ed25519-signed token (see `memvault_auth::jwt`) issued by an agent
//! identity. The token embeds the agent's `NodeAttestation` inline,
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

async fn verify_bearer(
    parts: &mut Parts,
    state: &Arc<AppState>,
) -> Result<AgentTokenClaims, AuthRejection> {
    let header = parts
        .headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| AuthRejection("missing authorization header".into()))?;
    let token = header
        .strip_prefix("Bearer ")
        .ok_or_else(|| AuthRejection("expected Bearer scheme".into()))?;
    let claims = memvault_auth::jwt::verify(token, state.admin_pubkey.as_ref(), |node_pk| {
        // Filter revoked nodes: act as if they're not in the trust table.
        if state
            .revoked_nodes
            .read()
            .map(|s| s.contains(node_pk))
            .unwrap_or(false)
        {
            return None;
        }
        state.node_trust.get(node_pk).cloned()
    })
    .map_err(|e| AuthRejection(format!("token: {e}")))?;

    // Revocation check — fails even if JWT signature + exp pass. The agent
    // pubkey is the `sub` claim (hex of the 32-byte ed25519 pubkey).
    let mut sub_bytes = [0u8; 32];
    let decoded = hex::decode(&claims.sub).map_err(|e| AuthRejection(format!("sub hex: {e}")))?;
    if decoded.len() != 32 {
        return Err(AuthRejection("sub is not 32 bytes".into()));
    }
    sub_bytes.copy_from_slice(&decoded);
    if state
        .revoked_agents
        .read()
        .map(|s| s.contains(&sub_bytes))
        .unwrap_or(false)
    {
        return Err(AuthRejection(format!(
            "agent {} has been revoked",
            claims.sub
        )));
    }
    Ok(claims)
}

impl FromRequestParts<Arc<AppState>> for RequireAuth {
    type Rejection = AuthRejection;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &Arc<AppState>,
    ) -> Result<Self, Self::Rejection> {
        Ok(RequireAuth {
            claims: verify_bearer(parts, state).await?,
        })
    }
}

/// Returns 403 Forbidden when the JWT lacks the required scope (vs 401 for
/// missing/invalid auth).
#[derive(Debug)]
pub struct ForbiddenScope(&'static str);

impl IntoResponse for ForbiddenScope {
    fn into_response(self) -> Response {
        (
            StatusCode::FORBIDDEN,
            axum::Json(serde_json::json!({
                "error": "Forbidden",
                "status": 403,
                "required_scope": self.0,
            })),
        )
            .into_response()
    }
}

/// Either an auth failure (401) or a scope failure (403).
#[derive(Debug)]
pub enum ScopeRejection {
    Auth(AuthRejection),
    Forbidden(ForbiddenScope),
}

impl IntoResponse for ScopeRejection {
    fn into_response(self) -> Response {
        match self {
            ScopeRejection::Auth(a) => a.into_response(),
            ScopeRejection::Forbidden(f) => f.into_response(),
        }
    }
}

macro_rules! scoped_extractor {
    ($name:ident, $scope:literal) => {
        /// Verified JWT extractor that also enforces a specific scope.
        pub struct $name {
            pub claims: AgentTokenClaims,
        }

        impl FromRequestParts<Arc<AppState>> for $name {
            type Rejection = ScopeRejection;

            async fn from_request_parts(
                parts: &mut Parts,
                state: &Arc<AppState>,
            ) -> Result<Self, Self::Rejection> {
                let claims = verify_bearer(parts, state)
                    .await
                    .map_err(ScopeRejection::Auth)?;
                if !claims.has_scope($scope) {
                    return Err(ScopeRejection::Forbidden(ForbiddenScope($scope)));
                }
                Ok(Self { claims })
            }
        }
    };
}

scoped_extractor!(RequireRead, "read");
scoped_extractor!(RequireWrite, "write");
scoped_extractor!(RequireAdmin, "admin");

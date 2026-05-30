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
    // The web auth path normally runs against the daemon's LocalClient
    // (set via `ui::state::set_client` at bootstrap), but tests/headless
    // hosts can install a per-request lookup via
    // `AppState.agent_attestation_lookup`. Prefer the explicit hook;
    // fall back to the global LocalClient when not set.
    let local_client_opt = match &state.agent_attestation_lookup {
        Some(_) => None,
        None => Some(
            crate::ui::state::local_client()
                .map_err(|e| AuthRejection(format!("local client not available: {e}")))?,
        ),
    };
    // Multi-admin: verify node attestations against the cluster's full
    // admin key set, read live from the client so a freshly-admitted
    // admin takes effect without a restart. Falls back to the pinned
    // anchor (`state.admin_pubkey`) when no client is available (the
    // test/headless lookup-hook path).
    let admin_keys: Vec<ed25519_dalek::VerifyingKey> = match local_client_opt.as_ref() {
        Some(client) => {
            let live = client.admin_verifying_keys();
            if live.is_empty() {
                state.admin_pubkey.into_iter().collect()
            } else {
                live
            }
        }
        None => state.admin_pubkey.into_iter().collect(),
    };
    let claims = memvault_auth::jwt::verify(
        token,
        &admin_keys,
        |agent_pk| {
            // Reject revoked agents up front by returning None — same
            // effect as the post-verify revocation check below, but
            // saves the chain walk.
            if state
                .revoked_agents
                .read()
                .map(|s| s.contains(agent_pk))
                .unwrap_or(false)
            {
                return None;
            }
            if let Some(lookup) = &state.agent_attestation_lookup {
                return lookup(agent_pk);
            }
            let local_client = local_client_opt.as_ref()?;
            memvault_api::sigchain::find_agent_attestation(local_client, agent_pk)
                .ok()
                .flatten()
        },
        |node_pk| {
            // Filter revoked nodes: act as if they're not in the trust table.
            if state
                .revoked_nodes
                .read()
                .map(|s| s.contains(node_pk))
                .unwrap_or(false)
            {
                return None;
            }
            state
                .node_trust
                .read()
                .ok()
                .and_then(|m| m.get(node_pk).cloned())
        },
    )
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

/// Resolve the verified caller's cluster [`Role`] from their claims, via the
/// same attestation lookup used during JWT verification (the per-request hook
/// when set, else the daemon's LocalClient sigchain scan). `None` when the
/// attestation can't be resolved.
pub fn caller_role(
    state: &Arc<AppState>,
    claims: &AgentTokenClaims,
) -> Option<memvault_auth::Role> {
    let decoded = hex::decode(&claims.sub).ok()?;
    let sub: [u8; 32] = decoded.try_into().ok()?;
    let att = if let Some(lookup) = &state.agent_attestation_lookup {
        lookup(&sub)?
    } else {
        let lc = crate::ui::state::local_client().ok()?;
        memvault_api::sigchain::find_agent_attestation(&lc, &sub)
            .ok()
            .flatten()?
    };
    Some(att.role)
}

/// Whether the caller may see retracted entries. Auditor (the read-only
/// observability role) and Admin bypass retraction filtering; everyone else
/// gets the normal filtered view.
pub fn caller_sees_retracted(state: &Arc<AppState>, claims: &AgentTokenClaims) -> bool {
    matches!(
        caller_role(state, claims),
        Some(memvault_auth::Role::Auditor) | Some(memvault_auth::Role::Admin)
    )
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

/// Enforce bucket-level ACL for an authenticated caller. Wraps
/// [`memvault_api::acl::check_bucket_access`] in the daemon's
/// `LocalClient` and surfaces denials as `ApiError::forbidden`.
///
/// The JWT must already be verified (i.e. you have `claims` from one of
/// the `Require*` extractors). The pubkey is taken from `claims.sub` —
/// the authoritative identity — not from any request-body field.
pub fn enforce_bucket_action(
    claims: &AgentTokenClaims,
    bucket_id: &memvault_core::BucketId,
    action: memvault_auth::Action,
) -> Result<(), crate::error::ApiError> {
    let client = crate::ui::state::local_client()
        .map_err(|e| crate::error::ApiError::internal(format!("local client unavailable: {e}")))?;
    let pubkey = hex::decode(&claims.sub)
        .map_err(|e| crate::error::ApiError::bad_request(format!("claims.sub hex: {e}")))?;
    memvault_api::acl::check_bucket_access(&client, &pubkey, bucket_id, action)
        .map_err(|e| match e {
            memvault_api::ApiError::Forbidden(msg) => crate::error::ApiError {
                status: axum::http::StatusCode::FORBIDDEN,
                message: msg,
            },
            other => crate::error::ApiError::internal(other.to_string()),
        })
}

/// Same as [`enforce_bucket_action`] but resolves the target bucket from
/// a document id. No-ops (returns `Ok`) when the doc is pre-bucket /
/// unscoped — the lower-level read will then succeed or 404 on its own
/// terms; we don't gate legacy data behind ACLs.
pub fn enforce_doc_action(
    claims: &AgentTokenClaims,
    doc_id: &memvault_core::DocId,
    action: memvault_auth::Action,
) -> Result<(), crate::error::ApiError> {
    let client = crate::ui::state::local_client()
        .map_err(|e| crate::error::ApiError::internal(format!("local client unavailable: {e}")))?;
    let Some(bid) = client.bucket_for_doc(doc_id) else {
        return Ok(());
    };
    enforce_bucket_action(claims, &bid, action)
}

/// Same as [`enforce_bucket_action`] but resolves the target bucket from
/// an entity id.
pub fn enforce_entity_action(
    claims: &AgentTokenClaims,
    entity_id: &memvault_core::EntityId,
    action: memvault_auth::Action,
) -> Result<(), crate::error::ApiError> {
    let client = crate::ui::state::local_client()
        .map_err(|e| crate::error::ApiError::internal(format!("local client unavailable: {e}")))?;
    let Some(bid) = client.bucket_for_entity(entity_id) else {
        return Ok(());
    };
    enforce_bucket_action(claims, &bid, action)
}

/// Same as [`enforce_bucket_action`] but resolves the target bucket from
/// a file manifest CID.
pub fn enforce_file_action(
    claims: &AgentTokenClaims,
    manifest_cid: &[u8],
    action: memvault_auth::Action,
) -> Result<(), crate::error::ApiError> {
    let client = crate::ui::state::local_client()
        .map_err(|e| crate::error::ApiError::internal(format!("local client unavailable: {e}")))?;
    let Some(bid) = client.bucket_for_file(manifest_cid) else {
        return Ok(());
    };
    enforce_bucket_action(claims, &bid, action)
}

/// Same as [`enforce_bucket_action`] but resolves the target bucket from
/// any node id string (`doc:<hex>`, `entity:<hex>`, `file:<hex>`,
/// `attachment:<hex>`).
pub fn enforce_node_action(
    claims: &AgentTokenClaims,
    node_id: &str,
    action: memvault_auth::Action,
) -> Result<(), crate::error::ApiError> {
    let client = crate::ui::state::local_client()
        .map_err(|e| crate::error::ApiError::internal(format!("local client unavailable: {e}")))?;
    let Some(bid) = client.bucket_for_node_id(node_id) else {
        return Ok(());
    };
    enforce_bucket_action(claims, &bid, action)
}

/// Drop items the caller cannot Read. Result-listing endpoints
/// (`search`, `list_nodes`, `view_members`) call this to filter out
/// hits from buckets the caller has no Read grant on.
///
/// `key` extracts the node id string from each item; items that don't
/// map to a bucket (legacy / pre-bucket / unknown id format) pass
/// through. Per-bucket decisions are cached for the duration of the
/// call so a hit list with 100 docs in 3 buckets only runs 3 grant
/// scans.
pub fn filter_readable<T, F>(
    claims: &AgentTokenClaims,
    items: Vec<T>,
    key: F,
) -> Result<Vec<T>, crate::error::ApiError>
where
    F: Fn(&T) -> String,
{
    use std::collections::HashMap;
    let client = crate::ui::state::local_client()
        .map_err(|e| crate::error::ApiError::internal(format!("local client unavailable: {e}")))?;
    let pubkey = hex::decode(&claims.sub)
        .map_err(|e| crate::error::ApiError::bad_request(format!("claims.sub hex: {e}")))?;

    let mut cache: HashMap<[u8; 32], bool> = HashMap::new();
    let mut out = Vec::with_capacity(items.len());
    for item in items {
        let node_id = key(&item);
        let Some(bid) = client.bucket_for_node_id(&node_id) else {
            out.push(item);
            continue;
        };
        let allowed = *cache.entry(bid.0).or_insert_with(|| {
            memvault_api::acl::check_bucket_access(
                &client,
                &pubkey,
                &bid,
                memvault_auth::Action::Read,
            )
            .is_ok()
        });
        if allowed {
            out.push(item);
        }
    }
    Ok(out)
}

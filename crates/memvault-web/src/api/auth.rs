//! Bearer JWT authentication middleware.
//!
//! Every request to /api/v1/* (except `/auth/session-token`, which serves the
//! web UI) carries an ed25519-signed agent JWT (see `memvault_auth::jwt`) on
//! one of:
//!
//! - `Authorization: Bearer <jwt>` — used by `memctl --url …` and other
//!   CLI / agent callers.
//! - the `memvault_session` cookie — set by `GET /auth/session-token` so
//!   the browser-hosted web UI never has to touch the JWT directly.
//!
//! Verification is stateless either way:
//!
//! 1. Verify attestation signature against the cluster admin's pubkey.
//! 2. Verify JWT signature against the agent's pubkey from the attestation.
//! 3. Check the token has not expired.
//!
//! Handlers can require a particular scope via the `RequireAuth` extractor's
//! `claims.has_scope(...)` once the request is in scope.
//!
//! State-changing requests are additionally gated by [`origin_guard`], a
//! cheap CSRF check that matches the `Origin` header's host against the
//! request `Host` (so cookie-bearing cross-origin POSTs are rejected without
//! affecting Bearer-token clients that don't set `Origin`).

use axum::extract::FromRequestParts;
use axum::http::header::HeaderMap;
use axum::http::request::Parts;
use axum::http::{Method, Request, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum_extra::extract::CookieJar;
use axum_extra::extract::cookie::{Cookie, Expiration, SameSite};

use std::sync::Arc;

use memvault_auth::jwt::AgentTokenClaims;

use crate::AppState;

/// Name of the HttpOnly cookie that carries the web UI's session JWT.
/// Kept stable so reverse proxies / log scrapers can recognise it.
pub const SESSION_COOKIE: &str = "memvault_session";

/// Session TTL for browser-issued JWTs (web UI).
const SESSION_TTL_SECS: i64 = 3600;

/// Build the `memvault_session` cookie for a freshly-minted session JWT.
/// Extracted so tests can assert the same flags the browser will see.
fn session_cookie(token: String) -> Cookie<'static> {
    let mut c = Cookie::build((SESSION_COOKIE, token))
        .path("/")
        .http_only(true)
        .same_site(SameSite::Strict)
        .build();
    c.set_max_age(Some(time::Duration::seconds(SESSION_TTL_SECS)));
    // Expiration belt-and-braces for clients that mis-handle Max-Age.
    c.set_expires(Expiration::DateTime(
        time::OffsetDateTime::now_utc() + time::Duration::seconds(SESSION_TTL_SECS),
    ));
    c
}

/// Issues a fresh JWT for the daemon's built-in web-ui agent identity.
///
/// Two outputs:
/// - JSON body `{ token, ttl_secs, api_base }` for any caller that wants the
///   bare JWT (e.g. a programmatic client that prefers `Authorization: Bearer`).
/// - `Set-Cookie: memvault_session=…; HttpOnly; SameSite=Strict; Path=/` so
///   the browser carries the token on every subsequent request — including
///   server-function calls — without the WASM client ever touching it.
///
/// The web UI is served by the same process as the API, so the daemon trusts
/// the UI agent unconditionally (its identity is auto-generated at daemon
/// start). [`origin_guard`] still gates this endpoint, so a cross-origin page
/// can't silently steal a session by polling it.
pub async fn get_session_token(
    jar: CookieJar,
    axum::extract::State(state): axum::extract::State<Arc<AppState>>,
) -> Result<(CookieJar, axum::Json<serde_json::Value>), StatusCode> {
    let identity =
        crate::ui::state::ui_agent_identity().ok_or(StatusCode::SERVICE_UNAVAILABLE)?;
    let token = identity
        .issue_jwt("read write admin", SESSION_TTL_SECS as u64)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    // Don't expose state in the response — keep it minimal.
    let _ = state.client.status().await.ok();

    let jar = jar.add(session_cookie(token.clone()));
    let body = axum::Json(serde_json::json!({
        "token": token,
        "ttl_secs": SESSION_TTL_SECS,
        "api_base": "/api/v1",
    }));
    Ok((jar, body))
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

/// Extract a session JWT from either `Authorization: Bearer …` or the
/// `memvault_session` cookie, in that order. Returns `None` when neither
/// is present.
fn extract_token(headers: &HeaderMap) -> Option<String> {
    if let Some(bearer) = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
    {
        return Some(bearer.to_string());
    }
    let raw = headers.get("cookie")?.to_str().ok()?;
    for pair in raw.split(';') {
        let pair = pair.trim();
        if let Some((name, value)) = pair.split_once('=') {
            if name == SESSION_COOKIE {
                return Some(value.to_string());
            }
        }
    }
    None
}

async fn verify_bearer(
    parts: &mut Parts,
    state: &Arc<AppState>,
) -> Result<AgentTokenClaims, AuthRejection> {
    let token = extract_token(&parts.headers).ok_or_else(|| {
        AuthRejection("missing Authorization header or session cookie".into())
    })?;
    let token = token.as_str();
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
) -> Option<memvault_auth::AgentRole> {
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
        Some(memvault_auth::AgentRole::Auditor) | Some(memvault_auth::AgentRole::Admin)
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

/// Cheap, browser-side CSRF defence: on non-safe methods, require the
/// request `Origin` (when present) to share its host:port with the
/// request `Host` header — i.e. it came from a page served by this same
/// daemon (or whatever reverse proxy is fronting it, since proxies
/// forward `Host` verbatim).
///
/// Policy:
/// - Safe methods (`GET`/`HEAD`/`OPTIONS`) → pass through. Idempotent
///   reads can't be turned into a CSRF write.
/// - `Origin` present → its authority must equal the `Host` authority.
/// - `Origin` absent + session cookie present → reject. A real browser
///   would have set `Origin`; absence suggests the request was crafted
///   to dodge the check.
/// - `Origin` absent + cookie absent → pass through. This is the
///   `memctl --url … import-docs` / scripted-`curl` path; those callers
///   present a Bearer token and the existing JWT verification gates them.
///
/// `Set-Cookie` SameSite=Strict on the session cookie is the primary
/// protection; this guard catches the residual case where SameSite is
/// disabled / unsupported and adds defence in depth for the reverse-proxy
/// scenario where `Host` is the public hostname and `Origin` is whatever
/// the browser was looking at when it made the request.
pub async fn origin_guard(
    req: Request<axum::body::Body>,
    next: Next,
) -> Result<Response, StatusCode> {
    if matches!(
        *req.method(),
        Method::GET | Method::HEAD | Method::OPTIONS
    ) {
        return Ok(next.run(req).await);
    }
    let headers = req.headers();
    let origin = headers
        .get("origin")
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    let host = headers
        .get("host")
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    let has_session_cookie = headers
        .get("cookie")
        .and_then(|v| v.to_str().ok())
        .map(|c| {
            c.split(';')
                .any(|p| p.trim().starts_with(&format!("{SESSION_COOKIE}=")))
        })
        .unwrap_or(false);

    if let Some(origin) = origin {
        let Some(host) = host else {
            // Origin present but no Host — malformed; refuse.
            return Err(StatusCode::FORBIDDEN);
        };
        // Origin's authority is everything after `scheme://` up to the
        // next `/`. Match against the verbatim `Host` header.
        let origin_authority = origin
            .splitn(2, "://")
            .nth(1)
            .unwrap_or("")
            .split('/')
            .next()
            .unwrap_or("");
        if origin_authority != host {
            return Err(StatusCode::FORBIDDEN);
        }
        return Ok(next.run(req).await);
    }

    if has_session_cookie {
        // Cookie auth path with no Origin → CSRF-shaped.
        return Err(StatusCode::FORBIDDEN);
    }

    Ok(next.run(req).await)
}

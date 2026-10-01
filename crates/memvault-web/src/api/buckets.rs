//! Bucket CRUD API routes.

use std::sync::Arc;

use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use memvault_api::rest::{
    BindBucketRequest, BucketCreated, BucketMerge, CreateBucketRequest, EnsureAgentBucketRequest,
    GrantIssued, GrantRevoked, IssueGrantRequest, MergeBucketsRequest, ReasonRequest,
    RenameRequest, SubmitGrantRequest,
};
use serde::Deserialize;

use crate::AppState;
use crate::api::auth::{RequireAdmin, RequireAuth, RequireWrite};
use crate::error::ApiError;

#[derive(Debug, Default, Deserialize)]
pub struct ListBucketsQuery {
    /// Surface buckets that have been merged into a canonical (hidden by
    /// default, like retracted). Auditor/Admin roles always see them.
    #[serde(default)]
    pub include_merged: bool,
}

fn parse_bucket_hex(s: &str) -> Result<memvault_core::BucketId, ApiError> {
    memvault_core::BucketId::from_hex(s).map_err(|_| ApiError::bad_request("invalid bucket id"))
}

pub async fn list_buckets(
    auth: RequireAuth,
    State(state): State<Arc<AppState>>,
    Query(params): Query<ListBucketsQuery>,
) -> Result<Json<Vec<memvault_api::types::BucketInfo>>, ApiError> {
    // Merged source buckets are hidden from the default listing — they're
    // surfaced under their canonical, so showing them too would double-count
    // and confuse. Treat them like retracted: visible only when explicitly
    // requested, or to Auditor/Admin roles (who audit the full topology).
    let role = crate::api::auth::caller_role(&state, &auth.claims);
    let show_merged = params.include_merged
        || matches!(
            role,
            Some(memvault_auth::AgentRole::Auditor) | Some(memvault_auth::AgentRole::Admin)
        );
    // `BucketInfo` carries hex-id wire encoding (see `standards/`), so it is
    // transmitted as-is — no hand-built JSON.
    let mut buckets = state.client.bucket_list_filtered(show_merged).await?;
    // Only the buckets the caller may read (its own, granted ones; all for
    // admins), the same rule that answers 404 when it opens another.
    let mut readable = crate::api::auth::Readable::new(&auth.claims)?;
    buckets.retain(|b| readable.bucket(&b.id));
    Ok(Json(buckets))
}

pub async fn get_bucket(
    auth: RequireAuth,
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<Json<memvault_api::types::BucketInfo>, ApiError> {
    let bucket_id = parse_bucket_hex(&id)?;
    // A bucket the caller may not read doesn't exist for it (404).
    crate::api::auth::enforce_bucket_action(&auth.claims, &bucket_id, memvault_auth::Action::Read)?;
    state
        .client
        .bucket_get(&bucket_id)
        .await?
        .map(Json)
        .ok_or_else(|| ApiError::not_found("Bucket not found"))
}

/// POST /api/v1/buckets — 201 with the new `bucket_id`.
pub async fn create_bucket(
    auth: RequireWrite,
    State(_state): State<Arc<AppState>>,
    Json(req): Json<CreateBucketRequest>,
) -> Result<(StatusCode, Json<BucketCreated>), ApiError> {
    if req
        .role
        .is_some_and(|r| r != memvault_core::BucketRole::Standard)
    {
        return Err(ApiError::bad_request(
            "only standard buckets are created over the API",
        ));
    }
    // Resolve the caller's on-chain agent_id so the new bucket records
    // them as `owner_agent`. Without this, the BucketDecl would inherit
    // the daemon's identity and the caller would have no implicit
    // access to a bucket they just created.
    let client = crate::ui::state::local_client()
        .map_err(|e| ApiError::internal(format!("local client unavailable: {e}")))?;
    let pubkey_bytes = hex::decode(&auth.claims.sub)
        .map_err(|e| ApiError::bad_request(format!("claims.sub hex: {e}")))?;
    let pubkey_arr: [u8; 32] = pubkey_bytes
        .as_slice()
        .try_into()
        .map_err(|_| ApiError::bad_request("claims.sub must be 32 bytes".to_string()))?;
    let attestation = memvault_api::sigchain::find_agent_attestation(&client, &pubkey_arr)
        .map_err(|e| ApiError::internal(format!("attestation lookup: {e}")))?
        .ok_or_else(|| ApiError {
            status: StatusCode::FORBIDDEN,
            message: format!(
                "no agent attestation on chain for pubkey {}",
                auth.claims.sub
            ),
        })?;

    let bucket_id = client
        .bucket_create_as(
            attestation.agent_id,
            Some(pubkey_arr),
            &req.name,
            req.description.as_deref(),
            req.default_visibility
                .unwrap_or(memvault_core::Visibility::Internal),
            req.default_classification
                .unwrap_or(memvault_core::classification::Classification::Internal),
            memvault_core::BucketRole::Standard,
        )
        .await
        .map_err(|e| ApiError::internal(format!("bucket_create: {e}")))?;

    Ok((StatusCode::CREATED, Json(BucketCreated { bucket_id })))
}

/// PATCH /api/v1/buckets/{id} — rename. Needs Admin on the bucket (its
/// owner, a grant, or an admin): the write scope alone let any agent rename
/// any bucket.
pub async fn rename_bucket(
    auth: RequireWrite,
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Json(req): Json<RenameRequest>,
) -> Result<StatusCode, ApiError> {
    let bucket_id = parse_bucket_hex(&id)?;
    crate::api::auth::enforce_bucket_action(
        &auth.claims,
        &bucket_id,
        memvault_auth::Action::Admin,
    )?;
    state
        .client
        .bucket_rename(&bucket_id, &req.name)
        .await
        .map_err(|e| ApiError::internal(format!("bucket rename: {e}")))?;
    Ok(StatusCode::NO_CONTENT)
}

/// POST /api/v1/buckets/merge — alias `sources → canonical`.
///
/// Authority is enforced against the **caller's** JWT: they must be admin
/// or owner (Action::Admin) of the canonical *and* every source. The daemon
/// then signs the `BucketMergeRecord` with the best authority it holds.
pub async fn merge_buckets(
    auth: RequireWrite,
    State(state): State<Arc<AppState>>,
    Json(req): Json<MergeBucketsRequest>,
) -> Result<StatusCode, ApiError> {
    if req.sources.is_empty() {
        return Err(ApiError::bad_request("no source buckets given"));
    }
    crate::api::auth::enforce_bucket_action(
        &auth.claims,
        &req.canonical,
        memvault_auth::Action::Admin,
    )?;
    for s in &req.sources {
        crate::api::auth::enforce_bucket_action(&auth.claims, s, memvault_auth::Action::Admin)?;
    }
    state
        .client
        .bucket_merge(&req.sources, &req.canonical)
        .await
        .map_err(|e| ApiError::internal(format!("bucket merge: {e}")))?;
    Ok(StatusCode::NO_CONTENT)
}

/// POST /api/v1/buckets/unmerge — reverse a single `source → canonical` edge.
pub async fn unmerge_buckets(
    auth: RequireWrite,
    State(state): State<Arc<AppState>>,
    Json(req): Json<BucketMerge>,
) -> Result<StatusCode, ApiError> {
    crate::api::auth::enforce_bucket_action(
        &auth.claims,
        &req.canonical,
        memvault_auth::Action::Admin,
    )?;
    state
        .client
        .bucket_unmerge(&req.source, &req.canonical)
        .await
        .map_err(|e| ApiError::internal(format!("bucket unmerge: {e}")))?;
    Ok(StatusCode::NO_CONTENT)
}

/// GET /api/v1/buckets/merges — the `source → canonical` edges whose both
/// ends the caller may read.
pub async fn list_merges(
    auth: RequireAuth,
    State(state): State<Arc<AppState>>,
) -> Result<Json<Vec<BucketMerge>>, ApiError> {
    let edges = state
        .client
        .bucket_merges()
        .await
        .map_err(|e| ApiError::internal(format!("list merges: {e}")))?;
    let mut readable = crate::api::auth::Readable::new(&auth.claims)?;
    Ok(Json(
        edges
            .into_iter()
            .filter(|(s, c)| readable.bucket(s) && readable.bucket(c))
            .map(|(source, canonical)| BucketMerge { source, canonical })
            .collect(),
    ))
}

/// POST /api/v1/buckets/{id}/attach — bind to this cluster. Needs Admin on
/// the bucket, like rename.
pub async fn attach_bucket(
    auth: RequireWrite,
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<StatusCode, ApiError> {
    let bucket_id = parse_bucket_hex(&id)?;
    crate::api::auth::enforce_bucket_action(
        &auth.claims,
        &bucket_id,
        memvault_auth::Action::Admin,
    )?;
    state
        .client
        .bucket_attach(&bucket_id)
        .await
        .map_err(|e| ApiError::internal(format!("bucket attach: {e}")))?;
    Ok(StatusCode::NO_CONTENT)
}

/// POST /api/v1/buckets/{id}/bind — bind the bucket to a cluster (exclusive:
/// rebinding to another cluster is refused). Admin scope and Admin on the
/// bucket.
pub async fn bind_bucket(
    auth: RequireAdmin,
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Json(req): Json<BindBucketRequest>,
) -> Result<StatusCode, ApiError> {
    let bucket_id = parse_bucket_hex(&id)?;
    crate::api::auth::enforce_bucket_action(
        &auth.claims,
        &bucket_id,
        memvault_auth::Action::Admin,
    )?;
    state
        .client
        .bucket_bind(&bucket_id, &req.cluster_id)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

/// POST /api/v1/buckets/agent — the caller's own agent bucket, created on
/// first use.
pub async fn ensure_agent_bucket(
    auth: RequireWrite,
    State(state): State<Arc<AppState>>,
    Json(req): Json<EnsureAgentBucketRequest>,
) -> Result<Json<BucketCreated>, ApiError> {
    // The bucket id is keyed by the agent's pubkey. Use claims.sub (the
    // verified ed25519 pubkey hex) instead of trusting req.agent_id for
    // identity — the name is only a display hint on the BucketDecl.
    let pubkey = hex::decode(&auth.claims.sub)
        .ok()
        .filter(|p| p.len() == 32)
        .ok_or_else(|| ApiError::bad_request("claims.sub must be a 32-byte hex key"))?;
    // Only AgentHost agents (writers) get a data bucket; Auditor / Service /
    // Admin agents don't.
    if crate::api::auth::caller_role(&state, &auth.claims)
        != Some(memvault_auth::AgentRole::AgentHost)
    {
        return Err(ApiError {
            status: StatusCode::FORBIDDEN,
            message: "only agent-host agents have an agent bucket".into(),
        });
    }
    let bucket_id = state
        .client
        .ensure_agent_bucket(&pubkey, &req.agent_id)
        .await
        .map_err(|e| ApiError::internal(format!("agent bucket: {e}")))?;
    Ok(Json(BucketCreated { bucket_id }))
}

/// POST /api/v1/buckets/{id}/archive — Admin scope and Admin on the bucket.
pub async fn archive_bucket(
    auth: RequireAdmin,
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Json(req): Json<ReasonRequest>,
) -> Result<StatusCode, ApiError> {
    let bucket_id = parse_bucket_hex(&id)?;
    crate::api::auth::enforce_bucket_action(
        &auth.claims,
        &bucket_id,
        memvault_auth::Action::Admin,
    )?;
    state.client.bucket_archive(&bucket_id, &req.reason).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// GET /api/v1/buckets/{id}/grants — list active grants on a bucket the
/// caller may read (404 for one it may not).
pub async fn list_grants(
    auth: RequireAuth,
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<Json<Vec<memvault_api::GrantInfo>>, ApiError> {
    let bucket_id = parse_bucket_hex(&id)?;
    crate::api::auth::enforce_bucket_action(&auth.claims, &bucket_id, memvault_auth::Action::Read)?;
    let grants = state
        .client
        .bucket_grants_list(&bucket_id)
        .await
        .map_err(|e| ApiError::internal(format!("list grants: {e}")))?;
    Ok(Json(grants))
}

#[derive(Debug, Deserialize)]
pub struct RevokeGrantRequest {
    #[serde(default = "default_revoke_reason")]
    pub reason: String,
}
fn default_revoke_reason() -> String {
    "revoked via API".into()
}

/// POST /api/v1/grants/{cid}/revoke — revoke a previously-issued grant (its
/// CID string, or legacy hex); 201 with the revocation's CID.
pub async fn revoke_grant(
    _auth: RequireAdmin,
    State(state): State<Arc<AppState>>,
    Path(grant_cid): Path<String>,
    Json(req): Json<RevokeGrantRequest>,
) -> Result<(StatusCode, Json<GrantRevoked>), ApiError> {
    let grant_cid = memvault_core::cid_bytes_lenient(&grant_cid)
        .map_err(|_| ApiError::bad_request("invalid grant CID"))?;
    let revocation_cid = state
        .client
        .revoke_grant(&grant_cid, &req.reason)
        .await
        .map_err(|e| ApiError::internal(format!("revoke grant: {e}")))?;
    Ok((StatusCode::CREATED, Json(GrantRevoked { revocation_cid })))
}

/// POST /api/v1/buckets/{id}/issue-grant — sign and publish a grant; 201
/// with its CID.
///
/// The daemon picks the best signing authority it holds for this bucket
/// (admin / owner-agent / node key) and stores the resulting grant block,
/// which then propagates via the normal sigchain sync.
pub async fn issue_grant(
    _auth: RequireAdmin,
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Json(req): Json<IssueGrantRequest>,
) -> Result<(StatusCode, Json<GrantIssued>), ApiError> {
    let bucket_id = parse_bucket_hex(&id)?;
    let audience = memvault_auth::GrantAudience::from(req.audience);
    if matches!(audience, memvault_auth::GrantAudience::Agent(_)) {
        return Err(ApiError::bad_request(
            "legacy agent-id grants are no longer supported — grant by agent_pubkey instead",
        ));
    }
    let grant_cid = state
        .client
        .bucket_grant(&bucket_id, audience, req.actions, req.ttl_secs)
        .await
        .map_err(|e| ApiError::internal(format!("issue grant: {e}")))?;
    Ok((StatusCode::CREATED, Json(GrantIssued { grant_cid })))
}

/// POST /api/v1/buckets/{id}/grants — submit an externally-signed grant;
/// 201 with its CID.
///
/// The daemon validates and stores; it does not sign. The submitter must
/// be the grant's issuer (JWT `sub` == the grant's signer pubkey), the
/// grant must scope this bucket, and the issuer must be authorised for it
/// (admin / bucket owner agent / owning node / owner's attesting node).
pub async fn submit_grant(
    auth: RequireWrite,
    State(_state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Json(req): Json<SubmitGrantRequest>,
) -> Result<(StatusCode, Json<GrantIssued>), ApiError> {
    let bucket_id = parse_bucket_hex(&id)?;
    let grant_bytes = hex::decode(&req.grant_cbor_hex)
        .map_err(|_| ApiError::bad_request("grant_cbor_hex is not hex"))?;
    let grant: memvault_auth::Grant = serde_ipld_dagcbor::from_slice(&grant_bytes)
        .map_err(|e| ApiError::bad_request(format!("grant decode: {e}")))?;

    // The grant must scope exactly the bucket in the path.
    if grant.bucket_scopes.as_slice() != [bucket_id] {
        return Err(ApiError::bad_request(
            "grant bucket_scopes must be exactly this bucket",
        ));
    }
    // The submitter must be the grant's issuer (no relaying others' grants).
    let sub = hex::decode(&auth.claims.sub)
        .map_err(|e| ApiError::bad_request(format!("claims.sub hex: {e}")))?;
    if sub.as_slice() != grant.admin_pubkey {
        return Err(ApiError {
            status: StatusCode::FORBIDDEN,
            message: "submitter is not the grant issuer".into(),
        });
    }

    let client = crate::ui::state::local_client()
        .map_err(|e| ApiError::internal(format!("local client unavailable: {e}")))?;
    let grant_cid = client.submit_signed_grant(&grant).map_err(|e| match e {
        memvault_api::ApiError::Forbidden(m) => ApiError {
            status: StatusCode::FORBIDDEN,
            message: m,
        },
        other => ApiError::bad_request(other.to_string()),
    })?;
    Ok((StatusCode::CREATED, Json(GrantIssued { grant_cid })))
}

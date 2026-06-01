//! Bucket CRUD API routes.

use std::sync::Arc;

use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use serde::{Deserialize, Serialize};

use crate::AppState;
use crate::api::auth::{RequireAdmin, RequireAuth, RequireWrite};
use crate::error::ApiError;

#[derive(Debug, Deserialize)]
pub struct CreateBucketRequest {
    pub name: String,
    pub description: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct CreateBucketResponse {
    pub id: String,
}

pub async fn list_buckets(
    _auth: RequireAuth,
    State(state): State<Arc<AppState>>,
) -> Result<Json<Vec<memvault_api::types::BucketInfo>>, StatusCode> {
    // `BucketInfo` carries hex-id wire encoding (see `standards/`), so it is
    // transmitted as-is — no hand-built JSON.
    let buckets = state
        .client
        .bucket_list()
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(buckets))
}

pub async fn get_bucket(
    _auth: RequireAuth,
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<Json<memvault_api::types::BucketInfo>, StatusCode> {
    let bucket_bytes = hex::decode(&id).map_err(|_| StatusCode::BAD_REQUEST)?;
    let bucket_arr: [u8; 32] = bucket_bytes
        .try_into()
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    let bucket_id = memvault_core::BucketId(bucket_arr);

    match state.client.bucket_get(&bucket_id).await {
        Ok(Some(b)) => Ok(Json(b)),
        Ok(None) => Err(StatusCode::NOT_FOUND),
        Err(_) => Err(StatusCode::INTERNAL_SERVER_ERROR),
    }
}

pub async fn create_bucket(
    auth: RequireWrite,
    State(_state): State<Arc<AppState>>,
    Json(req): Json<CreateBucketRequest>,
) -> Result<Json<CreateBucketResponse>, ApiError> {
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
            memvault_core::Visibility::Internal,
            memvault_core::classification::Classification::Internal,
            memvault_doc::BucketRole::Standard,
        )
        .await
        .map_err(|e| ApiError::internal(format!("bucket_create: {e}")))?;

    Ok(Json(CreateBucketResponse {
        id: hex::encode(bucket_id.0),
    }))
}

#[derive(Debug, Deserialize)]
pub struct RenameBucketRequest {
    pub name: String,
}

pub async fn rename_bucket(
    _auth: RequireWrite,
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Json(req): Json<RenameBucketRequest>,
) -> Result<StatusCode, StatusCode> {
    let bucket_bytes = hex::decode(&id).map_err(|_| StatusCode::BAD_REQUEST)?;
    let bucket_arr: [u8; 32] = bucket_bytes
        .try_into()
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    let bucket_id = memvault_core::BucketId(bucket_arr);

    state
        .client
        .bucket_rename(&bucket_id, &req.name)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(StatusCode::NO_CONTENT)
}

pub async fn attach_bucket(
    _auth: RequireWrite,
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<StatusCode, StatusCode> {
    let bucket_bytes = hex::decode(&id).map_err(|_| StatusCode::BAD_REQUEST)?;
    let bucket_arr: [u8; 32] = bucket_bytes
        .try_into()
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    let bucket_id = memvault_core::BucketId(bucket_arr);

    state
        .client
        .bucket_attach(&bucket_id)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(StatusCode::NO_CONTENT)
}

#[derive(Debug, Deserialize)]
pub struct ArchiveBucketRequest {
    pub reason: String,
}

#[derive(Debug, Deserialize)]
pub struct EnsureAgentBucketRequest {
    pub agent_id: String,
}

#[derive(Debug, Serialize)]
pub struct EnsureAgentBucketResponse {
    pub id: String,
}

pub async fn ensure_agent_bucket(
    auth: RequireWrite,
    State(state): State<Arc<AppState>>,
    Json(req): Json<EnsureAgentBucketRequest>,
) -> Result<Json<EnsureAgentBucketResponse>, StatusCode> {
    // The bucket id is keyed by the agent's pubkey. Use claims.sub (the
    // verified ed25519 pubkey hex) instead of trusting req.agent_id for
    // identity — the name is only a display hint on the BucketDecl.
    let pubkey = hex::decode(&auth.claims.sub).map_err(|_| StatusCode::BAD_REQUEST)?;
    if pubkey.len() != 32 {
        return Err(StatusCode::BAD_REQUEST);
    }
    // Only AgentHost agents (writers) get a data bucket; Auditor / Service /
    // Admin agents don't.
    if crate::api::auth::caller_role(&state, &auth.claims) != Some(memvault_auth::AgentRole::AgentHost)
    {
        return Err(StatusCode::FORBIDDEN);
    }
    let bucket_id = state
        .client
        .ensure_agent_bucket_for_pubkey(&pubkey, &req.agent_id)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(EnsureAgentBucketResponse {
        id: hex::encode(bucket_id.0),
    }))
}

pub async fn archive_bucket(
    _auth: RequireAdmin,
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Json(req): Json<ArchiveBucketRequest>,
) -> Result<StatusCode, StatusCode> {
    let bucket_bytes = hex::decode(&id).map_err(|_| StatusCode::BAD_REQUEST)?;
    let bucket_arr: [u8; 32] = bucket_bytes
        .try_into()
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    let bucket_id = memvault_core::BucketId(bucket_arr);

    state
        .client
        .bucket_archive(&bucket_id, &req.reason)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(StatusCode::NO_CONTENT)
}

#[derive(Debug, Deserialize)]
pub struct SubmitGrantRequest {
    /// The DAG-CBOR-encoded, agent-signed `Grant`, hex-encoded. Built and
    /// signed client-side by the issuer (path 2 — the daemon never holds
    /// the issuer's key).
    pub grant_cbor_hex: String,
}

/// GET /api/v1/buckets/{id}/grants — list active grants on a bucket.
pub async fn list_grants(
    _auth: RequireAuth,
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<Json<Vec<memvault_api::GrantInfo>>, ApiError> {
    let bucket_bytes =
        hex::decode(&id).map_err(|_| ApiError::bad_request("invalid bucket id hex"))?;
    let bucket_arr: [u8; 32] = bucket_bytes
        .try_into()
        .map_err(|_| ApiError::bad_request("bucket id must be 32 bytes"))?;
    let grants = state
        .client
        .bucket_grants_list(&memvault_core::BucketId(bucket_arr))
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

/// POST /api/v1/grants/{cid}/revoke — revoke a previously-issued grant.
pub async fn revoke_grant(
    _auth: RequireAdmin,
    State(state): State<Arc<AppState>>,
    Path(grant_cid_hex): Path<String>,
    Json(req): Json<RevokeGrantRequest>,
) -> Result<(StatusCode, Json<serde_json::Value>), ApiError> {
    let grant_cid = hex::decode(&grant_cid_hex)
        .map_err(|_| ApiError::bad_request("invalid grant cid hex"))?;
    let rev_cid = state
        .client
        .revoke_grant(&grant_cid, &req.reason)
        .await
        .map_err(|e| ApiError::internal(format!("revoke grant: {e}")))?;
    Ok((
        StatusCode::CREATED,
        Json(serde_json::json!({ "revocation_cid": hex::encode(rev_cid) })),
    ))
}

#[derive(Debug, Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum IssueGrantAudience {
    Cluster { cluster_id: String },
    Peer { peer_id: String },
    Agent { agent_id: String },
    Role { role: String },
}

#[derive(Debug, Deserialize)]
pub struct IssueGrantRequest {
    pub audience: IssueGrantAudience,
    /// "read" | "write" | "admin" | "egress"
    pub actions: Vec<String>,
    pub ttl_secs: u64,
}

/// POST /api/v1/buckets/{id}/issue-grant — sign and publish a grant.
///
/// The daemon picks the best signing authority it holds for this bucket
/// (admin / owner-agent / node key) and stores the resulting grant block,
/// which then propagates via the normal sigchain sync.
pub async fn issue_grant(
    _auth: RequireAdmin,
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Json(req): Json<IssueGrantRequest>,
) -> Result<(StatusCode, Json<serde_json::Value>), ApiError> {
    let bucket_bytes =
        hex::decode(&id).map_err(|_| ApiError::bad_request("invalid bucket id hex"))?;
    let bucket_arr: [u8; 32] = bucket_bytes
        .try_into()
        .map_err(|_| ApiError::bad_request("bucket id must be 32 bytes"))?;
    let bucket_id = memvault_core::BucketId(bucket_arr);

    let audience = match req.audience {
        IssueGrantAudience::Cluster { cluster_id } => {
            let bytes = hex::decode(&cluster_id)
                .map_err(|_| ApiError::bad_request("cluster_id hex"))?;
            let arr: [u8; 32] = bytes
                .try_into()
                .map_err(|_| ApiError::bad_request("cluster_id must be 32 bytes"))?;
            memvault_auth::GrantAudience::Cluster(memvault_core::ClusterId(arr))
        }
        IssueGrantAudience::Peer { peer_id } => {
            let bytes = hex::decode(&peer_id)
                .map_err(|_| ApiError::bad_request("peer_id hex"))?;
            memvault_auth::GrantAudience::Peer(memvault_core::PeerId(bytes))
        }
        IssueGrantAudience::Agent { agent_id } => {
            memvault_auth::GrantAudience::Agent(memvault_core::AgentId(agent_id))
        }
        IssueGrantAudience::Role { role } => {
            let parsed = match role.as_str() {
                "agent-host" | "agenthost" => memvault_auth::AgentRole::AgentHost,
                "auditor" => memvault_auth::AgentRole::Auditor,
                "service" => memvault_auth::AgentRole::Service,
                "admin" => memvault_auth::AgentRole::Admin,
                other => {
                    return Err(ApiError::bad_request(format!(
                        "unknown role: {other}"
                    )));
                }
            };
            memvault_auth::GrantAudience::Role(parsed)
        }
    };

    let actions: Vec<memvault_auth::Action> = req
        .actions
        .iter()
        .map(|a| match a.as_str() {
            "read" => Ok(memvault_auth::Action::Read),
            "write" => Ok(memvault_auth::Action::Write),
            "admin" => Ok(memvault_auth::Action::Admin),
            "egress" => Ok(memvault_auth::Action::Egress),
            other => Err(ApiError::bad_request(format!("unknown action: {other}"))),
        })
        .collect::<Result<_, _>>()?;

    let cid = state
        .client
        .bucket_grant(&bucket_id, audience, actions, req.ttl_secs)
        .await
        .map_err(|e| ApiError::internal(format!("issue grant: {e}")))?;

    Ok((
        StatusCode::CREATED,
        Json(serde_json::json!({ "grant_cid": hex::encode(cid) })),
    ))
}

/// POST /api/v1/buckets/{id}/grants — submit an externally-signed grant.
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
) -> Result<(StatusCode, Json<serde_json::Value>), ApiError> {
    let bucket_bytes =
        hex::decode(&id).map_err(|_| ApiError::bad_request("invalid bucket id hex"))?;
    let bucket_arr: [u8; 32] = bucket_bytes
        .try_into()
        .map_err(|_| ApiError::bad_request("bucket id must be 32 bytes"))?;

    let grant_bytes = hex::decode(&req.grant_cbor_hex)
        .map_err(|_| ApiError::bad_request("grant_cbor_hex is not hex"))?;
    let grant: memvault_auth::Grant = serde_ipld_dagcbor::from_slice(&grant_bytes)
        .map_err(|e| ApiError::bad_request(format!("grant decode: {e}")))?;

    // The grant must scope exactly the bucket in the path.
    if grant.bucket_scopes.as_slice() != [memvault_core::BucketId(bucket_arr)] {
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
    let cid = client.submit_signed_grant(&grant).map_err(|e| match e {
        memvault_api::ApiError::Forbidden(m) => ApiError {
            status: StatusCode::FORBIDDEN,
            message: m,
        },
        other => ApiError::bad_request(other.to_string()),
    })?;
    Ok((
        StatusCode::CREATED,
        Json(serde_json::json!({ "grant_cid": hex::encode(cid) })),
    ))
}

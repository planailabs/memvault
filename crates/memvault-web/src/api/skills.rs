//! Skill endpoints.
//!
//! Thin HTTP surface over `MemvaultClient`'s first-class skill API. Each
//! handler just resolves auth + parses ids, then calls `state.client.skill_*`
//! — the composition logic lives in the client layer (server-side
//! `LocalClient`), so these handlers are pure pass-through. The `HttpApiClient`
//! skill methods thread through to exactly these routes (one round trip each).

use std::sync::Arc;

use axum::Json;
use axum::extract::{Path, Query, State};
use memvault_core::{EntityId, NodeRef};
use serde::Deserialize;

use crate::AppState;
use crate::api::auth::{RequireAuth, RequireWrite};
use crate::error::ApiError;
use memvault_api::{SkillBundle, SkillInfo, SkillSpec};

#[derive(Deserialize)]
pub struct PublishSkillRequest {
    #[serde(flatten)]
    pub spec: SkillSpec,
    #[serde(default)]
    pub visibility: Option<String>,
    #[serde(default)]
    pub bucket: Option<String>,
}

#[derive(Deserialize)]
pub struct ListSkillsQuery {
    pub limit: Option<usize>,
    pub bucket: Option<String>,
}

#[derive(Deserialize)]
pub struct RenameSkillRequest {
    pub name: String,
}

#[derive(Deserialize)]
pub struct DeleteSkillQuery {
    pub reason: Option<String>,
}

#[derive(Deserialize)]
pub struct LinkResourceRequest {
    /// Target node — "doc:<hex>", "file:<hex>", or "entity:<hex>".
    pub node: String,
    pub relation: String,
    #[serde(default)]
    pub path: Option<String>,
    #[serde(default)]
    pub executable: bool,
    #[serde(default)]
    pub visibility: Option<String>,
}

fn parse_bucket(hex_str: Option<&str>) -> Option<memvault_core::BucketId> {
    let bytes = hex::decode(hex_str?).ok()?;
    let arr: [u8; 32] = bytes.try_into().ok()?;
    Some(memvault_core::BucketId(arr))
}

fn parse_skill_id(input: &str) -> Result<EntityId, ApiError> {
    EntityId::from_hex(input)
        .map_err(|_| ApiError::bad_request("Invalid skill ID — expected hex or entity:<hex>"))
}

/// POST /api/v1/skills — publish a new skill.
pub async fn publish_skill(
    auth: RequireWrite,
    State(state): State<Arc<AppState>>,
    Json(req): Json<PublishSkillRequest>,
) -> Result<(axum::http::StatusCode, Json<serde_json::Value>), ApiError> {
    let vis = super::docs::parse_visibility_str(req.visibility.as_deref());
    let bucket = parse_bucket(req.bucket.as_deref());
    if let Some(bid) = &bucket {
        crate::api::auth::enforce_bucket_action(&auth.claims, bid, memvault_auth::Action::Write)?;
    }
    let id = state
        .client
        .skill_publish(req.spec, vis, bucket.as_ref())
        .await?;
    let node_id = format!("entity:{}", hex::encode(id.0));
    Ok((
        axum::http::StatusCode::CREATED,
        Json(serde_json::json!({ "id": node_id })),
    ))
}

/// GET /api/v1/skills — list skills (manifest summaries).
pub async fn list_skills(
    auth: RequireAuth,
    State(state): State<Arc<AppState>>,
    Query(params): Query<ListSkillsQuery>,
) -> Result<Json<Vec<SkillInfo>>, ApiError> {
    let limit = params.limit.unwrap_or(500);
    let bucket = parse_bucket(params.bucket.as_deref());
    let skills = state.client.skill_list(limit, bucket.as_ref()).await?;
    let skills = crate::api::auth::filter_readable(&auth.claims, skills, |s| {
        format!("entity:{}", hex::encode(s.id.0))
    })?;
    Ok(Json(skills))
}

/// GET /api/v1/skills/:id — assemble a skill bundle.
pub async fn get_skill(
    auth: RequireAuth,
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<Json<SkillBundle>, ApiError> {
    let skill_id = parse_skill_id(&id)?;
    crate::api::auth::enforce_entity_action(&auth.claims, &skill_id, memvault_auth::Action::Read)?;
    let bundle = state
        .client
        .skill_get(&skill_id)
        .await?
        .ok_or_else(|| ApiError::not_found("Skill not found"))?;
    Ok(Json(bundle))
}

/// PATCH /api/v1/skills/:id — rename a skill.
pub async fn rename_skill(
    auth: RequireWrite,
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Json(req): Json<RenameSkillRequest>,
) -> Result<axum::http::StatusCode, ApiError> {
    let skill_id = parse_skill_id(&id)?;
    crate::api::auth::enforce_entity_action(&auth.claims, &skill_id, memvault_auth::Action::Write)?;
    state.client.skill_rename(&skill_id, &req.name).await?;
    Ok(axum::http::StatusCode::NO_CONTENT)
}

/// DELETE /api/v1/skills/:id — retract a skill.
pub async fn delete_skill(
    auth: RequireWrite,
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Query(params): Query<DeleteSkillQuery>,
) -> Result<axum::http::StatusCode, ApiError> {
    let skill_id = parse_skill_id(&id)?;
    crate::api::auth::enforce_entity_action(&auth.claims, &skill_id, memvault_auth::Action::Write)?;
    let reason = params.reason.as_deref().unwrap_or("deleted via API");
    state.client.skill_delete(&skill_id, reason).await?;
    Ok(axum::http::StatusCode::NO_CONTENT)
}

/// POST /api/v1/skills/:id/resources — link a node to the skill.
pub async fn link_resource(
    auth: RequireWrite,
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Json(req): Json<LinkResourceRequest>,
) -> Result<(axum::http::StatusCode, Json<serde_json::Value>), ApiError> {
    let skill_id = parse_skill_id(&id)?;
    crate::api::auth::enforce_entity_action(&auth.claims, &skill_id, memvault_auth::Action::Write)?;
    let target = NodeRef::from_tag_label(&req.node)
        .ok_or_else(|| ApiError::bad_request("Invalid node: expected 'type:hex'"))?;
    let vis = super::docs::parse_visibility_str(req.visibility.as_deref());
    let edge_id = state
        .client
        .skill_link_resource(
            &skill_id,
            &target,
            &req.relation,
            req.path.as_deref(),
            req.executable,
            vis,
        )
        .await?;
    Ok((
        axum::http::StatusCode::CREATED,
        Json(serde_json::json!({ "edge_id": hex::encode(edge_id.0) })),
    ))
}

/// DELETE /api/v1/skills/:id/resources/:edge_id — unlink a node.
pub async fn unlink_resource(
    auth: RequireWrite,
    State(state): State<Arc<AppState>>,
    Path((id, edge_id)): Path<(String, String)>,
) -> Result<axum::http::StatusCode, ApiError> {
    let skill_id = parse_skill_id(&id)?;
    crate::api::auth::enforce_entity_action(&auth.claims, &skill_id, memvault_auth::Action::Write)?;
    let edge_bytes = hex::decode(&edge_id)
        .map_err(|_| ApiError::bad_request("Invalid edge id (expected hex)"))?;
    let arr: [u8; 32] = edge_bytes
        .try_into()
        .map_err(|_| ApiError::bad_request("Invalid edge id length"))?;
    state
        .client
        .skill_unlink_resource(&skill_id, &memvault_core::EdgeId(arr))
        .await?;
    Ok(axum::http::StatusCode::NO_CONTENT)
}

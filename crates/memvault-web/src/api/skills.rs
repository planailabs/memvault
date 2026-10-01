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
use axum::http::StatusCode;
use memvault_api::rest::{
    EdgeCreated, LinkResourceRequest, NodeCreated, PublishSkillRequest, ReasonParams, RenameRequest,
};
use memvault_core::{EntityId, NodeRef};
use serde::Deserialize;

use crate::AppState;
use crate::api::auth::{RequireAuth, RequireWrite};
use crate::error::ApiError;
use memvault_api::{SkillBundle, SkillInfo};

#[derive(Deserialize)]
pub struct ListSkillsQuery {
    pub limit: Option<usize>,
    pub bucket: Option<String>,
}

fn parse_skill_id(input: &str) -> Result<EntityId, ApiError> {
    EntityId::from_hex(input)
        .map_err(|_| ApiError::bad_request("Invalid skill ID — expected hex or entity:<hex>"))
}

/// POST /api/v1/skills — publish a new skill; 201 with its `node_id`.
pub async fn publish_skill(
    auth: RequireWrite,
    State(state): State<Arc<AppState>>,
    Json(req): Json<PublishSkillRequest>,
) -> Result<(StatusCode, Json<NodeCreated>), ApiError> {
    let vis = super::docs::parse_visibility_str(req.visibility.as_deref());
    // No bucket named: the caller's agent bucket, like `POST /docs`.
    let named = crate::api::auth::parse_bucket_param(req.bucket.as_deref())?;
    let bucket = crate::api::auth::write_bucket(&state, &auth.claims, named).await?;
    let id = state
        .client
        .skill_publish(req.spec, vis, Some(&bucket))
        .await?;
    Ok((
        StatusCode::CREATED,
        Json(NodeCreated {
            node_id: NodeRef::Entity(id).tag_label(),
        }),
    ))
}

/// GET /api/v1/skills — list skills (manifest summaries).
pub async fn list_skills(
    auth: RequireAuth,
    State(state): State<Arc<AppState>>,
    Query(params): Query<ListSkillsQuery>,
) -> Result<Json<Vec<SkillInfo>>, ApiError> {
    let limit = params.limit.unwrap_or(500);
    // No bucket named: the caller's agent bucket (admins: every bucket),
    // read-filtered before the limit.
    let named = crate::api::auth::parse_bucket_param(params.bucket.as_deref())?;
    let bucket = crate::api::auth::read_bucket(&state, &auth.claims, named).await?;
    let mut readable = crate::api::auth::Readable::new(&auth.claims)?;
    let skills = crate::api::auth::fetch_kept(
        limit,
        |n| {
            let (state, bucket) = (&state, bucket.as_ref());
            async move { Ok(state.client.skill_list(n, bucket).await?) }
        },
        |s: &SkillInfo| readable.node(&format!("entity:{}", hex::encode(s.id.0))),
    )
    .await?;
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
    Json(req): Json<RenameRequest>,
) -> Result<StatusCode, ApiError> {
    let skill_id = parse_skill_id(&id)?;
    crate::api::auth::enforce_entity_action(&auth.claims, &skill_id, memvault_auth::Action::Write)?;
    state.client.skill_rename(&skill_id, &req.name).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// DELETE /api/v1/skills/:id — retract a skill.
pub async fn delete_skill(
    auth: RequireWrite,
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Query(params): Query<ReasonParams>,
) -> Result<StatusCode, ApiError> {
    let skill_id = parse_skill_id(&id)?;
    crate::api::auth::enforce_entity_action(&auth.claims, &skill_id, memvault_auth::Action::Write)?;
    let reason = params.reason.as_deref().unwrap_or("deleted via API");
    state.client.skill_delete(&skill_id, reason).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// POST /api/v1/skills/:id/resources — link a node to the skill.
pub async fn link_resource(
    auth: RequireWrite,
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Json(req): Json<LinkResourceRequest>,
) -> Result<(StatusCode, Json<EdgeCreated>), ApiError> {
    let skill_id = parse_skill_id(&id)?;
    crate::api::auth::enforce_entity_action(&auth.claims, &skill_id, memvault_auth::Action::Write)?;
    let target = NodeRef::from_tag_label(&req.node)
        .ok_or_else(|| ApiError::bad_request("Invalid node: expected 'type:hex'"))?;
    // The resource is read through the skill: the caller must be able to.
    crate::api::auth::enforce_node_action(&auth.claims, &req.node, memvault_auth::Action::Read)?;
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
    Ok((StatusCode::CREATED, Json(EdgeCreated { edge_id })))
}

/// DELETE /api/v1/skills/:id/resources/:edge_id — unlink a node.
pub async fn unlink_resource(
    auth: RequireWrite,
    State(state): State<Arc<AppState>>,
    Path((id, edge_id)): Path<(String, String)>,
) -> Result<StatusCode, ApiError> {
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
    Ok(StatusCode::NO_CONTENT)
}

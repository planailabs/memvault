//! Knowledge graph endpoints.

use std::collections::BTreeMap;
use std::sync::Arc;

use axum::extract::{Path, State};
use axum::Json;
use memvault_core::EntityId;
use memvault_doc::Entity;
use serde::{Deserialize, Serialize};

use crate::api::auth::RequireAuth;
use crate::error::ApiError;
use crate::AppState;

#[derive(Deserialize)]
pub struct ListEntitiesQuery {
    pub kind: Option<String>,
    pub limit: Option<usize>,
}

#[derive(Deserialize)]
pub struct CreateEntityRequest {
    pub kind: String,
    #[serde(default)]
    pub props: BTreeMap<String, serde_json::Value>,
    pub visibility: Option<String>,
}

#[derive(Serialize)]
pub struct EntityResponse {
    pub id: String,
    pub kind: String,
    pub props: BTreeMap<String, serde_json::Value>,
    pub edges: Vec<EdgeResponse>,
}

#[derive(Serialize)]
pub struct EdgeResponse {
    pub id: String,
    pub relation: String,
    pub target: String,
    pub weight: Option<f32>,
    pub props: BTreeMap<String, serde_json::Value>,
}

#[derive(Deserialize)]
pub struct UpdateEntityRequest {
    #[serde(default)]
    pub props: BTreeMap<String, serde_json::Value>,
}

/// POST /api/v1/entities
pub async fn create_entity(
    _auth: RequireAuth,
    State(state): State<Arc<AppState>>,
    Json(req): Json<CreateEntityRequest>,
) -> Result<(axum::http::StatusCode, Json<serde_json::Value>), ApiError> {
    let entity = Entity {
        id: EntityId::random(),
        kind: req.kind,
        props: req.props,
        edges_out: vec![],
    };
    let vis = super::docs::parse_visibility_str(req.visibility.as_deref());
    let id = state.client.add_entity(entity, vis).await?;
    Ok((
        axum::http::StatusCode::CREATED,
        Json(serde_json::json!({ "id": hex::encode(id.0) })),
    ))
}

/// GET /api/v1/entities/:id
pub async fn get_entity(
    _auth: RequireAuth,
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<Json<EntityResponse>, ApiError> {
    let entity_id = parse_entity_id(&id)?;
    let entity = state
        .client
        .get_entity(&entity_id)
        .await?
        .ok_or_else(|| ApiError::not_found("Entity not found"))?;

    let edges = entity
        .edges_out
        .iter()
        .map(|e| EdgeResponse {
            id: hex::encode(e.id.0),
            relation: e.relation.clone(),
            target: e.target.tag_label(),
            weight: e.weight,
            props: e.props.clone(),
        })
        .collect();

    Ok(Json(EntityResponse {
        id: hex::encode(entity.id.0),
        kind: entity.kind,
        props: entity.props,
        edges,
    }))
}

/// DELETE /api/v1/entities/:id
pub async fn delete_entity(
    _auth: RequireAuth,
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let entity_id = parse_entity_id(&id)?;
    // Retract entity by its ID bytes
    let cid = state
        .client
        .retract(&entity_id.0, "deleted via API")
        .await?;
    Ok(Json(serde_json::json!({ "cid": hex::encode(&cid) })))
}


fn parse_entity_id(hex_str: &str) -> Result<EntityId, ApiError> {
    let bytes = hex::decode(hex_str).map_err(|_| ApiError::bad_request("Invalid entity ID"))?;
    if bytes.len() != 32 {
        return Err(ApiError::bad_request("Entity ID must be 32 bytes"));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(EntityId(arr))
}


//! Knowledge graph endpoints.

use std::collections::BTreeMap;
use std::sync::Arc;

use axum::Json;
use axum::extract::{Path, State};
use memvault_core::EntityId;
use memvault_doc::Entity;
use serde::{Deserialize, Serialize};

use crate::AppState;
use crate::api::auth::RequireAuth;
use crate::error::ApiError;

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
    /// Optional VFS path to place the new entity at.
    #[serde(default)]
    pub vfs_path: Option<String>,
    /// Optional bucket ID (hex).
    #[serde(default)]
    pub bucket: Option<String>,
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
    let kind = req.kind;
    let entity = Entity {
        id: EntityId::random(),
        kind: kind.clone(),
        props: req.props,
        edges_out: vec![],
    };
    let vis = super::docs::parse_visibility_str(req.visibility.as_deref());
    let bucket_id = req.bucket.as_deref().and_then(|h| {
        let bytes = hex::decode(h).ok()?;
        if bytes.len() != 32 {
            return None;
        }
        let mut a = [0u8; 32];
        a.copy_from_slice(&bytes);
        Some(memvault_core::BucketId(a))
    });
    let id = state
        .client
        .add_entity(entity, vis, bucket_id.as_ref())
        .await?;
    let node_id = format!("entity:{}", hex::encode(id.0));
    tracing::info!(kind = %kind, "API: entity created");

    if let Some(vfs_path) = &req.vfs_path {
        let bucket = memvault_api::vfs::default_bucket(state.client.as_ref()).await;
        if let Err(e) =
            memvault_api::vfs::link_node_at_path(state.client.as_ref(), &bucket, vfs_path, &node_id)
                .await
        {
            tracing::warn!(path = %vfs_path, error = %e, "VFS link failed after entity creation");
        }
    }

    Ok((
        axum::http::StatusCode::CREATED,
        Json(serde_json::json!({ "id": node_id })),
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
        id: format!("entity:{}", hex::encode(entity.id.0)),
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

/// Parse an entity ID from either "entity:<hex>" or raw "<hex>" format.
fn parse_entity_id(input: &str) -> Result<EntityId, ApiError> {
    let hex_str = input.strip_prefix("entity:").unwrap_or(input);
    let bytes = hex::decode(hex_str)
        .map_err(|_| ApiError::bad_request("Invalid entity ID — expected hex or entity:<hex>"))?;
    if bytes.len() != 32 {
        return Err(ApiError::bad_request("Entity ID must be 32 bytes"));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(EntityId(arr))
}

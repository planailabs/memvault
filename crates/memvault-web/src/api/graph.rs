//! Knowledge graph endpoints.

use std::collections::BTreeMap;
use std::sync::Arc;

use axum::Json;
use axum::extract::{Path, Query, State};
use memvault_core::{EntityId, NodeRef};
use memvault_doc::Entity;
use serde::{Deserialize, Serialize};

use crate::AppState;
use crate::api::auth::{RequireAuth, RequireWrite};
use crate::error::ApiError;

#[derive(Deserialize)]
pub struct ListEntitiesQuery {
    pub kind: Option<String>,
    pub limit: Option<usize>,
    /// Optional bucket ID (hex) to scope the listing.
    pub bucket: Option<String>,
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

#[derive(Deserialize)]
pub struct TraverseQuery {
    /// Start node — "entity:<hex>", "doc:<hex>", or "attachment:<hex>".
    pub from: String,
    pub relation: Option<String>,
    pub max_depth: Option<usize>,
}

/// GET /api/v1/traverse?from=<label>&relation=&max_depth=
///
/// Walks the graph from a node. Backs `MemvaultClient::traverse_from` and the
/// `memvault_traverse` MCP tool over HTTP.
pub async fn traverse(
    auth: RequireAuth,
    State(state): State<Arc<AppState>>,
    Query(params): Query<TraverseQuery>,
) -> Result<Json<Vec<serde_json::Value>>, ApiError> {
    let from = NodeRef::from_tag_label(&params.from)
        .ok_or_else(|| ApiError::bad_request("Invalid from: expected 'type:hex'"))?;
    crate::api::auth::enforce_node_action(&auth.claims, &params.from, memvault_auth::Action::Read)?;
    let hits = state
        .client
        .traverse_from(&from, params.relation.as_deref(), params.max_depth.unwrap_or(2))
        .await?;
    let results: Vec<serde_json::Value> = hits
        .into_iter()
        .map(|h| {
            serde_json::json!({
                "node": h.node.tag_label(),
                "depth": h.depth,
                "path": h
                    .path
                    .iter()
                    .map(|(eid, rel)| serde_json::json!([hex::encode(eid.0), rel]))
                    .collect::<Vec<_>>(),
            })
        })
        .collect();
    Ok(Json(results))
}

/// GET /api/v1/entities?limit=&kind=&bucket=<hex>
///
/// Lists entities (full `kind` + `props`), optionally scoped to a bucket and
/// filtered by kind. Backs `MemvaultClient::list_entities` (and thus the
/// `memvault_list_entities` MCP tool and VFS root discovery) over HTTP.
pub async fn list_entities(
    auth: RequireAuth,
    State(state): State<Arc<AppState>>,
    Query(params): Query<ListEntitiesQuery>,
) -> Result<Json<Vec<EntityResponse>>, ApiError> {
    let limit = params.limit.unwrap_or(500);
    let bucket = params.bucket.as_deref().and_then(|h| {
        let bytes = hex::decode(h).ok()?;
        let arr: [u8; 32] = bytes.try_into().ok()?;
        Some(memvault_core::BucketId(arr))
    });
    let entities = state.client.list_entities(limit, bucket.as_ref()).await?;
    let results: Vec<EntityResponse> = entities
        .into_iter()
        .filter(|e| params.kind.as_deref().is_none_or(|k| e.kind == k))
        .map(|e| EntityResponse {
            id: format!("entity:{}", hex::encode(e.id.0)),
            kind: e.kind,
            props: e.props,
            edges: vec![],
        })
        .collect();
    let results = crate::api::auth::filter_readable(&auth.claims, results, |r| r.id.clone())?;
    Ok(Json(results))
}

/// POST /api/v1/entities
pub async fn create_entity(
    auth: RequireWrite,
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
    if let Some(bid) = &bucket_id {
        crate::api::auth::enforce_bucket_action(&auth.claims, bid, memvault_auth::Action::Write)?;
    }
    let id = state
        .client
        .add_entity(entity, vis, bucket_id.as_ref())
        .await?;
    let node_id = format!("entity:{}", hex::encode(id.0));
    tracing::info!(kind = %kind, "API: entity created");

    if let Some(vfs_path) = &req.vfs_path {
        if let Some(bucket) = bucket_id.as_ref() {
            if let Err(e) =
                memvault_api::vfs::link_node_at_path(state.client.as_ref(), bucket, vfs_path, &node_id)
                    .await
            {
                tracing::warn!(path = %vfs_path, error = %e, "VFS link failed after entity creation");
            }
        } else {
            tracing::warn!(path = %vfs_path, "skipping VFS link: entity request omitted bucket");
        }
    }

    Ok((
        axum::http::StatusCode::CREATED,
        Json(serde_json::json!({ "id": node_id })),
    ))
}

/// GET /api/v1/entities/:id
pub async fn get_entity(
    auth: RequireAuth,
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<Json<EntityResponse>, ApiError> {
    let entity_id = parse_entity_id(&id)?;
    crate::api::auth::enforce_entity_action(&auth.claims, &entity_id, memvault_auth::Action::Read)?;
    let include_retracted = crate::api::auth::caller_sees_retracted(&state, &auth.claims);
    let entity = state
        .client
        .get_entity_scoped(&entity_id, &memvault_core::QueryScope::all().with_include_retracted(include_retracted))
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
    auth: RequireWrite,
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let entity_id = parse_entity_id(&id)?;
    crate::api::auth::enforce_entity_action(&auth.claims, &entity_id, memvault_auth::Action::Write)?;
    // Retract entity by its ID bytes
    let cid = state
        .client
        .retract(&entity_id.0, "deleted via API")
        .await?;
    Ok(Json(serde_json::json!({ "cid": hex::encode(&cid) })))
}

/// Parse an entity ID from either "entity:<hex>" or raw "<hex>" format.
fn parse_entity_id(input: &str) -> Result<EntityId, ApiError> {
    EntityId::from_hex(input)
        .map_err(|_| ApiError::bad_request("Invalid entity ID — expected hex or entity:<hex>"))
}

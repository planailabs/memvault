//! Knowledge graph endpoints.

use std::sync::Arc;

use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use memvault_api::rest::{CreateEntityRequest, ListEntitiesParams, NodeCreated, ScopeParams};
use memvault_api::wire::{AuditRecordWire, EntityWire};
use memvault_core::{EntityId, NodeRef};
use memvault_doc::Entity;
use serde::Deserialize;

use crate::AppState;
use crate::api::auth::{RequireAuth, RequireWrite};
use crate::error::ApiError;

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
/// `memvault_traverse` MCP tool over HTTP; answers `TraversalHit`s.
pub async fn traverse(
    auth: RequireAuth,
    State(state): State<Arc<AppState>>,
    Query(params): Query<TraverseQuery>,
) -> Result<Json<Vec<memvault_api::TraversalHit>>, ApiError> {
    let from = NodeRef::from_tag_label(&params.from)
        .ok_or_else(|| ApiError::bad_request("Invalid from: expected 'type:hex'"))?;
    crate::api::auth::enforce_node_action(&auth.claims, &params.from, memvault_auth::Action::Read)?;
    // The walk itself, here rather than `traverse_from`, so a node the caller
    // may not read is neither returned nor walked through.
    let mut readable = crate::api::auth::Readable::new(&auth.claims)?;
    let max_depth = params.max_depth.unwrap_or(2);
    let mut hits: Vec<memvault_api::TraversalHit> = Vec::new();
    let mut visited = std::collections::HashSet::from([from.clone()]);
    let mut queue = std::collections::VecDeque::from([(from, 0usize, Vec::new())]);
    while let Some((node, depth, path)) = queue.pop_front() {
        if depth > 0 {
            hits.push(memvault_api::TraversalHit {
                node: node.clone(),
                depth,
                path: path.clone(),
            });
        }
        if depth >= max_depth {
            continue;
        }
        for (source, edge) in state.client.edges_of(&node).await? {
            if source != node
                || params
                    .relation
                    .as_deref()
                    .is_some_and(|r| edge.relation != r)
                || visited.contains(&edge.target)
                || !readable.node(&edge.target.tag_label())
            {
                continue;
            }
            visited.insert(edge.target.clone());
            let mut next = path.clone();
            next.push((edge.id.clone(), edge.relation.clone()));
            queue.push_back((edge.target, depth + 1, next));
        }
    }
    Ok(Json(hits))
}

/// GET /api/v1/entities?limit=&kind=&bucket=<hex>&include_retracted=
///
/// Lists entities (full `kind` + `props`), optionally scoped to a bucket and
/// filtered by kind. Backs `MemvaultClient::list_entities{,_ex}` (and thus
/// the `memvault_list_entities` MCP tool and VFS root discovery) over HTTP.
pub async fn list_entities(
    auth: RequireAuth,
    State(state): State<Arc<AppState>>,
    Query(params): Query<ListEntitiesParams>,
) -> Result<Json<Vec<EntityWire>>, ApiError> {
    let limit = params.limit.unwrap_or(500);
    // No bucket named: the caller's agent bucket (admins: every bucket).
    let named = crate::api::auth::parse_bucket_param(params.bucket.as_deref())?;
    let bucket = crate::api::auth::read_bucket(&state, &auth.claims, named).await?;
    // Retracted entities only for callers who may see them (on request; by
    // default, included).
    let include_retracted = crate::api::auth::caller_sees_retracted(&state, &auth.claims)
        && params.include_retracted.unwrap_or(true);
    // The generic HTTP entity list returns all kinds (it's the low-level API +
    // introspection surface). Reserved kinds (skill, vfs:dir) are hidden from
    // the graph *view* at the presentation layer instead — the web graph
    // explorer and the MCP list_entities tool both filter them. The kind and
    // read filters apply before the limit.
    let mut readable = crate::api::auth::Readable::new(&auth.claims)?;
    let entities = crate::api::auth::fetch_kept(
        limit,
        |n| {
            let state = &state;
            let bucket = bucket.as_ref();
            async move {
                Ok(state
                    .client
                    .list_entities_ex(n, bucket, include_retracted)
                    .await?)
            }
        },
        |e: &Entity| {
            params.kind.as_deref().is_none_or(|k| e.kind == k)
                && readable.node(&format!("entity:{}", hex::encode(e.id.0)))
        },
    )
    .await?;
    Ok(Json(entities.iter().map(EntityWire::summary).collect()))
}

/// POST /api/v1/entities — 201 with the new entity's `node_id`.
pub async fn create_entity(
    auth: RequireWrite,
    State(state): State<Arc<AppState>>,
    Json(req): Json<CreateEntityRequest>,
) -> Result<(StatusCode, Json<NodeCreated>), ApiError> {
    let kind = req.kind;
    let entity = Entity {
        id: EntityId::random(),
        kind: kind.clone(),
        props: req.props,
        edges_out: vec![],
    };
    let vis = super::docs::parse_visibility_str(req.visibility.as_deref());
    // No bucket named: the caller's agent bucket, like `POST /docs`.
    let named = crate::api::auth::parse_bucket_param(req.bucket.as_deref())?;
    let bucket_id = crate::api::auth::write_bucket(&state, &auth.claims, named).await?;
    // Validated create: rejects reserved kinds (skill, vfs:dir). Safe to guard
    // here now that VFS/skills no longer ride this endpoint — they use their
    // own /vfs and /skills endpoints, so this is purely the generic node API.
    let id = state
        .client
        .add_entity(entity, vis, Some(&bucket_id))
        .await?;
    let node_id = NodeRef::Entity(id).tag_label();
    tracing::info!(kind = %kind, "API: entity created");

    if let Some(vfs_path) = &req.vfs_path {
        if let Err(e) = memvault_api::vfs::link_node_at_path(
            state.client.as_ref(),
            &bucket_id,
            vfs_path,
            &node_id,
        )
        .await
        {
            tracing::warn!(path = %vfs_path, error = %e, "VFS link failed after entity creation");
        }
    }

    Ok((StatusCode::CREATED, Json(NodeCreated { node_id })))
}

/// GET /api/v1/entities/:id — the entity with its out-edges, in the scope
/// asked for ([`ScopeParams`]).
pub async fn get_entity(
    auth: RequireAuth,
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Query(scope): Query<ScopeParams>,
) -> Result<Json<EntityWire>, ApiError> {
    let entity_id = parse_entity_id(&id)?;
    crate::api::auth::enforce_entity_action(&auth.claims, &entity_id, memvault_auth::Action::Read)?;
    let scope = crate::api::auth::scope_from_params(&state, &auth.claims, &scope, false).await?;
    let entity = state
        .client
        .get_entity_scoped(&entity_id, &scope)
        .await?
        .ok_or_else(|| ApiError::not_found("Entity not found"))?;
    Ok(Json(EntityWire::with_edges(&entity)))
}

/// GET /api/v1/entities/:id/history — the entity's audit records.
pub async fn entity_history(
    auth: RequireAuth,
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<Json<Vec<AuditRecordWire>>, ApiError> {
    let entity_id = parse_entity_id(&id)?;
    crate::api::auth::enforce_entity_action(&auth.claims, &entity_id, memvault_auth::Action::Read)?;
    let records = state.client.entity_history(&entity_id).await?;
    Ok(Json(records.iter().map(AuditRecordWire::from).collect()))
}

/// DELETE /api/v1/entities/:id — retract; 204.
pub async fn delete_entity(
    auth: RequireWrite,
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<StatusCode, ApiError> {
    let entity_id = parse_entity_id(&id)?;
    crate::api::auth::enforce_entity_action(
        &auth.claims,
        &entity_id,
        memvault_auth::Action::Write,
    )?;
    // External (validated) node retract: refuses reserved kinds (skill,
    // vfs:dir), which must be removed via their dedicated API.
    let node_id = NodeRef::Entity(entity_id).tag_label();
    state
        .client
        .retract_node(&node_id, "deleted via API")
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Parse an entity ID from either "entity:<hex>" or raw "<hex>" format.
fn parse_entity_id(input: &str) -> Result<EntityId, ApiError> {
    EntityId::from_hex(input)
        .map_err(|_| ApiError::bad_request("Invalid entity ID — expected hex or entity:<hex>"))
}

//! Cross-type link endpoints — create, list, and remove edges between any node types.

use std::collections::BTreeMap;
use std::sync::Arc;

use axum::Json;
use axum::extract::{Path, Query, State};
use memvault_core::{EdgeId, NodeRef};
use memvault_doc::Edge;
use serde::{Deserialize, Serialize};

use crate::AppState;
use crate::api::auth::{RequireAuth, RequireWrite};
use crate::error::ApiError;

#[derive(Deserialize)]
pub struct CreateLinkRequest {
    /// Source node as "entity:<hex>", "doc:<hex>", or "attachment:<hex>".
    pub source: String,
    /// Target node — same format as source.
    pub target: String,
    /// Relation type (e.g. "references", "evidence_for", "related_to").
    pub relation: String,
    /// Optional edge weight (0.0–1.0).
    pub weight: Option<f32>,
    /// Optional edge properties.
    #[serde(default)]
    pub props: BTreeMap<String, serde_json::Value>,
    /// Visibility level.
    pub visibility: Option<String>,
}

#[derive(Serialize)]
pub struct LinkResponse {
    pub edge_id: String,
    pub source: String,
    pub target: String,
    pub relation: String,
    pub weight: Option<f32>,
    pub props: BTreeMap<String, serde_json::Value>,
}

#[derive(Deserialize)]
pub struct LinksQuery {
    /// Node to query — "entity:<hex>", "doc:<hex>", or "attachment:<hex>".
    pub node: String,
}

#[derive(Deserialize)]
pub struct DeleteLinkQuery {
    /// Source node — required to identify which node's edge to remove.
    pub source: String,
}

/// POST /api/v1/links — create an edge between any two nodes.
pub async fn create_link(
    auth: RequireWrite,
    State(state): State<Arc<AppState>>,
    Json(req): Json<CreateLinkRequest>,
) -> Result<(axum::http::StatusCode, Json<serde_json::Value>), ApiError> {
    let source = NodeRef::from_tag_label(&req.source).ok_or_else(|| {
        ApiError::bad_request(
            "Invalid source: expected 'entity:<hex>', 'doc:<hex>', or 'attachment:<hex>'",
        )
    })?;
    let target = NodeRef::from_tag_label(&req.target).ok_or_else(|| {
        ApiError::bad_request(
            "Invalid target: expected 'entity:<hex>', 'doc:<hex>', or 'attachment:<hex>'",
        )
    })?;

    // ACL: writing an edge mutates the source node's bucket, and reads the
    // target — require Write on the source and at least Read on the target.
    crate::api::auth::enforce_node_action(
        &auth.claims,
        &req.source,
        memvault_auth::Action::Write,
    )?;
    crate::api::auth::enforce_node_action(
        &auth.claims,
        &req.target,
        memvault_auth::Action::Read,
    )?;

    let vis = super::docs::parse_visibility_str(req.visibility.as_deref());

    let relation = req.relation;
    let edge = Edge {
        id: EdgeId::random(),
        relation: relation.clone(),
        target,
        weight: req.weight,
        props: req.props,
        provenance: None,
    };

    let edge_id = state.client.add_link(&source, edge, vis).await?;
    tracing::info!(source = %req.source, target = %req.target, relation = %relation, "API: link created");
    Ok((
        axum::http::StatusCode::CREATED,
        Json(serde_json::json!({ "edge_id": hex::encode(edge_id.0) })),
    ))
}

/// GET /api/v1/links?node=entity:<hex> — list all edges touching a node.
pub async fn list_links(
    auth: RequireAuth,
    State(state): State<Arc<AppState>>,
    Query(params): Query<LinksQuery>,
) -> Result<Json<Vec<LinkResponse>>, ApiError> {
    let node = NodeRef::from_tag_label(&params.node).ok_or_else(|| {
        ApiError::bad_request(
            "Invalid node: expected 'entity:<hex>', 'doc:<hex>', or 'attachment:<hex>'",
        )
    })?;
    crate::api::auth::enforce_node_action(&auth.claims, &params.node, memvault_auth::Action::Read)?;

    let edges = state.client.edges_of(&node).await?;

    let results: Vec<LinkResponse> = edges
        .into_iter()
        .map(|(source, edge)| LinkResponse {
            edge_id: hex::encode(edge.id.0),
            source: source.tag_label(),
            target: edge.target.tag_label(),
            relation: edge.relation,
            weight: edge.weight,
            props: edge.props,
        })
        .collect();

    Ok(Json(results))
}

#[derive(Deserialize)]
pub struct ListNodesQuery {
    pub view: Option<String>,
    pub limit: Option<usize>,
    /// Optional bucket id (hex) to scope the listing (standards/bucket-scoping.md).
    pub bucket: Option<String>,
}

/// GET /api/v1/nodes/:node_id — get any node by type:hex ID.
pub async fn get_node(
    auth: RequireAuth,
    State(state): State<Arc<AppState>>,
    Path(node_id): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    tracing::debug!(node_id = %node_id, "API: get node");
    let node_ref = NodeRef::from_tag_label(&node_id).ok_or_else(|| {
        ApiError::bad_request(
            "Invalid node ID — expected 'entity:<hex>', 'doc:<hex>', or 'attachment:<hex>'",
        )
    })?;
    crate::api::auth::enforce_node_action(&auth.claims, &node_id, memvault_auth::Action::Read)?;
    let include_retracted = crate::api::auth::caller_sees_retracted(&state, &auth.claims);

    match node_ref {
        NodeRef::Entity(eid) => {
            let entity = state
                .client
                .get_entity_scoped(&eid, &memvault_core::QueryScope::all().with_include_retracted(include_retracted))
                .await?
                .ok_or_else(|| ApiError::not_found("Entity not found"))?;
            Ok(Json(serde_json::json!({
                "node_id": node_id,
                "node_type": "entity",
                "kind": entity.kind,
                "props": entity.props,
                "edges": entity.edges_out.iter().map(|e| serde_json::json!({
                    "edge_id": hex::encode(e.id.0),
                    "relation": e.relation,
                    "target": e.target.tag_label(),
                    "weight": e.weight,
                })).collect::<Vec<_>>(),
                "tags": state.client.get_tags(&node_id).await.unwrap_or_default(),
            })))
        }
        NodeRef::Doc(did) => {
            let doc = state
                .client
                .get_doc_scoped(&did, &memvault_core::QueryScope::all().with_include_retracted(include_retracted))
                .await?
                .ok_or_else(|| ApiError::not_found("Document not found"))?;
            Ok(Json(serde_json::json!({
                "node_id": node_id,
                "node_type": "doc",
                "title": doc.frontmatter.get("title").and_then(|v| v.as_str()),
                "body": doc.body,
                "frontmatter": doc.frontmatter,
                "tags": state.client.get_tags(&node_id).await.unwrap_or_default(),
            })))
        }
        NodeRef::Attachment(cid) => {
            let manifest = state.client.get_file_manifest(&cid).await?;
            Ok(Json(serde_json::json!({
                "node_id": node_id,
                "node_type": "file",
                "manifest": manifest.map(|b| serde_json::from_slice::<serde_json::Value>(&b).ok()).flatten(),
                "tags": state.client.get_tags(&node_id).await.unwrap_or_default(),
            })))
        }
    }
}

/// GET /api/v1/nodes — list all nodes, optionally filtered by view.
pub async fn list_nodes(
    auth: RequireAuth,
    State(state): State<Arc<AppState>>,
    Query(params): Query<ListNodesQuery>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let limit = params.limit.unwrap_or(100);
    let include_retracted = crate::api::auth::caller_sees_retracted(&state, &auth.claims);
    // Optional bucket scope (standards/bucket-scoping.md): when present, the
    // listing is restricted to that bucket via QueryScope.
    let bucket = params.bucket.as_deref().and_then(|h| {
        let bytes = hex::decode(h).ok()?;
        let arr: [u8; 32] = bytes.try_into().ok()?;
        Some(memvault_core::BucketId(arr))
    });
    let items = state
        .client
        .list_scoped(
            &memvault_core::QueryScope::all()
                .with_view(params.view.clone())
                .with_bucket(bucket)
                .with_include_retracted(include_retracted),
            limit,
        )
        .await?;
    let items = crate::api::auth::filter_readable(&auth.claims, items, |n| n.node_id.clone())?;
    Ok(Json(serde_json::json!({
        "count": items.len(),
        "nodes": items.iter().map(|n| serde_json::json!({
            "node_id": n.node_id,
            "node_type": n.node_type,
            "label": n.label,
            "tags": n.tags,
        })).collect::<Vec<_>>(),
    })))
}

/// DELETE /api/v1/nodes/:node_id — retract (soft-delete) any node.
pub async fn retract_node(
    auth: RequireWrite,
    State(state): State<Arc<AppState>>,
    Path(node_id): Path<String>,
) -> Result<axum::http::StatusCode, ApiError> {
    crate::api::auth::enforce_node_action(&auth.claims, &node_id, memvault_auth::Action::Write)?;
    state
        .client
        .retract_node(&node_id, "retracted via API")
        .await?;
    tracing::info!(node_id = %node_id, "API: node retracted");
    Ok(axum::http::StatusCode::NO_CONTENT)
}

/// DELETE /api/v1/links/:edge_id?source=entity:<hex> — remove an edge by ID.
/// The source parameter is required because edges are indexed by source.
pub async fn delete_link(
    auth: RequireWrite,
    State(state): State<Arc<AppState>>,
    Path(edge_id_str): Path<String>,
    Query(params): Query<DeleteLinkQuery>,
) -> Result<axum::http::StatusCode, ApiError> {
    let bytes = hex::decode(&edge_id_str).map_err(|_| ApiError::bad_request("Invalid edge ID"))?;
    if bytes.len() != 32 {
        return Err(ApiError::bad_request("Edge ID must be 32 bytes"));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    let edge_id = EdgeId(arr);

    let source = NodeRef::from_tag_label(&params.source).ok_or_else(|| {
        ApiError::bad_request(
            "Invalid source: expected 'entity:<hex>', 'doc:<hex>', or 'attachment:<hex>'",
        )
    })?;
    crate::api::auth::enforce_node_action(&auth.claims, &params.source, memvault_auth::Action::Write)?;

    state.client.remove_link_from(&source, &edge_id).await?;

    Ok(axum::http::StatusCode::NO_CONTENT)
}

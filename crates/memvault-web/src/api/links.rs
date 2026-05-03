//! Cross-type link endpoints — create, list, and remove edges between any node types.

use std::collections::BTreeMap;
use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::Json;
use memvault_core::{EdgeId, NodeRef};
use memvault_doc::Edge;
use serde::{Deserialize, Serialize};

use crate::api::auth::RequireAuth;
use crate::error::ApiError;
use crate::AppState;

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

/// POST /api/v1/links — create an edge between any two nodes.
pub async fn create_link(
    _auth: RequireAuth,
    State(state): State<Arc<AppState>>,
    Json(req): Json<CreateLinkRequest>,
) -> Result<(axum::http::StatusCode, Json<serde_json::Value>), ApiError> {
    let source = NodeRef::from_tag_label(&req.source)
        .ok_or_else(|| ApiError::bad_request("Invalid source: expected 'entity:<hex>', 'doc:<hex>', or 'attachment:<hex>'"))?;
    let target = NodeRef::from_tag_label(&req.target)
        .ok_or_else(|| ApiError::bad_request("Invalid target: expected 'entity:<hex>', 'doc:<hex>', or 'attachment:<hex>'"))?;

    let vis = super::docs::parse_visibility_str(req.visibility.as_deref());

    let edge = Edge {
        id: EdgeId::random(),
        relation: req.relation,
        target,
        weight: req.weight,
        props: req.props,
        provenance: None,
    };

    let edge_id = state.client.add_link(&source, edge, vis).await?;
    Ok((
        axum::http::StatusCode::CREATED,
        Json(serde_json::json!({ "edge_id": hex::encode(edge_id.0) })),
    ))
}

/// GET /api/v1/links?node=entity:<hex> — list all edges touching a node.
pub async fn list_links(
    _auth: RequireAuth,
    State(state): State<Arc<AppState>>,
    Query(params): Query<LinksQuery>,
) -> Result<Json<Vec<LinkResponse>>, ApiError> {
    let node = NodeRef::from_tag_label(&params.node)
        .ok_or_else(|| ApiError::bad_request("Invalid node: expected 'entity:<hex>', 'doc:<hex>', or 'attachment:<hex>'"))?;

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

/// DELETE /api/v1/links/:edge_id — remove an edge by ID.
pub async fn delete_link(
    _auth: RequireAuth,
    State(state): State<Arc<AppState>>,
    Path(edge_id_str): Path<String>,
) -> Result<axum::http::StatusCode, ApiError> {
    let bytes = hex::decode(&edge_id_str).map_err(|_| ApiError::bad_request("Invalid edge ID"))?;
    if bytes.len() != 32 {
        return Err(ApiError::bad_request("Edge ID must be 32 bytes"));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    let edge_id = EdgeId(arr);

    // We need to find the source to remove the edge. Query by edge_id tag.
    // For now, use a simple approach: try to find the edge in edges_of results.
    // Since remove_link_from needs a source, we search for it.
    let edges = state.client.edges_of(&NodeRef::Entity(memvault_core::EntityId([0; 32]))).await;
    // Fallback: retract the edge by edge_id bytes
    let _ = edges;
    state.client.retract(&edge_id.0, "deleted via links API").await?;

    Ok(axum::http::StatusCode::NO_CONTENT)
}

//! Cross-type link endpoints — create, list, and remove edges between any node types.

use std::sync::Arc;

use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use memvault_api::rest::{
    CreateLinkRequest, EdgeCreated, LimitParams, NodeBucket, NodeWire, ReasonParams, ScopeParams,
};
use memvault_api::wire::{EntityWire, LinkWire};
use memvault_core::{EdgeId, NodeRef};
use memvault_doc::Edge;
use serde::Deserialize;

use crate::AppState;
use crate::api::auth::{RequireAuth, RequireWrite};
use crate::error::ApiError;

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
) -> Result<(StatusCode, Json<EdgeCreated>), ApiError> {
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
    crate::api::auth::enforce_node_action(&auth.claims, &req.source, memvault_auth::Action::Write)?;
    crate::api::auth::enforce_node_action(&auth.claims, &req.target, memvault_auth::Action::Read)?;

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
    Ok((StatusCode::CREATED, Json(EdgeCreated { edge_id })))
}

/// GET /api/v1/links?node=entity:<hex> — list all edges touching a node.
pub async fn list_links(
    auth: RequireAuth,
    State(state): State<Arc<AppState>>,
    Query(params): Query<LinksQuery>,
) -> Result<Json<Vec<LinkWire>>, ApiError> {
    let node = NodeRef::from_tag_label(&params.node).ok_or_else(|| {
        ApiError::bad_request(
            "Invalid node: expected 'entity:<hex>', 'doc:<hex>', or 'attachment:<hex>'",
        )
    })?;
    crate::api::auth::enforce_node_action(&auth.claims, &params.node, memvault_auth::Action::Read)?;

    let edges = state.client.edges_of(&node).await?;

    // Only edges whose other end the caller may read: an incoming edge from
    // another agent's node named that node.
    let mut readable = crate::api::auth::Readable::new(&auth.claims)?;
    let results: Vec<LinkWire> = edges
        .iter()
        .filter(|(source, edge)| {
            readable.node(&source.tag_label()) && readable.node(&edge.target.tag_label())
        })
        .map(|(source, edge)| LinkWire::new(source, edge))
        .collect();

    Ok(Json(results))
}

/// GET /api/v1/nodes/:node_id — get any node by type:hex ID, tagged by
/// `node_type` ([`NodeWire`]).
pub async fn get_node(
    auth: RequireAuth,
    State(state): State<Arc<AppState>>,
    Path(node_id): Path<String>,
) -> Result<Json<NodeWire>, ApiError> {
    tracing::debug!(node_id = %node_id, "API: get node");
    let node_ref = NodeRef::from_tag_label(&node_id).ok_or_else(|| {
        ApiError::bad_request(
            "Invalid node ID — expected 'entity:<hex>', 'doc:<hex>', or 'attachment:<hex>'",
        )
    })?;
    crate::api::auth::enforce_node_action(&auth.claims, &node_id, memvault_auth::Action::Read)?;
    let scope = memvault_core::QueryScope::all().with_retraction(crate::api::auth::retraction_for(
        &state,
        &auth.claims,
        None,
    ));
    let tags = state.client.get_tags(&node_id).await?;

    match node_ref {
        NodeRef::Entity(eid) => {
            let entity = state
                .client
                .get_entity_scoped(&eid, &scope)
                .await?
                .ok_or_else(|| ApiError::not_found("Entity not found"))?;
            Ok(Json(NodeWire::Entity {
                entity: EntityWire::with_edges(&entity),
                tags,
            }))
        }
        NodeRef::Doc(did) => {
            let doc = state
                .client
                .get_doc_scoped(&did, &scope)
                .await?
                .ok_or_else(|| ApiError::not_found("Document not found"))?;
            Ok(Json(NodeWire::Doc(memvault_api::rest::DocWire {
                node_id,
                cid: None,
                body: doc.body,
                frontmatter: doc.frontmatter,
                tags,
            })))
        }
        NodeRef::Attachment(cid) => {
            // The manifest block is dag-cbor: decoded, not parsed as JSON.
            let manifest = state
                .client
                .get_file_manifest(&cid)
                .await?
                .and_then(|b| memvault_api::types::FileManifestInfo::from_block(&b));
            Ok(Json(NodeWire::File {
                node_id,
                manifest,
                tags,
            }))
        }
    }
}

/// GET /api/v1/nodes/:node_id/bucket — the bucket a node lives in.
pub async fn node_bucket(
    auth: RequireAuth,
    State(state): State<Arc<AppState>>,
    Path(node_id): Path<String>,
) -> Result<Json<NodeBucket>, ApiError> {
    let node = NodeRef::from_tag_label(&node_id)
        .ok_or_else(|| ApiError::bad_request("Invalid node ID — expected 'type:hex'"))?;
    crate::api::auth::enforce_node_action(&auth.claims, &node_id, memvault_auth::Action::Read)?;
    Ok(Json(NodeBucket {
        bucket_id: state.client.node_bucket(&node).await?,
    }))
}

/// GET /api/v1/nodes — the nodes in a scope ([`ScopeParams`]: bucket, view,
/// kind, …; the caller's agent bucket when none is named), as
/// `NodeSummary`s.
pub async fn list_nodes(
    auth: RequireAuth,
    State(state): State<Arc<AppState>>,
    Query(params): Query<ScopeParams>,
    Query(limit): Query<LimitParams>,
) -> Result<Json<Vec<memvault_api::NodeSummary>>, ApiError> {
    let limit = limit.limit.unwrap_or(100);
    // One bucket (standards/bucket-scoping.md): the named one, else the
    // caller's agent bucket; admins keep the cross-bucket listing, read-
    // filtered before the limit.
    let scope = crate::api::auth::scope_from_params(&state, &auth.claims, &params, true).await?;
    let mut readable = crate::api::auth::Readable::new(&auth.claims)?;
    let items = crate::api::auth::fetch_kept(
        limit,
        |n| {
            let (state, scope) = (&state, &scope);
            async move { Ok(state.client.list_scoped(scope, n).await?) }
        },
        |n: &memvault_api::NodeSummary| readable.node(&n.node_id),
    )
    .await?;
    Ok(Json(items))
}

/// GET /api/v1/nodes/count — active/retracted counts for a scope (the same
/// [`ScopeParams`] as `GET /nodes`).
pub async fn count_nodes(
    auth: RequireAuth,
    State(state): State<Arc<AppState>>,
    Query(params): Query<ScopeParams>,
) -> Result<Json<memvault_api::ScopeCount>, ApiError> {
    let scope = crate::api::auth::scope_from_params(&state, &auth.claims, &params, true).await?;
    Ok(Json(state.client.count_scoped(&scope).await?))
}

/// DELETE /api/v1/nodes/:node_id?reason= — retract (soft-delete) any node.
pub async fn retract_node(
    auth: RequireWrite,
    State(state): State<Arc<AppState>>,
    Path(node_id): Path<String>,
    Query(params): Query<ReasonParams>,
) -> Result<StatusCode, ApiError> {
    crate::api::auth::enforce_node_action(&auth.claims, &node_id, memvault_auth::Action::Write)?;
    let reason = params.reason.as_deref().unwrap_or("retracted via API");
    state.client.retract_node(&node_id, reason).await?;
    tracing::info!(node_id = %node_id, "API: node retracted");
    Ok(StatusCode::NO_CONTENT)
}

/// DELETE /api/v1/links/:edge_id?source=entity:<hex> — remove an edge by ID.
/// The source parameter is required because edges are indexed by source.
pub async fn delete_link(
    auth: RequireWrite,
    State(state): State<Arc<AppState>>,
    Path(edge_id_str): Path<String>,
    Query(params): Query<DeleteLinkQuery>,
) -> Result<StatusCode, ApiError> {
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
    crate::api::auth::enforce_node_action(
        &auth.claims,
        &params.source,
        memvault_auth::Action::Write,
    )?;

    state.client.remove_link_from(&source, &edge_id).await?;

    Ok(StatusCode::NO_CONTENT)
}

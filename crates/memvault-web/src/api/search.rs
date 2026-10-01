//! Search endpoint.

use std::sync::Arc;

use axum::Json;
use axum::extract::{Query, State};
use serde::{Deserialize, Serialize};

use crate::AppState;
use crate::api::auth::RequireAuth;
use crate::error::ApiError;

#[derive(Deserialize)]
pub struct SearchQuery {
    pub q: String,
    pub limit: Option<usize>,
    /// Bucket id (hex) to search; the caller's agent bucket when absent.
    pub bucket: Option<String>,
}

#[derive(Serialize)]
pub struct SearchHitResponse {
    pub doc_id: String,
    pub score: f32,
    pub snippet: String,
}

/// GET /api/v1/search
pub async fn search(
    auth: RequireAuth,
    State(state): State<Arc<AppState>>,
    Query(params): Query<SearchQuery>,
) -> Result<Json<Vec<SearchHitResponse>>, ApiError> {
    let limit = params.limit.unwrap_or(20);
    let include_retracted = crate::api::auth::caller_sees_retracted(&state, &auth.claims);
    // One bucket (standards/bucket-scoping.md): the named one, else the
    // caller's agent bucket; admins search every bucket. Documents only, in
    // the scope, so other kinds don't take the limit's places.
    let named = crate::api::auth::parse_bucket_param(params.bucket.as_deref())?;
    let bucket = crate::api::auth::read_bucket(&state, &auth.claims, named).await?;
    let scope = memvault_core::QueryScope::all()
        .with_bucket(bucket)
        .with_kind(Some(memvault_core::NodeKind::Document))
        .with_include_retracted(include_retracted);
    let mut readable = crate::api::auth::Readable::new(&auth.claims)?;
    let hits = crate::api::auth::fetch_kept(
        limit,
        |n| {
            let (state, scope, q) = (&state, &scope, &params.q);
            async move { Ok(state.client.search_scoped(scope, q, n).await?) }
        },
        |h: &memvault_query::UnifiedHit| h.node_type == "doc" && readable.node(&h.node_id),
    )
    .await?;

    let results: Vec<SearchHitResponse> = hits
        .into_iter()
        .map(|h| SearchHitResponse {
            doc_id: h
                .node_id
                .strip_prefix("doc:")
                .unwrap_or(&h.node_id)
                .to_string(),
            score: h.score,
            snippet: h.snippet,
        })
        .collect();

    Ok(Json(results))
}

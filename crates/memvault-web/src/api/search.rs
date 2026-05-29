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
    let hits = state.client.search(&params.q, limit).await?;

    let results: Vec<SearchHitResponse> = hits
        .into_iter()
        .map(|h| SearchHitResponse {
            doc_id: hex::encode(h.doc_id.0),
            score: h.score,
            snippet: h.snippet,
        })
        .collect();

    let filtered = crate::api::auth::filter_readable(&auth.claims, results, |r| {
        format!("doc:{}", r.doc_id)
    })?;

    Ok(Json(filtered))
}

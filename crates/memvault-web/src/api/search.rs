//! Search endpoint.

use std::sync::Arc;

use axum::Json;
use axum::extract::{Query, State};
use memvault_api::rest::{ScopeParams, SearchParams};
use memvault_query::UnifiedHit;

use crate::AppState;
use crate::api::auth::RequireAuth;
use crate::error::ApiError;

/// GET /api/v1/search?q=&limit= plus a scope ([`ScopeParams`]: bucket, view,
/// kind, …) — `UnifiedHit`s of every node kind the scope admits, in the
/// bucket(s) named, else the caller's agent bucket (admins: every bucket),
/// only what the caller may read.
pub async fn search(
    auth: RequireAuth,
    State(state): State<Arc<AppState>>,
    Query(params): Query<SearchParams>,
    Query(scope): Query<ScopeParams>,
) -> Result<Json<Vec<UnifiedHit>>, ApiError> {
    let limit = params.limit.unwrap_or(20);
    let scope = crate::api::auth::scope_from_params(&state, &auth.claims, &scope, true).await?;
    let mut readable = crate::api::auth::Readable::new(&auth.claims)?;
    let hits = crate::api::auth::fetch_kept(
        limit,
        |n| {
            let (state, scope, q) = (&state, &scope, &params.q);
            async move { Ok(state.client.search_scoped(scope, q, n).await?) }
        },
        |h: &UnifiedHit| {
            scope.kind.is_none_or(|k| k.matches(&h.node_type)) && readable.node(&h.node_id)
        },
    )
    .await?;
    Ok(Json(hits))
}

//! Operational endpoints: metrics and health checks.

use std::sync::Arc;

use axum::extract::State;
use axum::http::{HeaderMap, HeaderValue};
use axum::response::IntoResponse;

use crate::AppState;

/// GET /api/v1/metrics — Prometheus exposition format.
pub async fn metrics(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let body = state.metrics.render_prometheus();
    let mut headers = HeaderMap::new();
    headers.insert(
        "content-type",
        HeaderValue::from_static("text/plain; version=0.0.4; charset=utf-8"),
    );
    (headers, body)
}

/// GET /api/v1/health — Health check JSON.
pub async fn health() -> axum::Json<serde_json::Value> {
    // Lightweight health response (store-level checks require store access;
    // full check_health is available via memvault_api::health when a store is wired in).
    axum::Json(serde_json::json!({
        "status": "Healthy",
        "checks": []
    }))
}

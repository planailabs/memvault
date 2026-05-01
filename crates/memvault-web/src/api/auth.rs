//! Bearer token authentication middleware.

use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};

use std::sync::Arc;

use crate::AppState;

/// Extracted bearer token.
pub struct AuthToken(pub String);

/// Middleware extractor that validates the Authorization header against the configured token.
pub struct RequireAuth;

#[derive(Debug)]
pub struct AuthRejection;

impl IntoResponse for AuthRejection {
    fn into_response(self) -> Response {
        (
            StatusCode::UNAUTHORIZED,
            axum::Json(serde_json::json!({"error": "Unauthorized", "status": 401})),
        )
            .into_response()
    }
}

impl FromRequestParts<Arc<AppState>> for RequireAuth {
    type Rejection = AuthRejection;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &Arc<AppState>,
    ) -> Result<Self, Self::Rejection> {
        let header = parts
            .headers
            .get("authorization")
            .and_then(|v| v.to_str().ok());

        let token = match header {
            Some(v) if v.starts_with("Bearer ") => &v[7..],
            _ => return Err(AuthRejection),
        };

        if token == state.auth_token {
            Ok(RequireAuth)
        } else {
            Err(AuthRejection)
        }
    }
}

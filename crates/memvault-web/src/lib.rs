//! `memvault-web` — Axum-based REST API and web UI for the memvault daemon.
//!
//! Uses `plan-ai-design` for shared UI components and styling.

pub mod api;
pub mod components;
pub mod error;

#[cfg(feature = "webui")]
pub mod ui;

/// Re-export the shared design system for consumers.
pub use plan_ai_design as design;

use std::sync::Arc;

use axum::Router;
use memvault_api::{EventBus, MemvaultClient};

/// Application state shared across all handlers.
pub struct AppState {
    pub client: Arc<dyn MemvaultClient>,
    pub event_bus: Arc<EventBus>,
    /// Pre-shared bearer token for Phase 7 authentication.
    pub auth_token: String,
    /// Operational metrics.
    pub metrics: Arc<memvault_api::metrics::Metrics>,
}

/// Build the complete memvault web router.
pub fn build_router(state: Arc<AppState>) -> Router {
    Router::new().nest("/api/v1", api::routes(state))
}

#[cfg(test)]
mod tests;

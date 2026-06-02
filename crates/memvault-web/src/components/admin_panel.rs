//! Render admin state as JSON.

use serde::Serialize;

/// Combined admin panel view.
#[derive(Serialize)]
pub struct AdminPanelView {
    pub status: memvault_api::NodeStatus,
    pub tokens: Vec<memvault_api::TokenStatus>,
}

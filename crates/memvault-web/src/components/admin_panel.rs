//! Render admin state as JSON.

use serde::Serialize;

use crate::api::admin::TokenStatusResponse;

/// Combined admin panel view.
#[derive(Serialize)]
pub struct AdminPanelView {
    pub status: memvault_api::NodeStatus,
    pub tokens: Vec<TokenStatusResponse>,
}

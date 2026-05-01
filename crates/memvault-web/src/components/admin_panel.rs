//! Render admin state as JSON.

use serde::Serialize;

use crate::api::admin::{NodeStatusResponse, TokenStatusResponse};

/// Combined admin panel view.
#[derive(Serialize)]
pub struct AdminPanelView {
    pub status: NodeStatusResponse,
    pub tokens: Vec<TokenStatusResponse>,
}

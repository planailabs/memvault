//! Render memory/document list as JSON.

use serde::Serialize;

use crate::api::docs::DocSummaryResponse;

/// A paginated list of documents.
#[derive(Serialize)]
pub struct MemoryListView {
    pub items: Vec<DocSummaryResponse>,
    pub total: usize,
}

impl MemoryListView {
    pub fn new(items: Vec<DocSummaryResponse>) -> Self {
        let total = items.len();
        Self { items, total }
    }
}

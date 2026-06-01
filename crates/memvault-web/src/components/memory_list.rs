//! Render memory/document list as JSON.

use serde::Serialize;

use memvault_api::DocSummary;

/// A paginated list of documents.
#[derive(Serialize)]
pub struct MemoryListView {
    pub items: Vec<DocSummary>,
    pub total: usize,
}

impl MemoryListView {
    pub fn new(items: Vec<DocSummary>) -> Self {
        let total = items.len();
        Self { items, total }
    }
}

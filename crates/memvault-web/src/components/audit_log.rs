//! Render audit log as JSON.

use serde::Serialize;

use crate::api::audit::AuditRecordResponse;

/// A paginated audit log view.
#[derive(Serialize)]
pub struct AuditLogView {
    pub records: Vec<AuditRecordResponse>,
    pub total: usize,
}

impl AuditLogView {
    pub fn new(records: Vec<AuditRecordResponse>) -> Self {
        let total = records.len();
        Self { records, total }
    }
}

//! Render audit log as JSON.

use serde::Serialize;

use memvault_api::wire::AuditRecordWire;

/// A paginated audit log view.
#[derive(Serialize)]
pub struct AuditLogView {
    pub records: Vec<AuditRecordWire>,
    pub total: usize,
}

impl AuditLogView {
    pub fn new(records: Vec<AuditRecordWire>) -> Self {
        let total = records.len();
        Self { records, total }
    }
}

//! `memvault-query` — Query, history, audit, and retraction layer for memvault.

pub mod audit;
pub mod error;
pub mod history;
pub mod index;
pub mod quotas;

pub use error::QueryError;
pub use history::checkpoint::Checkpoint;
pub use history::diff::{diff_doc, DiffEntry};
pub use history::time_travel::doc_at_time;
pub use history::trace::{trace_provenance, ProvenanceEntry};

pub use audit::query::{parse_audit_record, query_audit, AuditQuery, AuditRecord, OpKind};
pub use audit::retraction::{is_retracted, retract};

pub use index::effective_tags::effective_tags;
pub use index::search::{SearchHit, SearchQuery, TextIndex, UnifiedHit, INDEX_FORMAT_VERSION};

pub use quotas::{AgentQuota, BucketQuota, BucketUsage, QuotaExceeded, QuotaManager};

#[cfg(test)]
mod tests;


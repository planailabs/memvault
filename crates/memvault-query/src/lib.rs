//! `memvault-query` — Query, history, audit, and retraction layer for memvault.

pub mod audit;
pub mod error;
pub mod history;
pub mod index;
pub mod quotas;

pub use error::QueryError;
pub use history::checkpoint::Checkpoint;
pub use history::diff::{DiffEntry, diff_doc};
pub use history::time_travel::doc_at_time;
pub use history::trace::{ProvenanceEntry, trace_provenance};

pub use audit::query::{AuditQuery, AuditRecord, OpKind, parse_audit_record, query_audit};
pub use audit::retraction::{is_retracted, retract};

pub use index::effective_tags::effective_tags;
pub use index::search::{INDEX_FORMAT_VERSION, SearchHit, SearchQuery, TextIndex, UnifiedHit};
pub use index::tantivy_search::{TantivyHit, TantivyIndex};

pub use quotas::{AgentQuota, BucketQuota, BucketUsage, QuotaExceeded, QuotaManager};

#[cfg(test)]
mod tests;

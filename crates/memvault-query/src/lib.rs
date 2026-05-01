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

pub use audit::query::{query_audit, AuditQuery, AuditRecord, OpKind};
pub use audit::retraction::{is_retracted, retract};

pub use index::effective_tags::effective_tags;
pub use index::search::{SearchHit, SearchQuery, TextIndex};

pub use quotas::{AgentQuota, QuotaExceeded, QuotaManager};

#[cfg(test)]
mod tests;


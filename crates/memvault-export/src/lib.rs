//! Memvault export — structured export of documents, files, and graph entities.
//!
//! This crate provides the core export logic used by both the CLI binary and MCP tools.

pub mod export;
pub mod node;
pub mod plan;
pub mod sink;
pub mod title;
pub mod vfs_tree;

pub use export::{run_export, export_single_doc, export_single_entity, export_single_file, ExportStats};
pub use node::{export_node, NodeExportResult};
pub use plan::ExportPlan;
pub use sink::{create_sink, DirSink, ExportSink, TarSink};

/// Options controlling what gets exported.
#[derive(Debug, Clone, Default)]
pub struct ExportOptions {
    /// Include historical versions of documents.
    pub history: bool,
    /// Include VFS symlink tree.
    pub include_vfs: bool,
    /// Filter by tag (scope, label).
    pub tag_filter: Option<(String, String)>,
    /// Filter by view name.
    pub view_filter: Option<String>,
}

//! Single-node export — parse a node_id and export to a directory.

use std::path::Path;

use anyhow::Result;
use memvault_api::MemvaultClient;
use memvault_core::{DocId, EntityId};
use serde::Serialize;

use crate::export;

/// Result of exporting a single node.
#[derive(Debug, Serialize)]
pub struct NodeExportResult {
    /// Primary output file path.
    pub path: String,
    /// Node type: "doc", "entity", or "file".
    #[serde(rename = "type")]
    pub node_type: &'static str,
    /// The node_id that was exported.
    pub node_id: String,
    /// File size in bytes (for files).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub size: Option<usize>,
    /// Number of history versions exported (for docs with history).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub history_count: Option<usize>,
    /// Directory containing history files.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub history_dir: Option<String>,
    /// Inline content (for entities/small text).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content: Option<String>,
}

/// Export a single node by its node_id string to the given output directory.
///
/// The `node_id` format is `doc:<hex>`, `entity:<hex>`, or `file:<hex>`.
/// Files are written under `out_dir/` preserving the export layout
/// (documents/, graph/, files/ subdirectories).
pub async fn export_node(
    client: &dyn MemvaultClient,
    node_id: &str,
    out_dir: &Path,
    history: bool,
) -> Result<NodeExportResult> {
    std::fs::create_dir_all(out_dir)?;

    if let Some(hex_str) = node_id.strip_prefix("doc:") {
        export_doc_node(client, hex_str, node_id, out_dir, history).await
    } else if let Some(hex_str) = node_id.strip_prefix("entity:") {
        export_entity_node(client, hex_str, node_id, out_dir).await
    } else if let Some(hex_str) = node_id.strip_prefix("file:") {
        export_file_node(client, hex_str, node_id, out_dir).await
    } else {
        anyhow::bail!("node_id must start with 'doc:', 'entity:', or 'file:'")
    }
}

async fn export_doc_node(
    client: &dyn MemvaultClient,
    hex_str: &str,
    node_id: &str,
    out_dir: &Path,
    history: bool,
) -> Result<NodeExportResult> {
    let bytes = hex::decode(hex_str)?;
    anyhow::ensure!(bytes.len() == 32, "doc ID must be 32 bytes (64 hex chars)");
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    let doc_id = DocId(arr);

    let entries = export::export_single_doc(client, &doc_id, history).await?;
    anyhow::ensure!(!entries.is_empty(), "document not found");

    let (rel_path, content) = &entries[0];
    let filename = Path::new(rel_path)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("doc.md");
    let out_path = out_dir.join(filename);
    std::fs::write(&out_path, content)?;

    let mut result = NodeExportResult {
        path: out_path.display().to_string(),
        node_type: "doc",
        node_id: node_id.to_string(),
        size: None,
        history_count: None,
        history_dir: None,
        content: None,
    };

    if entries.len() > 1 {
        let hist_dir = out_dir.join(hex_str);
        std::fs::create_dir_all(&hist_dir)?;
        for (rel, data) in &entries[1..] {
            let hist_name = Path::new(rel)
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("version.md");
            std::fs::write(hist_dir.join(hist_name), data)?;
        }
        result.history_count = Some(entries.len() - 1);
        result.history_dir = Some(hist_dir.display().to_string());
    }

    Ok(result)
}

async fn export_entity_node(
    client: &dyn MemvaultClient,
    hex_str: &str,
    node_id: &str,
    out_dir: &Path,
) -> Result<NodeExportResult> {
    let bytes = hex::decode(hex_str)?;
    anyhow::ensure!(bytes.len() == 32, "entity ID must be 32 bytes (64 hex chars)");
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    let entity_id = EntityId(arr);

    let (_rel_path, content) = export::export_single_entity(client, &entity_id).await?;

    let graph_dir = out_dir.join("graph");
    std::fs::create_dir_all(&graph_dir)?;
    let out_path = graph_dir.join(format!("{hex_str}.json"));
    std::fs::write(&out_path, &content)?;

    Ok(NodeExportResult {
        path: out_path.display().to_string(),
        node_type: "entity",
        node_id: node_id.to_string(),
        size: None,
        history_count: None,
        history_dir: None,
        content: Some(String::from_utf8_lossy(&content).into_owned()),
    })
}

async fn export_file_node(
    client: &dyn MemvaultClient,
    hex_str: &str,
    node_id: &str,
    out_dir: &Path,
) -> Result<NodeExportResult> {
    let cid_bytes = hex::decode(hex_str)?;

    let (rel_path, data) = export::export_single_file(client, &cid_bytes).await?;

    let files_dir = out_dir.join("files");
    std::fs::create_dir_all(&files_dir)?;
    let filename = Path::new(&rel_path)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("file.bin");
    let out_path = files_dir.join(filename);
    std::fs::write(&out_path, &data)?;

    Ok(NodeExportResult {
        path: out_path.display().to_string(),
        node_type: "file",
        node_id: node_id.to_string(),
        size: Some(data.len()),
        history_count: None,
        history_dir: None,
        content: None,
    })
}

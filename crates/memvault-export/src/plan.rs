//! Export plan — enumerate what to export from the vault.

use memvault_api::MemvaultClient;
use memvault_core::{DocId, EntityId, NodeRef};

use anyhow::Result;

use crate::ExportOptions;

/// A document to be exported.
pub struct DocExportEntry {
    pub doc_id: DocId,
    pub title: Option<String>,
}

/// A file attachment to be exported.
pub struct FileExportEntry {
    pub manifest_cid: Vec<u8>,
    pub filename: Option<String>,
    pub mime_type: String,
}

/// A graph entity to be exported.
pub struct EntityExportEntry {
    pub entity_id: EntityId,
    pub kind: String,
}

/// Describes everything that should be exported.
pub struct ExportPlan {
    pub documents: Vec<DocExportEntry>,
    pub files: Vec<FileExportEntry>,
    pub entities: Vec<EntityExportEntry>,
}

/// Build an export plan by enumerating vault contents.
pub async fn build_plan(client: &dyn MemvaultClient, opts: &ExportOptions) -> Result<ExportPlan> {
    let mut documents = Vec::new();
    let mut files = Vec::new();
    let mut entities = Vec::new();

    // Use list_all for a unified listing, filtered by view if specified.
    // Vault export is cross-bucket by design → no bucket scope.
    let all_nodes = client
        .list_all(opts.view_filter.as_deref(), 10_000, None)
        .await?;

    for (node_id, node_type, label, tags) in &all_nodes {
        // Apply tag filter if specified
        if let Some((scope, tag_label)) = &opts.tag_filter {
            if !tags.iter().any(|(s, l)| s == scope && l == tag_label) {
                continue;
            }
        }

        match node_type.as_str() {
            "doc" => {
                if let Some(doc_id) = parse_doc_node_id(node_id) {
                    documents.push(DocExportEntry {
                        doc_id,
                        title: if label.is_empty() {
                            None
                        } else {
                            Some(label.clone())
                        },
                    });
                }
            }
            "entity" => {
                if let Some(entity_id) = parse_entity_node_id(node_id) {
                    // Skip VFS directory entities — they're structural, not content
                    if label.starts_with("vfs:") {
                        continue;
                    }
                    entities.push(EntityExportEntry {
                        entity_id,
                        kind: label.clone(),
                    });
                }
            }
            "file" => {
                if let Some(cid) = parse_file_node_id(node_id) {
                    files.push(FileExportEntry {
                        manifest_cid: cid,
                        filename: if label.is_empty() {
                            None
                        } else {
                            Some(label.clone())
                        },
                        mime_type: String::new(), // resolved during export
                    });
                }
            }
            _ => {}
        }
    }

    Ok(ExportPlan {
        documents,
        files,
        entities,
    })
}

fn parse_doc_node_id(node_id: &str) -> Option<DocId> {
    let hex_str = node_id.strip_prefix("doc:")?;
    let bytes = hex::decode(hex_str).ok()?;
    if bytes.len() != 32 {
        return None;
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Some(DocId(arr))
}

fn parse_entity_node_id(node_id: &str) -> Option<EntityId> {
    let hex_str = node_id.strip_prefix("entity:")?;
    let bytes = hex::decode(hex_str).ok()?;
    if bytes.len() != 32 {
        return None;
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Some(EntityId(arr))
}

fn parse_file_node_id(node_id: &str) -> Option<Vec<u8>> {
    let hex_str = node_id.strip_prefix("file:")?;
    hex::decode(hex_str).ok()
}

/// Resolve a NodeRef to its node_id string representation.
pub fn node_ref_to_id(node: &NodeRef) -> String {
    match node {
        NodeRef::Entity(id) => format!("entity:{}", hex::encode(id.0)),
        NodeRef::Doc(id) => format!("doc:{}", hex::encode(id.0)),
        NodeRef::Attachment(cid) => format!("file:{}", hex::encode(cid)),
    }
}

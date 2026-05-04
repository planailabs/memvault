//! Document helpers — shared logic for creating and managing documents.
//!
//! Used by: HTTP API, web UI server functions, MCP tools, CLI.

use std::collections::BTreeMap;

use memvault_core::{DocId, Visibility};
use memvault_doc::Document;

use crate::error::Result;
use crate::MemvaultClient;

/// Create a document, optionally linking it into the VFS.
/// Returns (cid_bytes, node_id).
///
/// Audit logging is automatic via `MemvaultClient::put_doc`.
pub async fn create_doc(
    client: &dyn MemvaultClient,
    body: &str,
    title: Option<&str>,
    tags: Vec<(String, String)>,
    vis: Visibility,
    vfs_path: Option<&str>,
) -> Result<(Vec<u8>, String)> {
    let doc_id = DocId::random();
    let mut frontmatter = BTreeMap::new();
    if let Some(t) = title {
        frontmatter.insert("title".to_string(), serde_json::Value::String(t.to_string()));
    }
    let doc = Document::new(doc_id.clone(), body.to_string(), frontmatter);
    let cid = client.put_doc(doc, tags, vis).await?;
    let node_id = format!("doc:{}", hex::encode(doc_id.0));

    if let Some(path) = vfs_path {
        if let Err(e) = crate::vfs::link_node_at_path(client, path, &node_id).await {
            tracing::warn!(path, error = %e, "VFS link failed after doc creation");
        }
    }

    Ok((cid, node_id))
}

/// Parse tags from "scope:label" strings.
pub fn parse_tags(tags: &[String]) -> Vec<(String, String)> {
    tags.iter()
        .filter_map(|t| {
            let (s, l) = t.split_once(':')?;
            Some((s.trim().to_string(), l.trim().to_string()))
        })
        .collect()
}

/// Parse a visibility string.
pub fn parse_visibility(s: Option<&str>) -> Visibility {
    match s {
        Some("public") => Visibility::Public,
        Some("federated") => Visibility::Federated,
        _ => Visibility::Internal,
    }
}

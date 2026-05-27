//! Document helpers — shared logic for creating and managing documents.
//!
//! Used by: HTTP API, web UI server functions, MCP tools, CLI.

use std::collections::BTreeMap;

use memvault_core::{BucketId, DocId, Visibility};
use memvault_doc::Document;

use crate::MemvaultClient;
use crate::error::Result;

/// Result of creating a document.
pub struct CreateDocResult {
    /// Raw CID bytes of the stored envelope.
    pub cid: Vec<u8>,
    /// Node ID in "doc:<hex>" format.
    pub node_id: String,
    /// The DocId that was generated.
    pub doc_id: DocId,
    /// The frontmatter that was stored (including title if provided).
    pub frontmatter: BTreeMap<String, serde_json::Value>,
}

/// Create a document, optionally linking it into the VFS.
///
/// If `title` is provided AND `frontmatter` doesn't already contain a "title"
/// key, the title is inserted into frontmatter automatically.
///
/// Audit logging is automatic via `MemvaultClient::put_doc`.
pub async fn create_doc<C: MemvaultClient + ?Sized>(
    client: &C,
    body: &str,
    title: Option<&str>,
    frontmatter: Option<BTreeMap<String, serde_json::Value>>,
    tags: Vec<(String, String)>,
    vis: Visibility,
    vfs_path: Option<&str>,
    bucket: Option<&BucketId>,
) -> Result<CreateDocResult> {
    let doc_id = DocId::random();
    let mut fm = frontmatter.unwrap_or_default();
    if let Some(t) = title {
        fm.entry("title".to_string())
            .or_insert_with(|| serde_json::Value::String(t.to_string()));
    }
    let doc = Document::new(doc_id.clone(), body.to_string(), fm.clone());
    let cid = client.put_doc(doc, tags, vis, bucket).await?;
    let node_id = format!("doc:{}", hex::encode(doc_id.0));

    if let Some(path) = vfs_path {
        let bucket_id = match bucket {
            Some(b) => b.clone(),
            None => client
                .default_bucket_id()
                .await
                .unwrap_or(BucketId([0u8; 32])),
        };
        if let Err(e) = crate::vfs::link_node_at_path(client, &bucket_id, path, &node_id).await {
            tracing::warn!(path, error = %e, "VFS link failed after doc creation");
        }
    }

    Ok(CreateDocResult {
        cid,
        node_id,
        doc_id,
        frontmatter: fm,
    })
}

/// Parse a single `"scope:label"` filter string into a `(scope, label)` tuple.
/// Returns `None` if the string lacks a colon.
pub fn parse_tag_filter(s: &str) -> Option<(String, String)> {
    let (scope, label) = s.split_once(':')?;
    Some((scope.trim().to_string(), label.trim().to_string()))
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

/// Parse a comma-separated list of `"scope:label"` tags.
/// Entries without a colon are skipped.
pub fn parse_tags_csv(s: &str) -> Vec<(String, String)> {
    s.split(',')
        .filter_map(parse_tag_filter)
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

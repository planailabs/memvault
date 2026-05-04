//! Document helpers — shared logic for creating and managing documents.

use std::collections::BTreeMap;

use memvault_core::{DocId, Visibility};
use memvault_doc::Document;

use crate::error::Result;
use crate::MemvaultClient;

/// Create a document and return (cid_bytes, node_id).
pub async fn create_doc(
    client: &dyn MemvaultClient,
    body: &str,
    title: Option<&str>,
    tags: Vec<(String, String)>,
    vis: Visibility,
) -> Result<(Vec<u8>, String)> {
    let doc_id = DocId::random();
    let mut frontmatter = BTreeMap::new();
    if let Some(t) = title {
        frontmatter.insert("title".to_string(), serde_json::Value::String(t.to_string()));
    }
    let doc = Document::new(doc_id.clone(), body.to_string(), frontmatter);
    let cid = client.put_doc(doc, tags, vis).await?;
    let node_id = format!("doc:{}", hex::encode(doc_id.0));
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

//! File upload helpers — shared logic for uploading files to memvault.
//!
//! Used by: HTTP API, web UI server functions, MCP tools, CLI.

use memvault_core::BucketId;

use crate::MemvaultClient;
use crate::error::Result;

/// Upload file data, optionally linking it into the VFS.
/// Returns (manifest_cid_bytes, node_id).
///
/// Audit logging is automatic via `MemvaultClient::upload_file`.
pub async fn upload_file(
    client: &dyn MemvaultClient,
    data: &[u8],
    filename: Option<&str>,
    mime_type: &str,
    tags: Vec<(String, String)>,
    visibility: &str,
    vfs_path: Option<&str>,
    bucket: Option<&BucketId>,
) -> Result<(Vec<u8>, String)> {
    let cid = client
        .upload_file(data, filename, mime_type, tags, visibility, bucket)
        .await?;
    let node_id = format!("file:{}", hex::encode(&cid));

    if let Some(path) = vfs_path {
        let bucket_id = match bucket {
            Some(b) => b.clone(),
            None => client
                .default_bucket_id()
                .await
                .unwrap_or(BucketId([0u8; 32])),
        };
        if let Err(e) = crate::vfs::link_node_at_path(client, &bucket_id, path, &node_id).await {
            tracing::warn!(path, error = %e, "VFS link failed after file upload");
        }
    }

    Ok((cid, node_id))
}

/// Detect MIME type from a file path, falling back to application/octet-stream.
pub fn detect_mime(path: &std::path::Path) -> &'static str {
    mime_guess::from_path(path)
        .first_raw()
        .unwrap_or("application/octet-stream")
}

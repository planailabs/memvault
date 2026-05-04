//! File upload helpers — shared logic for uploading files to memvault.

use crate::error::Result;
use crate::MemvaultClient;

/// Upload file data and return (manifest_cid_bytes, node_id).
pub async fn upload_file(
    client: &dyn MemvaultClient,
    data: &[u8],
    filename: Option<&str>,
    mime_type: &str,
    tags: Vec<(String, String)>,
    visibility: &str,
) -> Result<(Vec<u8>, String)> {
    let cid = client.upload_file(data, filename, mime_type, tags, visibility).await?;
    let node_id = format!("file:{}", hex::encode(&cid));
    Ok((cid, node_id))
}

/// Detect MIME type from a file path, falling back to application/octet-stream.
pub fn detect_mime(path: &std::path::Path) -> &'static str {
    mime_guess::from_path(path).first_raw().unwrap_or("application/octet-stream")
}

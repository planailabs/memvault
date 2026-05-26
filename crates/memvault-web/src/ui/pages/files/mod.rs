pub mod detail;
pub mod explorer;

/// Shared file metadata resolution: tries the manifest block first,
/// then falls back to finding the attachment envelope via the audit log.
#[cfg(feature = "server")]
pub(crate) struct FileMeta {
    pub filename: String,
    pub mime_type: String,
    pub size: u64,
}

#[cfg(feature = "server")]
pub(crate) async fn resolve_file_meta(
    client: &dyn memvault_api::MemvaultClient,
    manifest_cid: &[u8],
) -> FileMeta {
    let mut filename = None;
    let mut mime_type = None;
    let mut size = 0u64;

    // 1. Try the manifest block itself (new-style files).
    if let Ok(Some(manifest_bytes)) = client.get_file_manifest(manifest_cid).await {
        if let Ok(m) = serde_json::from_slice::<serde_json::Value>(&manifest_bytes) {
            filename = m.get("filename").and_then(|v| v.as_str()).map(|s| s.to_string());
            mime_type = m.get("mime_type").and_then(|v| v.as_str()).map(|s| s.to_string());
            size = m.get("content_size").and_then(|v| v.as_u64()).unwrap_or(0);
        }
    }

    // 2. Fallback: search the audit log for the attachment envelope that
    //    references this manifest CID — it has filename/mime_type/size.
    if filename.is_none() {
        let query = memvault_query::AuditQuery {
            op_kind: Some(memvault_query::OpKind::AttachFile),
            limit: Some(200),
            ..Default::default()
        };
        if let Ok(records) = client.audit(query).await {
            for record in &records {
                if record.attachment_cid.as_deref() == Some(manifest_cid) {
                    // Found the envelope — read the block for metadata.
                    if let Ok(Some(env_data)) = client.get_file_manifest(&record.cid).await {
                        if let Ok(env) = serde_json::from_slice::<serde_json::Value>(&env_data) {
                            filename = env.get("filename").and_then(|v| v.as_str()).map(|s| s.to_string());
                            mime_type = mime_type.or_else(|| env.get("mime_type").and_then(|v| v.as_str()).map(|s| s.to_string()));
                            if size == 0 { size = env.get("size").and_then(|v| v.as_u64()).unwrap_or(0); }
                        }
                    }
                    break;
                }
            }
        }
    }

    FileMeta {
        filename: filename.unwrap_or_else(|| "unnamed".to_string()),
        mime_type: mime_type.unwrap_or_else(|| "application/octet-stream".to_string()),
        size,
    }
}

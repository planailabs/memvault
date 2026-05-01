//! AttachmentManifest, ManifestUpdate, and AttachmentHeadRef types.

use serde::{Deserialize, Serialize};

use crate::chunk::ChunkLayout;
use crate::replication::ReplicationHint;

/// Attachment manifest — metadata for a stored file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttachmentManifest {
    /// CID of root block (inline or UnixFS DAG root).
    pub content_root: Vec<u8>,
    /// Total content size in bytes.
    pub content_size: u64,
    /// How the file is chunked.
    pub chunk_layout: ChunkLayout,
    /// Original filename, if known.
    pub filename: Option<String>,
    /// MIME type.
    pub mime_type: String,
    /// SHA-256 of the entire file content.
    pub sha256: Option<[u8; 32]>,
    /// Width x Height for images/video.
    pub width_height: Option<(u32, u32)>,
    /// Duration in milliseconds for audio/video.
    pub duration_ms: Option<u64>,
    /// CID of ExtractedText envelope.
    pub extracted_text: Option<Vec<u8>>,
    /// CID of source (for redacted derivatives).
    pub derived_from: Option<Vec<u8>>,
    /// CID of PiiFindingsBlock.
    pub pii_findings: Option<Vec<u8>>,
    /// Replication strategy.
    pub replication: ReplicationHint,
}

/// Update to an existing manifest (e.g., extraction completed).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManifestUpdate {
    /// CID of original manifest.
    pub target_manifest: Vec<u8>,
    /// CID of extracted text, if newly available.
    pub extracted_text: Option<Vec<u8>>,
    /// CID of PII findings, if newly available.
    pub pii_findings: Option<Vec<u8>>,
    /// CID of source derivation.
    pub derived_from: Option<Vec<u8>>,
    /// Timestamp of this update.
    pub updated_at_ns: u64,
}

/// Head announcement for attachments on gossipsub.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttachmentHeadRef {
    /// CID of the manifest.
    pub manifest_cid: Vec<u8>,
    /// Classification label (e.g. "image", "document").
    pub classification: String,
    /// Visibility label (e.g. "public", "private").
    pub visibility: String,
    /// Replication hint.
    pub replication: ReplicationHint,
    /// Total file size.
    pub size: u64,
}

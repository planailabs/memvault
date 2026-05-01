use memvault_policy::PiiFinding;
use serde::{Deserialize, Serialize};

/// Extracted text result from a file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtractedText {
    /// CID of attachment manifest
    pub source: Vec<u8>,
    /// e.g. "pdf-extract@0.7"
    pub extractor: String,
    pub extractor_version: String,
    pub extracted_at_ns: u64,
    /// Full extracted plain text
    pub text: String,
    /// Byte offsets of page/section breaks
    pub page_breaks: Vec<u32>,
    /// Extraction warnings
    pub warnings: Vec<String>,
}

/// PII findings for an attachment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PiiFindingsBlock {
    /// Attachment manifest CID
    pub target: Vec<u8>,
    /// ExtractedText CID
    pub scanned_text: Vec<u8>,
    pub findings: Vec<PiiFinding>,
    pub detector: String,
    pub scanned_at_ns: u64,
}

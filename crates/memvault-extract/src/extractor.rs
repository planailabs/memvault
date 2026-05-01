use crate::error::ExtractError;
use crate::extracted::ExtractedText;

/// Hints for extraction (passed by caller).
#[derive(Debug, Clone, Default)]
pub struct ExtractionHints {
    /// Truncate extracted text if larger than this
    pub max_text_bytes: Option<usize>,
    /// Timeout in milliseconds
    pub timeout_ms: Option<u64>,
}

/// Extractor trait.
pub trait Extractor: Send + Sync {
    /// Which MIME types this extractor handles.
    fn supports(&self, mime: &str) -> bool;

    /// Extract text from file content.
    fn extract(
        &self,
        content: &[u8],
        hints: &ExtractionHints,
    ) -> Result<ExtractedText, ExtractError>;

    /// Extractor identifier (e.g., "plain-text@1.0").
    fn id(&self) -> &str;
}

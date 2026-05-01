use crate::error::ExtractError;
use crate::extracted::ExtractedText;
use crate::extractor::{ExtractionHints, Extractor};
use crate::extractors;

/// Registry that dispatches extraction by MIME type.
pub struct ExtractionRegistry {
    extractors: Vec<Box<dyn Extractor>>,
}

impl ExtractionRegistry {
    pub fn new() -> Self {
        Self {
            extractors: Vec::new(),
        }
    }

    /// Create with all default extractors registered.
    pub fn with_defaults() -> Self {
        let mut reg = Self::new();
        reg.register(Box::new(extractors::plain_text::PlainTextExtractor));
        reg.register(Box::new(extractors::markdown::MarkdownExtractor));
        reg.register(Box::new(extractors::html::HtmlExtractor));
        reg.register(Box::new(extractors::pdf::PdfExtractor));
        reg.register(Box::new(extractors::docx::DocxExtractor));
        reg
    }

    /// Register a custom extractor.
    pub fn register(&mut self, extractor: Box<dyn Extractor>) {
        self.extractors.push(extractor);
    }

    /// Extract text from content with given MIME type.
    pub fn extract(
        &self,
        content: &[u8],
        mime: &str,
        hints: &ExtractionHints,
    ) -> Result<ExtractedText, ExtractError> {
        for extractor in &self.extractors {
            if extractor.supports(mime) {
                return extractor.extract(content, hints);
            }
        }
        Err(ExtractError::UnsupportedMime(mime.to_string()))
    }

    /// Check if any extractor supports this MIME type.
    pub fn can_extract(&self, mime: &str) -> bool {
        self.extractors.iter().any(|e| e.supports(mime))
    }
}

impl Default for ExtractionRegistry {
    fn default() -> Self {
        Self::new()
    }
}

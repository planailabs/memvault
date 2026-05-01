use crate::error::ExtractError;
use crate::extracted::ExtractedText;
use crate::extractor::{ExtractionHints, Extractor};

pub struct PlainTextExtractor;

impl Extractor for PlainTextExtractor {
    fn supports(&self, mime: &str) -> bool {
        matches!(
            mime,
            "text/plain" | "text/csv" | "application/json"
        ) || mime.starts_with("text/x-")
    }

    fn extract(
        &self,
        content: &[u8],
        hints: &ExtractionHints,
    ) -> Result<ExtractedText, ExtractError> {
        let mut text = String::from_utf8_lossy(content).into_owned();

        if let Some(max) = hints.max_text_bytes {
            if text.len() > max {
                // Truncate at a char boundary
                let mut end = max;
                while end > 0 && !text.is_char_boundary(end) {
                    end -= 1;
                }
                text.truncate(end);
            }
        }

        Ok(ExtractedText {
            source: Vec::new(),
            extractor: self.id().to_string(),
            extractor_version: "1.0".to_string(),
            extracted_at_ns: 0,
            text,
            page_breaks: Vec::new(),
            warnings: Vec::new(),
        })
    }

    fn id(&self) -> &str {
        "plain-text@1.0"
    }
}

use crate::error::ExtractError;
use crate::extracted::ExtractedText;
use crate::extractor::{ExtractionHints, Extractor};

pub struct PdfExtractor;

impl Extractor for PdfExtractor {
    fn supports(&self, mime: &str) -> bool {
        mime == "application/pdf"
    }

    fn extract(
        &self,
        content: &[u8],
        hints: &ExtractionHints,
    ) -> Result<ExtractedText, ExtractError> {
        let mut warnings = Vec::new();

        let text = match pdf_extract::extract_text_from_mem(content) {
            Ok(t) => t,
            Err(e) => {
                return Err(ExtractError::ExtractionFailed(format!(
                    "pdf-extract failed: {e}"
                )));
            }
        };

        if text.trim().is_empty() {
            warnings.push("possible scanned PDF — no text extracted".to_string());
        }

        // pdf-extract doesn't expose per-page boundaries easily,
        // so we use form-feed characters as page separators if present
        let mut page_breaks: Vec<u32> = Vec::new();
        for (i, c) in text.char_indices() {
            if c == '\x0C' {
                page_breaks.push(i as u32);
            }
        }

        let mut text = text;
        if let Some(max) = hints.max_text_bytes {
            if text.len() > max {
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
            extractor_version: "0.7".to_string(),
            extracted_at_ns: 0,
            text,
            page_breaks,
            warnings,
        })
    }

    fn id(&self) -> &str {
        "pdf-extract@0.7"
    }
}

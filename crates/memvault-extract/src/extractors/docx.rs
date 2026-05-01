use crate::error::ExtractError;
use crate::extracted::ExtractedText;
use crate::extractor::{ExtractionHints, Extractor};

pub struct DocxExtractor;

impl Extractor for DocxExtractor {
    fn supports(&self, mime: &str) -> bool {
        mime == "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
    }

    fn extract(
        &self,
        content: &[u8],
        hints: &ExtractionHints,
    ) -> Result<ExtractedText, ExtractError> {
        let doc = docx_rs::read_docx(content)
            .map_err(|e| ExtractError::ExtractionFailed(format!("docx-rs failed: {e}")))?;

        let mut text = String::new();
        let mut page_breaks: Vec<u32> = Vec::new();
        let mut paragraph_count = 0u32;

        for child in doc.document.children {
            if let docx_rs::DocumentChild::Paragraph(para) = child {
                paragraph_count += 1;

                // Insert page break every 50 paragraphs as a section heuristic
                if paragraph_count > 1 && paragraph_count % 50 == 1 {
                    page_breaks.push(text.len() as u32);
                }

                for run_child in &para.children {
                    if let docx_rs::ParagraphChild::Run(run) = run_child {
                        for run_child in &run.children {
                            if let docx_rs::RunChild::Text(t) = run_child {
                                text.push_str(&t.text);
                            }
                        }
                    }
                }
                text.push('\n');
            }
        }

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
            extractor_version: "0.4".to_string(),
            extracted_at_ns: 0,
            text,
            page_breaks,
            warnings: Vec::new(),
        })
    }

    fn id(&self) -> &str {
        "docx-rs@0.4"
    }
}

use memvault_extract_abi::{ExtractionHints, ExtractedText};

pub fn extract(content: &[u8], hints: &ExtractionHints) -> Result<ExtractedText, String> {
    let mut text = String::from_utf8_lossy(content).into_owned();

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
        extractor: "plain-text@1.0".to_string(),
        extractor_version: "1.0".to_string(),
        text,
        page_breaks: Vec::new(),
        warnings: Vec::new(),
    })
}

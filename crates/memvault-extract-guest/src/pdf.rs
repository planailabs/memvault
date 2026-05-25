use memvault_extract_abi::{ExtractionHints, ExtractedText};

pub fn extract(content: &[u8], hints: &ExtractionHints) -> Result<ExtractedText, String> {
    let doc = lopdf::Document::load_mem(content).map_err(|e| format!("PDF parse failed: {e}"))?;

    let mut text = String::new();
    let mut page_breaks: Vec<u32> = Vec::new();
    let mut warnings = Vec::new();

    let pages = doc.get_pages();
    let mut page_numbers: Vec<u32> = pages.keys().copied().collect();
    page_numbers.sort();

    for page_num in page_numbers {
        if !text.is_empty() {
            page_breaks.push(text.len() as u32);
        }

        match doc.extract_text(&[page_num]) {
            Ok(page_text) => {
                text.push_str(&page_text);
            }
            Err(_) => {
                // Some pages may not have extractable text (images, etc.)
            }
        }
    }

    if text.trim().is_empty() {
        warnings.push("possible scanned PDF — no text extracted".to_string());
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
        extractor: "lopdf@0.34".to_string(),
        extractor_version: "0.34".to_string(),
        text,
        page_breaks,
        warnings,
    })
}

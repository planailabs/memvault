use memvault_extract_abi::{ExtractionHints, ExtractedText};
use scraper::{Html, Selector};

pub fn extract(content: &[u8], hints: &ExtractionHints) -> Result<ExtractedText, String> {
    let source = String::from_utf8_lossy(content);
    let document = Html::parse_document(&source);

    let mut text = String::new();
    let mut page_breaks: Vec<u32> = Vec::new();

    let break_selector =
        Selector::parse("h1, h2, hr, section").unwrap_or_else(|_| Selector::parse("*").unwrap());

    let body_selector =
        Selector::parse("body").unwrap_or_else(|_| Selector::parse("*").unwrap());

    if let Some(body) = document.select(&body_selector).next() {
        extract_text_recursive(&body, &mut text, &mut page_breaks, &break_selector);
    } else {
        extract_text_recursive(
            &document.root_element(),
            &mut text,
            &mut page_breaks,
            &break_selector,
        );
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
        extractor: "html@1.0".to_string(),
        extractor_version: "1.0".to_string(),
        text,
        page_breaks,
        warnings: Vec::new(),
        links: Vec::new(),
    })
}

fn extract_text_recursive(
    element: &scraper::ElementRef,
    text: &mut String,
    page_breaks: &mut Vec<u32>,
    _break_selector: &Selector,
) {
    for child in element.children() {
        if let Some(text_node) = child.value().as_text() {
            let t = text_node.trim();
            if !t.is_empty() {
                if !text.is_empty() && !text.ends_with(' ') && !text.ends_with('\n') {
                    text.push(' ');
                }
                text.push_str(t);
            }
        } else if let Some(el) = scraper::ElementRef::wrap(child) {
            let tag_name = el.value().name();
            let is_break = matches!(tag_name, "h1" | "h2" | "hr" | "section");

            if is_break && !text.is_empty() {
                page_breaks.push(text.len() as u32);
                if !text.ends_with('\n') {
                    text.push('\n');
                }
            }

            let is_block = matches!(
                tag_name,
                "p" | "div" | "h1" | "h2" | "h3" | "h4" | "h5" | "h6" | "li" | "br" | "tr"
                    | "section" | "article" | "header" | "footer"
            );

            extract_text_recursive(&el, text, page_breaks, _break_selector);

            if is_block && !text.is_empty() && !text.ends_with('\n') {
                text.push('\n');
            }
        }
    }
}

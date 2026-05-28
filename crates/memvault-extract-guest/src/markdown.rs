use memvault_extract_abi::{ExtractionHints, ExtractedText};
use pulldown_cmark::{Event, Parser, Tag, TagEnd};

pub fn extract(content: &[u8], hints: &ExtractionHints) -> Result<ExtractedText, String> {
    let source = String::from_utf8_lossy(content);
    let parser = Parser::new(&source);

    let mut text = String::new();
    let mut page_breaks: Vec<u32> = Vec::new();

    for event in parser {
        match event {
            Event::Text(t) => text.push_str(&t),
            Event::SoftBreak | Event::HardBreak => text.push('\n'),
            Event::Start(Tag::Heading { .. }) => {
                if !text.is_empty() {
                    page_breaks.push(text.len() as u32);
                    if !text.ends_with('\n') {
                        text.push('\n');
                    }
                }
            }
            Event::End(TagEnd::Heading(_)) => {
                text.push('\n');
            }
            Event::End(TagEnd::Paragraph) => {
                text.push('\n');
            }
            Event::Rule => {
                page_breaks.push(text.len() as u32);
                text.push('\n');
            }
            _ => {}
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
        extractor: "markdown@1.0".to_string(),
        extractor_version: "1.0".to_string(),
        text,
        page_breaks,
        warnings: Vec::new(),
        links: Vec::new(),
    })
}

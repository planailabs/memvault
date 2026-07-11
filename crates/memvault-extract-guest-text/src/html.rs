use memvault_extract_abi::{
    ExtractedLink, ExtractedText, ExtractionHints, LinkSyntax, parse_uri, render_uri,
};
use scraper::{Html, Selector};

pub fn extract(content: &[u8], hints: &ExtractionHints) -> Result<ExtractedText, String> {
    let source = String::from_utf8_lossy(content);
    let document = Html::parse_document(&source);

    let mut text = String::new();
    let mut page_breaks: Vec<u32> = Vec::new();

    let break_selector =
        Selector::parse("h1, h2, hr, section").unwrap_or_else(|_| Selector::parse("*").unwrap());

    let body_selector = Selector::parse("body").unwrap_or_else(|_| Selector::parse("*").unwrap());

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

    let links = scan_anchors(&source);

    Ok(ExtractedText {
        extractor: "html@1.0".to_string(),
        extractor_version: "1.0".to_string(),
        text,
        page_breaks,
        warnings: Vec::new(),
        links,
        segments: Vec::new(),
    })
}

/// Scan for `<a … href="memvault://…">…</a>` anchors. We keep the parsing
/// simple — scraper doesn't give source byte ranges, so we do a byte walk
/// for accurate spans and to avoid the overhead of a full parse for this
/// pass.
fn scan_anchors(source: &str) -> Vec<ExtractedLink> {
    let bytes = source.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i + 1 < bytes.len() {
        if bytes[i] == b'<' && match_ci(bytes, i + 1, b"a") {
            // Only accept '<a' followed by whitespace or '>'.
            let after = i + 2;
            if after >= bytes.len() {
                break;
            }
            if !bytes[after].is_ascii_whitespace() && bytes[after] != b'>' {
                i += 1;
                continue;
            }
            // Find tag end '>'.
            let tag_end = match find_byte(bytes, i, b'>') {
                Some(e) => e,
                None => break,
            };
            let attrs = &source[i + 2..tag_end];
            if let Some(href) = extract_attr(attrs, "href") {
                if let Ok(parsed) = parse_uri(&href) {
                    // Find matching </a>.
                    let body_start = tag_end + 1;
                    let close = find_close_a(bytes, body_start);
                    let (display_end, span_end) = match close {
                        Some((open_close, after_close)) => (open_close, after_close),
                        None => (bytes.len(), bytes.len()),
                    };
                    let inner = strip_tags(&source[body_start..display_end]);
                    let display_text = if inner.trim().is_empty() {
                        None
                    } else {
                        Some(inner.trim().to_string())
                    };
                    out.push(ExtractedLink {
                        uri: render_uri(&parsed),
                        display_text,
                        byte_span: (i as u32, span_end as u32),
                        syntax: LinkSyntax::HtmlAnchor,
                    });
                    i = span_end;
                    continue;
                }
            }
            i = tag_end + 1;
            continue;
        }
        i += 1;
    }
    out
}

fn match_ci(bytes: &[u8], pos: usize, needle: &[u8]) -> bool {
    if pos + needle.len() > bytes.len() {
        return false;
    }
    for (k, n) in needle.iter().enumerate() {
        if bytes[pos + k].to_ascii_lowercase() != *n {
            return false;
        }
    }
    true
}

fn find_byte(bytes: &[u8], start: usize, b: u8) -> Option<usize> {
    let mut i = start;
    while i < bytes.len() {
        if bytes[i] == b {
            return Some(i);
        }
        i += 1;
    }
    None
}

/// Find the matching `</a>` from `pos`. Returns `(start_of_lt_slash, after_gt)`.
fn find_close_a(bytes: &[u8], pos: usize) -> Option<(usize, usize)> {
    let mut i = pos;
    while i + 3 < bytes.len() {
        if bytes[i] == b'<' && bytes[i + 1] == b'/' && match_ci(bytes, i + 2, b"a") {
            let after_name = i + 3;
            if after_name < bytes.len()
                && (bytes[after_name].is_ascii_whitespace() || bytes[after_name] == b'>')
            {
                let end = find_byte(bytes, after_name, b'>')?;
                return Some((i, end + 1));
            }
        }
        i += 1;
    }
    None
}

/// Pull `name="value"` or `name='value'` out of an attributes string. Very
/// permissive; not a full HTML attribute parser but sufficient for `href`.
fn extract_attr(attrs: &str, name: &str) -> Option<String> {
    let lower = attrs.to_ascii_lowercase();
    let needle = format!("{name}=");
    let mut from = 0;
    while let Some(pos) = lower[from..].find(&needle) {
        let at = from + pos;
        // Ensure preceding char is whitespace or start of attrs.
        if at > 0 {
            let prev = attrs.as_bytes()[at - 1];
            if !prev.is_ascii_whitespace() {
                from = at + needle.len();
                continue;
            }
        }
        let value_start = at + needle.len();
        let bytes = attrs.as_bytes();
        if value_start >= bytes.len() {
            return None;
        }
        let quote = bytes[value_start];
        if quote == b'"' || quote == b'\'' {
            let end_q = value_start + 1 + attrs[value_start + 1..].find(quote as char)?;
            return Some(attrs[value_start + 1..end_q].to_string());
        }
        // Unquoted: read until whitespace or '/'.
        let mut e = value_start;
        while e < bytes.len() && !bytes[e].is_ascii_whitespace() && bytes[e] != b'/' {
            e += 1;
        }
        return Some(attrs[value_start..e].to_string());
    }
    None
}

/// Strip HTML tags from a fragment, leaving only text. Naive — drops
/// everything between `<` and `>`.
fn strip_tags(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut in_tag = false;
    for c in s.chars() {
        if in_tag {
            if c == '>' {
                in_tag = false;
            }
        } else if c == '<' {
            in_tag = true;
        } else {
            out.push(c);
        }
    }
    out
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
                "p" | "div"
                    | "h1"
                    | "h2"
                    | "h3"
                    | "h4"
                    | "h5"
                    | "h6"
                    | "li"
                    | "br"
                    | "tr"
                    | "section"
                    | "article"
                    | "header"
                    | "footer"
            );

            extract_text_recursive(&el, text, page_breaks, _break_selector);

            if is_block && !text.is_empty() && !text.ends_with('\n') {
                text.push('\n');
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn links_of(src: &str) -> Vec<ExtractedLink> {
        let hints = ExtractionHints::default();
        let out = extract(src.as_bytes(), &hints).unwrap();
        out.links
    }

    #[test]
    fn extracts_anchor_to_doc() {
        let links = links_of(
            r#"<html><body><p>See <a href="memvault://doc/abcd">Alice</a> now.</p></body></html>"#,
        );
        assert_eq!(links.len(), 1);
        assert_eq!(links[0].uri, "memvault://doc/abcd");
        assert_eq!(links[0].syntax, LinkSyntax::HtmlAnchor);
        assert_eq!(links[0].display_text.as_deref(), Some("Alice"));
    }

    #[test]
    fn extracts_anchor_with_attributes() {
        let links = links_of(
            r#"<a class="ref" id="x" href="memvault://entity/1b2c?alias=Bob" data-x="1">Bob</a>"#,
        );
        assert_eq!(links.len(), 1);
        assert_eq!(links[0].uri, "memvault://entity/1b2c?alias=Bob");
    }

    #[test]
    fn drops_non_memvault_anchors() {
        let links = links_of(r#"<a href="https://google.com">G</a>"#);
        assert!(links.is_empty());
    }

    #[test]
    fn extracts_multiple_anchors() {
        let links = links_of(
            r#"<a href="memvault://doc/abcd">A</a> and <a href="memvault://doc/1234">B</a>"#,
        );
        assert_eq!(links.len(), 2);
    }

    #[test]
    fn anchor_with_nested_markup() {
        let links =
            links_of(r#"<a href="memvault://doc/abcd"><span>Hello</span> <b>World</b></a>"#);
        assert_eq!(links.len(), 1);
        assert_eq!(links[0].display_text.as_deref(), Some("Hello World"));
    }

    #[test]
    fn empty_anchor_has_no_display() {
        let links = links_of(r#"<a href="memvault://doc/abcd"></a>"#);
        assert_eq!(links.len(), 1);
        assert_eq!(links[0].display_text, None);
    }

    #[test]
    fn span_covers_full_anchor() {
        let src = r#"<p><a href="memvault://doc/abcd">x</a></p>"#;
        let links = links_of(src);
        assert_eq!(links.len(), 1);
        let (start, end) = links[0].byte_span;
        assert_eq!(
            &src[start as usize..end as usize],
            r#"<a href="memvault://doc/abcd">x</a>"#
        );
    }

    #[test]
    fn case_insensitive_tag() {
        let links = links_of(r#"<A HREF="memvault://doc/abcd">X</A>"#);
        assert_eq!(links.len(), 1);
        assert_eq!(links[0].uri, "memvault://doc/abcd");
    }

    #[test]
    fn invalid_memvault_uri_dropped() {
        // Missing ident.
        let links = links_of(r#"<a href="memvault://doc/">X</a>"#);
        assert!(links.is_empty());
    }
}

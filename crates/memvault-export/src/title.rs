//! Title extraction from documents.

use memvault_doc::Document;
use regex::Regex;
use std::sync::LazyLock;

static HEADING_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?m)^#\s+(.+)$").unwrap());

/// Extract a human-friendly title from a document.
/// Priority: frontmatter["title"] > first `# Heading` line > None.
pub fn extract_title(doc: &Document) -> Option<String> {
    if let Some(title) = doc.frontmatter.get("title").and_then(|v| v.as_str()) {
        let t = title.trim();
        if !t.is_empty() {
            return Some(t.to_string());
        }
    }
    if let Some(caps) = HEADING_RE.captures(&doc.body) {
        let heading = caps[1].trim();
        if !heading.is_empty() {
            return Some(heading.to_string());
        }
    }
    None
}

/// Sanitize a title for use as a filename component.
/// Replaces path separators, control chars, and trims whitespace.
pub fn title_to_filename(title: &str) -> String {
    let sanitized: String = title
        .chars()
        .map(|c| match c {
            '/' | '\\' | ':' | '*' | '?' | '"' | '<' | '>' | '|' | '\0' => '_',
            c if c.is_control() => '_',
            c => c,
        })
        .collect();
    let trimmed = sanitized.trim().trim_matches('.');
    if trimmed.is_empty() {
        "untitled".to_string()
    } else {
        trimmed.to_string()
    }
}

/// Build a document filename: `<Title> - <cid_hex>.md` or `<cid_hex>.md` if no title.
pub fn doc_filename(doc: &Document) -> String {
    let cid_hex = hex::encode(doc.id.0);
    match extract_title(doc) {
        Some(title) => {
            let safe = title_to_filename(&title);
            // Truncate long titles to avoid filesystem limits
            let safe = if safe.len() > 200 { &safe[..200] } else { &safe };
            format!("{safe} - {cid_hex}.md")
        }
        None => format!("{cid_hex}.md"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use memvault_core::DocId;
    use std::collections::BTreeMap;

    fn make_doc(body: &str, title: Option<&str>) -> Document {
        let mut frontmatter = BTreeMap::new();
        if let Some(t) = title {
            frontmatter.insert("title".to_string(), serde_json::json!(t));
        }
        Document {
            id: DocId([0u8; 32]),
            body: body.to_string(),
            frontmatter,
        }
    }

    #[test]
    fn title_from_frontmatter() {
        let doc = make_doc("some body", Some("My Title"));
        assert_eq!(extract_title(&doc), Some("My Title".to_string()));
    }

    #[test]
    fn title_from_heading() {
        let doc = make_doc("# Hello World\n\nBody text", None);
        assert_eq!(extract_title(&doc), Some("Hello World".to_string()));
    }

    #[test]
    fn no_title() {
        let doc = make_doc("just plain text", None);
        assert_eq!(extract_title(&doc), None);
    }

    #[test]
    fn filename_sanitization() {
        assert_eq!(title_to_filename("foo/bar:baz"), "foo_bar_baz");
        assert_eq!(title_to_filename("..."), "untitled");
        assert_eq!(title_to_filename("  normal  "), "normal");
    }

    #[test]
    fn doc_filename_with_title() {
        let doc = make_doc("# My Note\nbody", None);
        let name = doc_filename(&doc);
        let cid_hex = hex::encode([0u8; 32]);
        assert_eq!(name, format!("My Note - {cid_hex}.md"));
    }

    #[test]
    fn doc_filename_without_title() {
        let doc = make_doc("no heading", None);
        let name = doc_filename(&doc);
        let cid_hex = hex::encode([0u8; 32]);
        assert_eq!(name, format!("{cid_hex}.md"));
    }
}

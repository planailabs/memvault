use memvault_extract_abi::{
    ExtractedLink, ExtractedText, ExtractionHints, LinkSyntax, LinkTargetKind, ParsedUri,
    parse_uri, render_uri,
};
use pulldown_cmark::{Event, Parser, Tag, TagEnd};

pub fn extract(content: &[u8], hints: &ExtractionHints) -> Result<ExtractedText, String> {
    let source = String::from_utf8_lossy(content);
    let mut links: Vec<ExtractedLink> = Vec::new();

    // Strip and parse frontmatter; collect frontmatter-link entries.
    let (body_offset, body) = strip_frontmatter(&source, &mut links);

    let mut text = String::new();
    let mut page_breaks: Vec<u32> = Vec::new();

    let parser = Parser::new(body).into_offset_iter();
    let mut link_stack: Vec<(String, std::ops::Range<usize>, String)> = Vec::new();

    for (event, range) in parser {
        match event {
            Event::Text(t) => {
                if let Some((_, _, label)) = link_stack.last_mut() {
                    label.push_str(&t);
                }
                text.push_str(&t);
            }
            Event::Code(t) => {
                if let Some((_, _, label)) = link_stack.last_mut() {
                    label.push_str(&t);
                }
                text.push_str(&t);
            }
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
            Event::Start(Tag::Link { dest_url, .. }) => {
                link_stack.push((dest_url.to_string(), range, String::new()));
            }
            Event::End(TagEnd::Link) => {
                if let Some((dest, span, label)) = link_stack.pop() {
                    if let Some(uri) = normalize_markdown_link_dest(&dest, &label) {
                        let abs_start = (body_offset + span.start) as u32;
                        let abs_end = (body_offset + span.end) as u32;
                        let display = if label.is_empty() { None } else { Some(label) };
                        links.push(ExtractedLink {
                            uri,
                            display_text: display,
                            byte_span: (abs_start, abs_end),
                            syntax: LinkSyntax::MarkdownLink,
                        });
                    }
                }
            }
            _ => {}
        }
    }

    // Find wikilinks via byte scan over the body. pulldown-cmark renders
    // unrecognized `[[…]]` as literal text, so we scan once over the source.
    for wl in scan_wikilinks(body, body_offset) {
        links.push(wl);
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
        links,
        segments: Vec::new(),
    })
}

/// If the source begins with a YAML-style frontmatter block (`---\n…\n---\n`),
/// pull `links: [...]` entries out as `FrontmatterRef` links and return the
/// remaining body slice along with its byte offset into the original source.
fn strip_frontmatter<'a>(source: &'a str, out: &mut Vec<ExtractedLink>) -> (usize, &'a str) {
    if !source.starts_with("---\n") && !source.starts_with("---\r\n") {
        return (0, source);
    }
    let after_open = source.find('\n').map(|i| i + 1).unwrap_or(source.len());
    // Find the closing `\n---\n` from after_open.
    let rest = &source[after_open..];
    let close = rest.find("\n---").and_then(|i| {
        // Accept `\n---\n`, `\n---\r\n`, or `\n---` at EOF.
        let after = i + 4;
        let tail = rest.get(after..)?;
        if tail.starts_with('\n') || tail.starts_with("\r\n") || tail.is_empty() {
            Some((i, after))
        } else {
            None
        }
    });
    let Some((rel_close, after_close)) = close else {
        return (0, source);
    };
    let fm_text = &rest[..rel_close];
    let fm_start = after_open;

    parse_frontmatter_links(fm_text, fm_start, out);

    let body_offset = after_open + after_close;
    // Skip the trailing newline after `---` if present.
    let body_offset = if source[body_offset..].starts_with('\n') {
        body_offset + 1
    } else if source[body_offset..].starts_with("\r\n") {
        body_offset + 2
    } else {
        body_offset
    };
    (body_offset, &source[body_offset..])
}

/// Minimal YAML scanner for `links:` arrays. Supports two shapes:
///
/// ```yaml
/// links: [memvault://doc/abcd, memvault://entity/1234]
/// links:
///   - memvault://doc/abcd
///   - memvault://entity/1234
/// ```
fn parse_frontmatter_links(fm: &str, fm_offset: usize, out: &mut Vec<ExtractedLink>) {
    let mut in_links_block = false;
    let mut block_indent: Option<usize> = None;

    for line_match in line_iter(fm) {
        let (line, line_start) = line_match;
        let trimmed = line.trim_end();
        let leading_ws = line.len() - line.trim_start().len();

        // Detect a top-level `links:` key.
        if leading_ws == 0 && trimmed.starts_with("links:") {
            let after = trimmed["links:".len()..].trim_start();
            if let Some(rest) = after.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
                for raw in rest.split(',') {
                    let v = raw.trim().trim_matches(|c| c == '\'' || c == '"');
                    push_frontmatter_uri(v, fm_offset + line_start, line.len(), out);
                }
                in_links_block = false;
            } else if after.is_empty() {
                in_links_block = true;
                block_indent = None;
            } else {
                in_links_block = false;
            }
            continue;
        }

        if in_links_block {
            if trimmed.is_empty() {
                continue;
            }
            // Block ends when we see a non-indented or differently-keyed line.
            if leading_ws == 0 {
                in_links_block = false;
                continue;
            }
            let bullet = trimmed.trim_start().strip_prefix('-');
            let Some(after_dash) = bullet else {
                in_links_block = false;
                continue;
            };
            let indent_here = leading_ws;
            match block_indent {
                None => block_indent = Some(indent_here),
                Some(want) if want == indent_here => {}
                _ => {
                    in_links_block = false;
                    continue;
                }
            }
            let v = after_dash.trim().trim_matches(|c| c == '\'' || c == '"');
            push_frontmatter_uri(v, fm_offset + line_start, line.len(), out);
        }
    }
}

fn line_iter(s: &str) -> impl Iterator<Item = (&str, usize)> {
    let mut offset = 0usize;
    std::iter::from_fn(move || {
        if offset >= s.len() {
            return None;
        }
        let rest = &s[offset..];
        let end = rest.find('\n').map(|i| i + 1).unwrap_or(rest.len());
        let line = &rest[..end];
        let start = offset;
        offset += end;
        Some((line, start))
    })
}

fn push_frontmatter_uri(
    uri: &str,
    line_start: usize,
    line_len: usize,
    out: &mut Vec<ExtractedLink>,
) {
    if uri.is_empty() {
        return;
    }
    if parse_uri(uri).is_err() {
        return;
    }
    out.push(ExtractedLink {
        uri: uri.to_string(),
        display_text: None,
        byte_span: (line_start as u32, (line_start + line_len) as u32),
        syntax: LinkSyntax::FrontmatterRef,
    });
}

/// Normalize a markdown-link destination. Accepts existing memvault:// URIs
/// (validated and passed through) and the wikilink-style shorthand
/// `doc:hex`, `entity:hex`, `file:hex`. Anything else is dropped.
fn normalize_markdown_link_dest(dest: &str, label: &str) -> Option<String> {
    if dest.starts_with("memvault:") {
        return parse_uri(dest).ok().map(|p| render_uri(&p));
    }
    let parsed = parse_shorthand(dest, label)?;
    Some(render_uri(&parsed))
}

/// Parse a wikilink/shorthand body, e.g. `doc:hex`, `entity:hex|Alice`,
/// `file:abcd`, or plain `Alice` (alias kind).
fn parse_shorthand(body: &str, label: &str) -> Option<ParsedUri> {
    let (kind_part, alias) = match body.split_once('|') {
        Some((k, a)) => (k.trim(), Some(a.trim().to_string())),
        None => (body.trim(), None),
    };
    let display_alias = alias.clone().filter(|a| !a.is_empty());
    if let Some((kind, ident)) = kind_part.split_once(':') {
        let target_kind = match kind {
            "doc" => LinkTargetKind::Doc,
            "entity" => LinkTargetKind::Entity,
            "file" | "attachment" => LinkTargetKind::File,
            _ => return None,
        };
        let ident = ident.trim();
        if !ident.chars().all(|c| c.is_ascii_hexdigit()) || ident.is_empty() {
            return None;
        }
        Some(ParsedUri {
            kind: target_kind,
            ident: ident.to_string(),
            alias: display_alias.or_else(|| {
                let label = label.trim();
                if label.is_empty() {
                    None
                } else {
                    Some(label.to_string())
                }
            }),
            relation: None,
            pinned_at: None,
            weight: None,
            bucket: None,
            fragment: None,
        })
    } else {
        // No `kind:` prefix — treat as alias.
        let alias_ident = kind_part;
        if alias_ident.is_empty() {
            return None;
        }
        Some(ParsedUri {
            kind: LinkTargetKind::Alias,
            ident: alias_ident.to_string(),
            alias: display_alias,
            relation: None,
            pinned_at: None,
            weight: None,
            bucket: None,
            fragment: None,
        })
    }
}

/// Scan a markdown body for `[[…]]` wikilinks. Skips matches inside fenced
/// code blocks and inline code spans.
fn scan_wikilinks(body: &str, body_offset: usize) -> Vec<ExtractedLink> {
    let bytes = body.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    let mut in_fence = false;
    let mut at_line_start = true;

    while i < bytes.len() {
        if at_line_start && bytes[i] == b'`' {
            if let Some(fence_end) = is_code_fence(bytes, i) {
                in_fence = !in_fence;
                i = fence_end;
                at_line_start = false;
                continue;
            }
        }
        if !in_fence && bytes[i] == b'`' {
            // Inline code span: skip to closing backtick.
            i += 1;
            while i < bytes.len() && bytes[i] != b'`' {
                i += 1;
            }
            if i < bytes.len() {
                i += 1;
            }
            at_line_start = false;
            continue;
        }
        if !in_fence && i + 1 < bytes.len() && bytes[i] == b'[' && bytes[i + 1] == b'[' {
            let start = i;
            if let Some(end) = find_close(bytes, i + 2) {
                let inner = &body[i + 2..end];
                if let Some(parsed) = parse_shorthand(inner, "") {
                    let display = parsed.alias.clone();
                    out.push(ExtractedLink {
                        uri: render_uri(&parsed),
                        display_text: display,
                        byte_span: ((body_offset + start) as u32, (body_offset + end + 2) as u32),
                        syntax: LinkSyntax::Wikilink,
                    });
                }
                i = end + 2;
                at_line_start = false;
                continue;
            }
        }
        if bytes[i] == b'\n' {
            at_line_start = true;
        } else if bytes[i] != b' ' && bytes[i] != b'\t' {
            at_line_start = false;
        }
        i += 1;
    }
    out
}

/// If `pos` points at a fenced-code marker (three or more backticks at line
/// start), return the byte index just after the marker (incl. info string).
fn is_code_fence(bytes: &[u8], pos: usize) -> Option<usize> {
    let mut count = 0;
    let mut j = pos;
    while j < bytes.len() && bytes[j] == b'`' {
        count += 1;
        j += 1;
    }
    if count < 3 {
        return None;
    }
    while j < bytes.len() && bytes[j] != b'\n' {
        j += 1;
    }
    Some(j)
}

/// Find the index of the first `]]` at or after `pos` on the same line.
fn find_close(bytes: &[u8], pos: usize) -> Option<usize> {
    let mut i = pos;
    while i + 1 < bytes.len() {
        if bytes[i] == b'\n' {
            return None;
        }
        if bytes[i] == b']' && bytes[i + 1] == b']' {
            return Some(i);
        }
        i += 1;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn extract_links(src: &str) -> Vec<ExtractedLink> {
        let hints = ExtractionHints::default();
        let out = extract(src.as_bytes(), &hints).unwrap();
        out.links
    }

    #[test]
    fn extracts_markdown_link_to_doc() {
        let links = extract_links("See [Alice](memvault://doc/abcd) for details.");
        assert_eq!(links.len(), 1);
        assert_eq!(links[0].uri, "memvault://doc/abcd");
        assert_eq!(links[0].syntax, LinkSyntax::MarkdownLink);
        assert_eq!(links[0].display_text.as_deref(), Some("Alice"));
    }

    #[test]
    fn drops_non_memvault_markdown_links() {
        let links = extract_links("See [Google](https://google.com).");
        assert!(links.is_empty());
    }

    #[test]
    fn markdown_shorthand_dest() {
        let links = extract_links("Refers to [thing](doc:abcd).");
        assert_eq!(links.len(), 1);
        assert_eq!(links[0].uri, "memvault://doc/abcd?alias=thing");
    }

    #[test]
    fn extracts_wikilink_doc() {
        let links = extract_links("Hello [[doc:9f3a]] world.");
        assert_eq!(links.len(), 1);
        assert_eq!(links[0].uri, "memvault://doc/9f3a");
        assert_eq!(links[0].syntax, LinkSyntax::Wikilink);
    }

    #[test]
    fn extracts_wikilink_with_alias() {
        let links = extract_links("Refer to [[entity:1b2c|Alice Doe]] now.");
        assert_eq!(links.len(), 1);
        // Alias is percent-encoded; space → %20.
        assert_eq!(links[0].uri, "memvault://entity/1b2c?alias=Alice%20Doe");
        assert_eq!(links[0].display_text.as_deref(), Some("Alice Doe"));
    }

    #[test]
    fn extracts_wikilink_alias_only() {
        let links = extract_links("Plain ref [[Alice]] here.");
        assert_eq!(links.len(), 1);
        assert_eq!(links[0].uri, "memvault://alias/Alice");
    }

    #[test]
    fn ignores_wikilinks_in_fence() {
        let links = extract_links("Before\n```\n[[doc:abcd]]\n```\nAfter [[doc:1234]]");
        assert_eq!(links.len(), 1);
        assert_eq!(links[0].uri, "memvault://doc/1234");
    }

    #[test]
    fn ignores_wikilinks_in_inline_code() {
        let links = extract_links("Use `[[doc:abcd]]` syntax, like [[doc:1234]].");
        assert_eq!(links.len(), 1);
        assert_eq!(links[0].uri, "memvault://doc/1234");
    }

    #[test]
    fn frontmatter_inline_links_list() {
        let src = "---\nlinks: [memvault://doc/abcd, memvault://entity/1234]\n---\nBody text.";
        let links = extract_links(src);
        assert_eq!(links.len(), 2);
        assert!(links.iter().any(|l| l.uri == "memvault://doc/abcd"));
        assert!(links.iter().any(|l| l.uri == "memvault://entity/1234"));
        assert!(links.iter().all(|l| l.syntax == LinkSyntax::FrontmatterRef));
    }

    #[test]
    fn frontmatter_block_links_list() {
        let src = "---\ntitle: My Note\nlinks:\n  - memvault://doc/abcd\n  - memvault://entity/1234\n---\nBody.";
        let links = extract_links(src);
        assert_eq!(links.len(), 2);
        assert!(links.iter().any(|l| l.uri == "memvault://doc/abcd"));
    }

    #[test]
    fn rejects_invalid_frontmatter_uris() {
        let src = "---\nlinks:\n  - not-a-uri\n  - memvault://doc/abcd\n---\n";
        let links = extract_links(src);
        assert_eq!(links.len(), 1);
        assert_eq!(links[0].uri, "memvault://doc/abcd");
    }

    #[test]
    fn body_span_skips_past_frontmatter() {
        let src = "---\ntitle: x\n---\n[[doc:abcd]]";
        let links = extract_links(src);
        assert_eq!(links.len(), 1);
        let (start, end) = links[0].byte_span;
        assert_eq!(&src[start as usize..end as usize], "[[doc:abcd]]");
    }

    #[test]
    fn unclosed_wikilink_ignored() {
        let links = extract_links("Broken [[doc:abcd more text without close");
        assert!(links.is_empty());
    }

    #[test]
    fn invalid_kind_in_wikilink_dropped() {
        let links = extract_links("[[chunk:abcd]] is not a thing.");
        assert!(links.is_empty());
    }

    #[test]
    fn invalid_hex_in_wikilink_dropped() {
        let links = extract_links("[[doc:not-hex]]");
        assert!(links.is_empty());
    }
}

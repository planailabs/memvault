//! Markdown → HTML renderer that resolves `memvault://` URIs and
//! `[[wikilink]]` shorthand to in-app routes.
//!
//! Two passes:
//!   1. **Pre-process body bytes**: rewrite `[[doc:hex|alias]]`,
//!      `[[entity:hex]]`, `[[file:cid]]`, `[[Alice]]` into proper
//!      markdown links (`[label](memvault://…)`), so pulldown-cmark
//!      sees them as anchors rather than literal text.
//!   2. **Walk pulldown-cmark events**: every `Tag::Link` whose
//!      destination is `memvault://…` is rewritten to the matching app
//!      route (`/notes/<hex>`, `/graph/<hex>`, `/files/<hex>`, or
//!      `?q=<alias>` for unresolved alias kinds). Link text is kept
//!      from the source; empty text falls back to a friendly label
//!      derived from the URI.
//!
//! Code spans and fenced code blocks are left alone — wikilinks inside
//! code render literally, matching the parser pass in the extractor
//! plugin.

use std::borrow::Cow;

use memvault_extract_abi::{LinkTargetKind, ParsedUri, parse_uri, render_uri};
use pulldown_cmark::{CowStr, Event, Options, Parser, Tag, TagEnd};

/// Render a markdown body to HTML with memvault:// URIs and `[[…]]`
/// shorthand resolved to in-app links.
pub fn render_doc_body(body: &str) -> String {
    let pre = preprocess_wikilinks(body);
    let parser = Parser::new_ext(&pre, Options::all());
    let rewritten = rewrite_link_events(parser);
    let mut html = String::new();
    pulldown_cmark::html::push_html(&mut html, rewritten.into_iter());
    html
}

/// Scan the source for `[[…]]` wikilinks and rewrite them inline to
/// markdown link syntax. Code fences and inline code spans are skipped
/// so wikilinks inside code render literally.
fn preprocess_wikilinks(source: &str) -> String {
    let bytes = source.as_bytes();
    let mut out = String::with_capacity(source.len());
    let mut i = 0;
    let mut in_fence = false;
    let mut at_line_start = true;

    while i < bytes.len() {
        if at_line_start && bytes[i] == b'`' {
            if let Some(fence_end) = is_code_fence(bytes, i) {
                in_fence = !in_fence;
                out.push_str(&source[i..fence_end]);
                i = fence_end;
                at_line_start = false;
                continue;
            }
        }
        if !in_fence && bytes[i] == b'`' {
            out.push('`');
            i += 1;
            while i < bytes.len() && bytes[i] != b'`' {
                let c = source[i..].chars().next().unwrap();
                out.push(c);
                i += c.len_utf8();
            }
            if i < bytes.len() {
                out.push('`');
                i += 1;
            }
            at_line_start = false;
            continue;
        }
        if !in_fence && i + 1 < bytes.len() && bytes[i] == b'[' && bytes[i + 1] == b'[' {
            if let Some(end) = find_close(bytes, i + 2) {
                let inner = &source[i + 2..end];
                if let Some(parsed) = parse_shorthand(inner) {
                    let label = parsed
                        .alias
                        .clone()
                        .unwrap_or_else(|| default_label(&parsed));
                    let uri = render_uri(&parsed);
                    out.push_str(&format!("[{}]({})", escape_link_text(&label), uri));
                    i = end + 2;
                    at_line_start = false;
                    continue;
                }
            }
        }
        let c = source[i..].chars().next().unwrap();
        if c == '\n' {
            at_line_start = true;
        } else if c != ' ' && c != '\t' {
            at_line_start = false;
        }
        out.push(c);
        i += c.len_utf8();
    }
    out
}

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

/// Parse a wikilink body (without the surrounding `[[]]`).
fn parse_shorthand(body: &str) -> Option<ParsedUri> {
    let (kind_part, alias) = match body.split_once('|') {
        Some((k, a)) => (k.trim(), Some(a.trim().to_string())),
        None => (body.trim(), None),
    };
    if let Some((kind, ident)) = kind_part.split_once(':') {
        let target_kind = match kind {
            "doc" => LinkTargetKind::Doc,
            "entity" => LinkTargetKind::Entity,
            "file" | "attachment" => LinkTargetKind::File,
            _ => return None,
        };
        let ident = ident.trim();
        if ident.is_empty() || !ident.chars().all(|c| c.is_ascii_hexdigit()) {
            return None;
        }
        Some(ParsedUri {
            kind: target_kind,
            ident: ident.to_string(),
            alias,
            relation: None,
            pinned_at: None,
            weight: None,
            bucket: None,
            fragment: None,
        })
    } else {
        if kind_part.is_empty() {
            return None;
        }
        Some(ParsedUri {
            kind: LinkTargetKind::Alias,
            ident: kind_part.to_string(),
            alias,
            relation: None,
            pinned_at: None,
            weight: None,
            bucket: None,
            fragment: None,
        })
    }
}

fn default_label(parsed: &ParsedUri) -> String {
    match parsed.kind {
        LinkTargetKind::Doc => {
            let short = short_hex(&parsed.ident);
            format!("doc {short}")
        }
        LinkTargetKind::Entity => {
            let short = short_hex(&parsed.ident);
            format!("entity {short}")
        }
        LinkTargetKind::File => {
            let short = short_hex(&parsed.ident);
            format!("file {short}")
        }
        LinkTargetKind::Alias => parsed.ident.clone(),
    }
}

fn short_hex(s: &str) -> String {
    if s.len() <= 10 {
        s.to_string()
    } else {
        format!("{}…", &s[..8])
    }
}

fn escape_link_text(text: &str) -> String {
    text.replace('\\', "\\\\")
        .replace('[', "\\[")
        .replace(']', "\\]")
}

/// Walk the pulldown-cmark event stream, rewriting `memvault://` link
/// destinations to in-app routes.
fn rewrite_link_events<'a>(parser: Parser<'a>) -> Vec<Event<'a>> {
    let mut out = Vec::new();
    let mut current_link_text: Option<(Tag<'a>, String)> = None;
    for event in parser {
        match event {
            Event::Start(Tag::Link {
                link_type,
                dest_url,
                title,
                id,
            }) => {
                let rewritten_dest = match rewrite_dest(&dest_url) {
                    Cow::Borrowed(_) => dest_url.clone(),
                    Cow::Owned(s) => CowStr::Boxed(s.into_boxed_str()),
                };
                let new_tag = Tag::Link {
                    link_type,
                    dest_url: rewritten_dest,
                    title,
                    id,
                };
                current_link_text = Some((new_tag.clone(), String::new()));
                out.push(Event::Start(new_tag));
            }
            Event::End(TagEnd::Link) => {
                current_link_text = None;
                out.push(Event::End(TagEnd::Link));
            }
            Event::Text(t) => {
                if let Some((_, ref mut buf)) = current_link_text {
                    buf.push_str(&t);
                }
                out.push(Event::Text(t));
            }
            other => out.push(other),
        }
    }
    out
}

/// Resolve a `memvault://…` destination to the matching app route, or
/// leave the URL alone when it isn't a memvault URI.
fn rewrite_dest(dest: &str) -> Cow<'_, str> {
    if !dest.starts_with("memvault:") {
        return Cow::Borrowed(dest);
    }
    let Ok(parsed) = parse_uri(dest) else {
        return Cow::Borrowed(dest);
    };
    let route = match parsed.kind {
        LinkTargetKind::Doc => format!("/notes/{}", parsed.ident),
        LinkTargetKind::Entity => format!("/graph/{}", parsed.ident),
        LinkTargetKind::File => format!("/files/{}", parsed.ident),
        // Unresolved aliases route to search — better than a broken link.
        LinkTargetKind::Alias => format!("/search?q={}", url_encode_query(&parsed.ident)),
    };
    Cow::Owned(route)
}

fn url_encode_query(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for &b in s.as_bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char);
            }
            b' ' => out.push('+'),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wikilink_to_markdown_link() {
        let out = preprocess_wikilinks("See [[doc:abcd]] please.");
        assert!(out.contains("(memvault://doc/abcd)"));
        assert!(out.contains("[doc abcd]"));
    }

    #[test]
    fn alias_wikilink_with_label() {
        let out = preprocess_wikilinks("Find [[entity:1234|Alice]].");
        assert!(out.contains("[Alice]"));
        assert!(out.contains("(memvault://entity/1234?alias=Alice)"));
    }

    #[test]
    fn bare_alias_wikilink() {
        let out = preprocess_wikilinks("Ask [[Alice]].");
        assert!(out.contains("[Alice]"));
        assert!(out.contains("(memvault://alias/Alice)"));
    }

    #[test]
    fn wikilink_in_code_preserved() {
        let out = preprocess_wikilinks("`[[doc:abcd]]` is the syntax.");
        // The fenceless code span stays literal.
        assert!(out.starts_with("`[[doc:abcd]]`"));
    }

    #[test]
    fn full_render_replaces_href() {
        let html = render_doc_body("See [[doc:abcd]] now.");
        assert!(html.contains("href=\"/notes/abcd\""), "got: {html}");
    }

    #[test]
    fn full_render_markdown_link_resolved() {
        let html = render_doc_body("[Alice](memvault://entity/1234)");
        assert!(html.contains("href=\"/graph/1234\""), "got: {html}");
    }

    #[test]
    fn full_render_non_memvault_unchanged() {
        let html = render_doc_body("[Google](https://google.com)");
        assert!(html.contains("href=\"https://google.com\""));
    }

    #[test]
    fn full_render_file_link() {
        let html = render_doc_body("Attached [[file:c0ffee]].");
        assert!(html.contains("href=\"/files/c0ffee\""), "got: {html}");
    }

    #[test]
    fn unresolved_alias_routes_to_search() {
        let html = render_doc_body("[[Hello World]]");
        assert!(
            html.contains("href=\"/search?q=Hello+World\""),
            "got: {html}"
        );
    }
}

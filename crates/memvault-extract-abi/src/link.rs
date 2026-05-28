//! Link extraction types — shared between plugins and host.
//!
//! Plugins return `ExtractedLink`s alongside `ExtractedText`. Links are
//! addressed via the `memvault://` URI scheme:
//!
//! ```text
//! memvault://doc/<hex>[?alias=…][?rel=…][?at=<hex>][?weight=…][?bucket=<hex>][#L…]
//! memvault://entity/<hex>[…]
//! memvault://file/<hex>[…]
//! memvault://alias/<urlencoded>      // unresolved alias
//! ```
//!
//! The URI is the **sole source of relation** (`?rel=`). Plugins that want
//! to assert a semantic relation synthesize it into the URI; the host then
//! applies an allowlist and demotes disallowed relations to `mentions`.

use serde::{Deserialize, Serialize};

/// Source syntax the plugin observed when extracting the link. Used by the
/// host to round-trip rewrites (e.g. promoting an unresolved alias to a
/// canonical ref) back into the original syntax form.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LinkSyntax {
    /// `[[doc:hex|Alice]]` / `[[Alice]]`
    Wikilink,
    /// `[Alice](memvault://doc/hex)`
    MarkdownLink,
    /// `<a href="memvault://doc/hex">Alice</a>`
    HtmlAnchor,
    /// `links: [memvault://…]` in document frontmatter
    FrontmatterRef,
    /// PDF/DOCX/etc. hyperlink annotations embedded in binary formats.
    EmbeddedHyperlink,
}

/// A link extracted from document or attachment content.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtractedLink {
    /// Canonical `memvault://…` URI. The only place semantic relation lives.
    pub uri: String,
    /// Human-readable text the author wrote for this link, if any.
    #[serde(default)]
    pub display_text: Option<String>,
    /// Byte span (start, end_exclusive) in the source content — useful for
    /// hover-preview and span-aware UIs. `(0, 0)` means span unknown.
    /// Markdown/HTML extractors use source bytes; binary extractors that
    /// can't map back to a source offset leave this zero.
    #[serde(default)]
    pub byte_span: (u32, u32),
    /// Source syntax of the link in the original content.
    pub syntax: LinkSyntax,
}

/// What kind of node a URI addresses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkTargetKind {
    Doc,
    Entity,
    File,
    Alias,
}

/// Parsed view of a `memvault://` URI. Plugins/hosts use [`parse_uri`] to
/// validate and inspect URIs without depending on `memvault-core` types.
#[derive(Debug, Clone, PartialEq)]
pub struct ParsedUri {
    pub kind: LinkTargetKind,
    /// Hex-encoded identifier for `Doc`/`Entity`/`File`; raw alias string
    /// (already percent-decoded) for `Alias`.
    pub ident: String,
    pub alias: Option<String>,
    /// `?rel=` — semantic relation. Host validates against allowlist.
    pub relation: Option<String>,
    /// `?at=<hex>` — pinned op CID.
    pub pinned_at: Option<String>,
    /// `?weight=…` — edge weight hint.
    pub weight: Option<f32>,
    /// `?bucket=<hex>` — bucket for cross-bucket links.
    pub bucket: Option<String>,
    /// `#…` — fragment (target-side hint, e.g. `L42-L60`).
    pub fragment: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UriError {
    MissingScheme,
    UnknownScheme,
    MissingHost,
    UnknownKind(String),
    MissingIdent,
    InvalidHex,
    BadEscape,
    BadWeight,
}

impl std::fmt::Display for UriError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingScheme => write!(f, "missing scheme"),
            Self::UnknownScheme => write!(f, "unknown scheme; expected memvault://"),
            Self::MissingHost => write!(f, "missing host component"),
            Self::UnknownKind(s) => write!(f, "unknown target kind: {s}"),
            Self::MissingIdent => write!(f, "missing identifier"),
            Self::InvalidHex => write!(f, "identifier is not valid hex"),
            Self::BadEscape => write!(f, "malformed percent-encoding"),
            Self::BadWeight => write!(f, "weight is not a valid f32"),
        }
    }
}

impl std::error::Error for UriError {}

/// Parse a `memvault://kind/<ident>[?query][#frag]` URI into a [`ParsedUri`].
pub fn parse_uri(s: &str) -> Result<ParsedUri, UriError> {
    let rest = s.strip_prefix("memvault:").ok_or(UriError::MissingScheme)?;
    let rest = rest.strip_prefix("//").ok_or(UriError::UnknownScheme)?;

    // Split off fragment first.
    let (body, fragment) = match rest.find('#') {
        Some(i) => (&rest[..i], Some(percent_decode(&rest[i + 1..])?)),
        None => (rest, None),
    };
    // Then query.
    let (path, query) = match body.find('?') {
        Some(i) => (&body[..i], Some(&body[i + 1..])),
        None => (body, None),
    };

    let (kind_str, ident_raw) = path.split_once('/').ok_or(UriError::MissingHost)?;
    if ident_raw.is_empty() {
        return Err(UriError::MissingIdent);
    }
    let kind = match kind_str {
        "doc" => LinkTargetKind::Doc,
        "entity" => LinkTargetKind::Entity,
        "file" => LinkTargetKind::File,
        "alias" => LinkTargetKind::Alias,
        other => return Err(UriError::UnknownKind(other.to_string())),
    };
    let ident = match kind {
        LinkTargetKind::Alias => percent_decode(ident_raw)?,
        _ => {
            if !is_hex(ident_raw) {
                return Err(UriError::InvalidHex);
            }
            ident_raw.to_string()
        }
    };

    let mut out = ParsedUri {
        kind,
        ident,
        alias: None,
        relation: None,
        pinned_at: None,
        weight: None,
        bucket: None,
        fragment,
    };

    if let Some(q) = query {
        for pair in q.split('&') {
            if pair.is_empty() {
                continue;
            }
            let (k, v) = match pair.split_once('=') {
                Some(kv) => kv,
                None => (pair, ""),
            };
            let v = percent_decode(v)?;
            match k {
                "alias" => out.alias = Some(v),
                "rel" => out.relation = Some(v),
                "at" => {
                    if !is_hex(&v) {
                        return Err(UriError::InvalidHex);
                    }
                    out.pinned_at = Some(v);
                }
                "weight" => out.weight = Some(v.parse().map_err(|_| UriError::BadWeight)?),
                "bucket" => {
                    if !is_hex(&v) {
                        return Err(UriError::InvalidHex);
                    }
                    out.bucket = Some(v);
                }
                _ => {} // unknown params silently ignored for forward-compat
            }
        }
    }

    Ok(out)
}

/// Render a [`ParsedUri`] back into a canonical `memvault://` URI string.
pub fn render_uri(p: &ParsedUri) -> String {
    let kind = match p.kind {
        LinkTargetKind::Doc => "doc",
        LinkTargetKind::Entity => "entity",
        LinkTargetKind::File => "file",
        LinkTargetKind::Alias => "alias",
    };
    let ident_enc = match p.kind {
        LinkTargetKind::Alias => percent_encode(&p.ident),
        _ => p.ident.clone(),
    };
    let mut out = format!("memvault://{kind}/{ident_enc}");

    let mut params: Vec<(&str, String)> = Vec::new();
    if let Some(a) = &p.alias {
        params.push(("alias", percent_encode(a)));
    }
    if let Some(r) = &p.relation {
        params.push(("rel", percent_encode(r)));
    }
    if let Some(at) = &p.pinned_at {
        params.push(("at", at.clone()));
    }
    if let Some(w) = p.weight {
        params.push(("weight", w.to_string()));
    }
    if let Some(b) = &p.bucket {
        params.push(("bucket", b.clone()));
    }
    if !params.is_empty() {
        out.push('?');
        for (i, (k, v)) in params.iter().enumerate() {
            if i > 0 {
                out.push('&');
            }
            out.push_str(k);
            out.push('=');
            out.push_str(v);
        }
    }
    if let Some(f) = &p.fragment {
        out.push('#');
        out.push_str(&percent_encode(f));
    }
    out
}

fn is_hex(s: &str) -> bool {
    !s.is_empty() && s.chars().all(|c| c.is_ascii_hexdigit())
}

/// Percent-encode a string for use inside a URI segment or query value.
/// Encodes everything outside the unreserved set per RFC 3986 plus `-_.~`,
/// keeping the output stable across plugin and host.
fn percent_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for &b in s.as_bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char);
            }
            _ => {
                out.push('%');
                out.push(hex_digit(b >> 4));
                out.push(hex_digit(b & 0x0F));
            }
        }
    }
    out
}

fn hex_digit(n: u8) -> char {
    match n {
        0..=9 => (b'0' + n) as char,
        10..=15 => (b'A' + (n - 10)) as char,
        _ => unreachable!(),
    }
}

fn percent_decode(s: &str) -> Result<String, UriError> {
    let bytes = s.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' => {
                if i + 2 >= bytes.len() {
                    return Err(UriError::BadEscape);
                }
                let hi = decode_hex(bytes[i + 1]).ok_or(UriError::BadEscape)?;
                let lo = decode_hex(bytes[i + 2]).ok_or(UriError::BadEscape)?;
                out.push((hi << 4) | lo);
                i += 3;
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            other => {
                out.push(other);
                i += 1;
            }
        }
    }
    String::from_utf8(out).map_err(|_| UriError::BadEscape)
}

fn decode_hex(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_doc_simple() {
        let p = parse_uri("memvault://doc/9f3a").unwrap();
        assert_eq!(p.kind, LinkTargetKind::Doc);
        assert_eq!(p.ident, "9f3a");
        assert_eq!(p.alias, None);
        assert_eq!(p.relation, None);
    }

    #[test]
    fn parse_full_uri() {
        let s = "memvault://entity/1b2c?alias=Alice%20Doe&rel=cites&at=deadbeef&weight=0.5&bucket=ab12#L42-L60";
        let p = parse_uri(s).unwrap();
        assert_eq!(p.kind, LinkTargetKind::Entity);
        assert_eq!(p.ident, "1b2c");
        assert_eq!(p.alias.as_deref(), Some("Alice Doe"));
        assert_eq!(p.relation.as_deref(), Some("cites"));
        assert_eq!(p.pinned_at.as_deref(), Some("deadbeef"));
        assert_eq!(p.weight, Some(0.5));
        assert_eq!(p.bucket.as_deref(), Some("ab12"));
        assert_eq!(p.fragment.as_deref(), Some("L42-L60"));
    }

    #[test]
    fn parse_alias_kind() {
        let p = parse_uri("memvault://alias/Alice%20Doe").unwrap();
        assert_eq!(p.kind, LinkTargetKind::Alias);
        assert_eq!(p.ident, "Alice Doe");
    }

    #[test]
    fn parse_file_kind() {
        let p = parse_uri("memvault://file/c0ffee").unwrap();
        assert_eq!(p.kind, LinkTargetKind::File);
        assert_eq!(p.ident, "c0ffee");
    }

    #[test]
    fn roundtrip_canonical() {
        let original = ParsedUri {
            kind: LinkTargetKind::Doc,
            ident: "9f3a".to_string(),
            alias: Some("Bob".to_string()),
            relation: Some("cites".to_string()),
            pinned_at: Some("ab12".to_string()),
            weight: Some(1.5),
            bucket: None,
            fragment: Some("intro".to_string()),
        };
        let s = render_uri(&original);
        let parsed = parse_uri(&s).unwrap();
        assert_eq!(parsed, original);
    }

    #[test]
    fn roundtrip_alias_with_special_chars() {
        let original = ParsedUri {
            kind: LinkTargetKind::Alias,
            ident: "Hello World/Subpage?yes".to_string(),
            alias: None,
            relation: None,
            pinned_at: None,
            weight: None,
            bucket: None,
            fragment: None,
        };
        let s = render_uri(&original);
        let parsed = parse_uri(&s).unwrap();
        assert_eq!(parsed.ident, "Hello World/Subpage?yes");
        assert_eq!(parsed, original);
    }

    #[test]
    fn rejects_unknown_scheme() {
        // No `memvault:` prefix → MissingScheme.
        assert_eq!(parse_uri("https://doc/abc"), Err(UriError::MissingScheme));
        // `memvault:` prefix without `//` → UnknownScheme.
        assert_eq!(parse_uri("memvault:doc/abc"), Err(UriError::UnknownScheme));
    }

    #[test]
    fn rejects_missing_scheme() {
        assert_eq!(parse_uri("doc/abc"), Err(UriError::MissingScheme));
    }

    #[test]
    fn rejects_unknown_kind() {
        assert!(matches!(
            parse_uri("memvault://chunk/abc"),
            Err(UriError::UnknownKind(_))
        ));
    }

    #[test]
    fn rejects_invalid_hex() {
        assert_eq!(
            parse_uri("memvault://doc/not-hex"),
            Err(UriError::InvalidHex)
        );
    }

    #[test]
    fn rejects_missing_ident() {
        assert_eq!(parse_uri("memvault://doc/"), Err(UriError::MissingIdent));
    }

    #[test]
    fn forward_compat_unknown_param() {
        let p = parse_uri("memvault://doc/abcd?future=42&alias=A").unwrap();
        assert_eq!(p.alias.as_deref(), Some("A"));
    }

    #[test]
    fn rejects_bad_weight() {
        assert_eq!(
            parse_uri("memvault://doc/abcd?weight=not-a-number"),
            Err(UriError::BadWeight)
        );
    }

    #[test]
    fn extracted_link_roundtrip_cbor() {
        let link = ExtractedLink {
            uri: "memvault://doc/9f3a?alias=Bob".to_string(),
            display_text: Some("Bob".to_string()),
            byte_span: (10, 20),
            syntax: LinkSyntax::Wikilink,
        };
        let mut buf = Vec::new();
        ciborium::into_writer(&link, &mut buf).unwrap();
        let decoded: ExtractedLink = ciborium::from_reader(buf.as_slice()).unwrap();
        assert_eq!(decoded.uri, link.uri);
        assert_eq!(decoded.display_text, link.display_text);
        assert_eq!(decoded.byte_span, link.byte_span);
        assert_eq!(decoded.syntax, link.syntax);
    }
}

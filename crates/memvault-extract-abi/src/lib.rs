use serde::{Deserialize, Serialize};

mod link;

pub use link::{ExtractedLink, LinkSyntax, LinkTargetKind, ParsedUri, UriError, parse_uri, render_uri};

// ─── Input envelope ────────────────────────────────────────────────────────────

/// Header portion of the binary input envelope (CBOR-encoded).
/// The full envelope is: [4 bytes LE header_len][header CBOR][raw file content].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtractionInput {
    /// MIME type of the content (e.g. "text/html")
    pub mime: String,
    /// File extension without dot (e.g. "docx"), for extension-based dispatch
    #[serde(default)]
    pub extension: Option<String>,
    /// Extraction hints
    #[serde(default)]
    pub hints: ExtractionHints,
}

/// Hints passed to extractors for resource control.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ExtractionHints {
    /// Truncate extracted text if larger than this many bytes
    #[serde(default)]
    pub max_text_bytes: Option<usize>,
    /// Timeout in milliseconds (advisory — host enforces via fuel)
    #[serde(default)]
    pub timeout_ms: Option<u64>,
}

// ─── Output ────────────────────────────────────────────────────────────────────

/// Response from an extractor plugin (CBOR-encoded).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ExtractionResponse {
    Ok(ExtractedText),
    Err { code: String, message: String },
}

/// Successfully extracted text content.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtractedText {
    /// Extractor identifier (e.g. "plain-text@1.0")
    pub extractor: String,
    /// Extractor version
    pub extractor_version: String,
    /// Extracted plain text
    pub text: String,
    /// Byte offsets of page/section breaks within `text`
    pub page_breaks: Vec<u32>,
    /// Extraction warnings (e.g. "possible scanned PDF")
    #[serde(default)]
    pub warnings: Vec<String>,
    /// Links discovered in the source, addressed via `memvault://` URIs.
    /// Plugins that only extract text leave this empty. Spans (when set)
    /// index into `text`.
    #[serde(default)]
    pub links: Vec<ExtractedLink>,
}

// ─── Plugin capabilities ───────────────────────────────────────────────────────

/// Capabilities declared by a plugin (CBOR-encoded), returned by the
/// `capabilities` export.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginCapabilities {
    /// Unique plugin identifier
    pub id: String,
    /// Plugin version
    pub version: String,
    /// List of capabilities this plugin provides
    pub capabilities: Vec<ExtractorCapability>,
}

/// A single extraction capability with its own match rule and priority.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtractorCapability {
    /// What this capability matches on
    pub match_rule: MatchRule,
    /// Priority level. Higher = preferred when multiple plugins match.
    /// Built-ins default to 0. Custom plugins use higher values to override.
    #[serde(default)]
    pub priority: i32,
}

/// How a capability matches incoming files.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MatchRule {
    /// Match by MIME type (e.g. "text/html")
    Mime(String),
    /// Match by file extension without dot (e.g. "docx")
    Extension(String),
}

// ─── Binary envelope encoding ──────────────────────────────────────────────────

/// Encode an extraction request into the binary envelope format:
/// `[4 bytes LE header_len][header CBOR][raw content]`
pub fn encode_envelope(input: &ExtractionInput, content: &[u8]) -> Vec<u8> {
    let mut header_cbor = Vec::new();
    ciborium::into_writer(input, &mut header_cbor).expect("CBOR serialization cannot fail");

    let header_len = header_cbor.len() as u32;
    let mut envelope = Vec::with_capacity(4 + header_cbor.len() + content.len());
    envelope.extend_from_slice(&header_len.to_le_bytes());
    envelope.extend_from_slice(&header_cbor);
    envelope.extend_from_slice(content);
    envelope
}

/// Decode a binary envelope into the header and raw content slice.
/// Returns `(header, content_offset)` where content starts at `&data[content_offset..]`.
pub fn decode_envelope(data: &[u8]) -> Result<(ExtractionInput, &[u8]), EnvelopeError> {
    if data.len() < 4 {
        return Err(EnvelopeError::TooShort);
    }
    let header_len = u32::from_le_bytes([data[0], data[1], data[2], data[3]]) as usize;
    let header_end = 4 + header_len;
    if data.len() < header_end {
        return Err(EnvelopeError::TooShort);
    }
    let header: ExtractionInput =
        ciborium::from_reader(&data[4..header_end]).map_err(EnvelopeError::Cbor)?;
    Ok((header, &data[header_end..]))
}

/// Encode an extraction response to CBOR bytes.
pub fn encode_response(response: &ExtractionResponse) -> Vec<u8> {
    let mut buf = Vec::new();
    ciborium::into_writer(response, &mut buf).expect("CBOR serialization cannot fail");
    buf
}

/// Decode an extraction response from CBOR bytes.
pub fn decode_response(data: &[u8]) -> Result<ExtractionResponse, EnvelopeError> {
    ciborium::from_reader(data).map_err(EnvelopeError::Cbor)
}

/// Encode plugin capabilities to CBOR bytes.
pub fn encode_capabilities(caps: &PluginCapabilities) -> Vec<u8> {
    let mut buf = Vec::new();
    ciborium::into_writer(caps, &mut buf).expect("CBOR serialization cannot fail");
    buf
}

/// Decode plugin capabilities from CBOR bytes.
pub fn decode_capabilities(data: &[u8]) -> Result<PluginCapabilities, EnvelopeError> {
    ciborium::from_reader(data).map_err(EnvelopeError::Cbor)
}

// ─── Errors ────────────────────────────────────────────────────────────────────

#[derive(Debug)]
pub enum EnvelopeError {
    TooShort,
    Cbor(ciborium::de::Error<std::io::Error>),
}

impl std::fmt::Display for EnvelopeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TooShort => write!(f, "envelope too short"),
            Self::Cbor(e) => write!(f, "CBOR decode error: {e}"),
        }
    }
}

impl std::error::Error for EnvelopeError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn envelope_roundtrip() {
        let input = ExtractionInput {
            mime: "text/html".to_string(),
            extension: Some("html".to_string()),
            hints: ExtractionHints {
                max_text_bytes: Some(1024),
                timeout_ms: None,
            },
        };
        let content = b"<html><body>Hello</body></html>";

        let envelope = encode_envelope(&input, content);
        let (decoded_input, decoded_content) = decode_envelope(&envelope).unwrap();

        assert_eq!(decoded_input.mime, "text/html");
        assert_eq!(decoded_input.extension.as_deref(), Some("html"));
        assert_eq!(decoded_input.hints.max_text_bytes, Some(1024));
        assert_eq!(decoded_content, content);
    }

    #[test]
    fn response_roundtrip() {
        let response = ExtractionResponse::Ok(ExtractedText {
            extractor: "html@1.0".to_string(),
            extractor_version: "1.0".to_string(),
            text: "Hello world".to_string(),
            page_breaks: vec![5],
            warnings: vec![],
            links: vec![],
        });

        let encoded = encode_response(&response);
        let decoded = decode_response(&encoded).unwrap();

        match decoded {
            ExtractionResponse::Ok(t) => {
                assert_eq!(t.text, "Hello world");
                assert_eq!(t.page_breaks, vec![5]);
            }
            _ => panic!("expected Ok"),
        }
    }

    #[test]
    fn capabilities_roundtrip() {
        let caps = PluginCapabilities {
            id: "builtin".to_string(),
            version: "0.1.0".to_string(),
            capabilities: vec![
                ExtractorCapability {
                    match_rule: MatchRule::Mime("text/html".to_string()),
                    priority: 0,
                },
                ExtractorCapability {
                    match_rule: MatchRule::Extension("htm".to_string()),
                    priority: 5,
                },
            ],
        };

        let encoded = encode_capabilities(&caps);
        let decoded = decode_capabilities(&encoded).unwrap();

        assert_eq!(decoded.capabilities.len(), 2);
        assert_eq!(decoded.capabilities[1].priority, 5);
    }

    #[test]
    fn forward_compat_missing_fields() {
        // Simulate an older version that doesn't include `extension` or `hints`
        let minimal = ciborium::Value::Map(vec![(
            ciborium::Value::Text("mime".to_string()),
            ciborium::Value::Text("text/plain".to_string()),
        )]);
        let mut buf = Vec::new();
        ciborium::into_writer(&minimal, &mut buf).unwrap();

        let decoded: ExtractionInput = ciborium::from_reader(buf.as_slice()).unwrap();
        assert_eq!(decoded.mime, "text/plain");
        assert_eq!(decoded.extension, None);
        assert_eq!(decoded.hints.max_text_bytes, None);
    }
}

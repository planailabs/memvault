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
    /// Guest-visible model file/dir paths keyed by role (e.g.
    /// "whisper" → "/models/whisper-small"). Paths are inside the
    /// sandbox namespace mapped by the host via allowed_paths.
    #[serde(default)]
    pub model_paths: std::collections::BTreeMap<String, String>,
    /// Preferred language (BCP-47 or "auto") for transcription/OCR.
    #[serde(default)]
    pub language: Option<String>,
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
    /// Timed segments for transcription extractors. Empty for plain text
    /// extraction. `byte_span` indexes into `text`.
    #[serde(default)]
    pub segments: Vec<TranscriptSegment>,
}

/// A timed transcript segment produced by audio transcription.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TranscriptSegment {
    /// Segment start in milliseconds from the beginning of the audio.
    pub start_ms: u64,
    /// Segment end in milliseconds.
    pub end_ms: u64,
    /// Byte range of this segment's text within `ExtractedText::text`.
    pub byte_span: (u32, u32),
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
    /// Which operation this capability serves. Plugins predating ops
    /// decode as `Extract`.
    #[serde(default)]
    pub op: PluginOp,
}

impl ExtractorCapability {
    /// Capability serving the `extract` export.
    pub fn extract(match_rule: MatchRule, priority: i32) -> Self {
        Self { match_rule, priority, op: PluginOp::Extract }
    }

    /// Capability serving the `render_pages` export.
    pub fn render(match_rule: MatchRule, priority: i32) -> Self {
        Self { match_rule, priority, op: PluginOp::RenderPages }
    }
}

/// Operation a plugin capability serves. The same MIME can be claimed by
/// different plugins for different ops (e.g. fast text extraction vs page
/// rendering for `application/pdf`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum PluginOp {
    /// Text extraction via the `extract` export.
    #[default]
    Extract,
    /// Page rendering via the `render_pages` export.
    RenderPages,
}

/// How a capability matches incoming files.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MatchRule {
    /// Match by MIME type (e.g. "text/html")
    Mime(String),
    /// Match by file extension without dot (e.g. "docx")
    Extension(String),
    /// Match by MIME prefix (e.g. "audio/")
    MimePrefix(String),
}

// ─── Page rendering (render_pages export) ──────────────────────────────────────

/// Header portion of the binary render input envelope (CBOR-encoded).
/// Same wire layout as extraction: `[4 bytes LE header_len][header CBOR][raw content]`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RenderInput {
    /// MIME type of the content (e.g. "application/pdf")
    pub mime: String,
    /// File extension without dot, for extension-based dispatch
    #[serde(default)]
    pub extension: Option<String>,
    /// Rendering parameters
    pub params: RenderParams,
}

/// Parameters controlling page rasterization.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RenderParams {
    /// Raster resolution in dots per inch (PDF user space is 72/inch).
    pub dpi: u32,
    /// First page to render in this call, 0-based. The host loops over
    /// batches to bound guest memory.
    pub page_start: u32,
    /// Number of pages to render in this call.
    pub page_count: u32,
    /// Encoding of the returned page images.
    pub image_format: RenderImageFormat,
    /// Downscale so the longest image edge does not exceed this.
    #[serde(default)]
    pub max_edge_px: Option<u32>,
    /// Guest-visible model paths (same semantics as `ExtractionHints::model_paths`).
    #[serde(default)]
    pub model_paths: std::collections::BTreeMap<String, String>,
}

/// Image encoding for rendered pages.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum RenderImageFormat {
    #[default]
    Png,
    Webp,
}

impl RenderImageFormat {
    pub fn mime(self) -> &'static str {
        match self {
            Self::Png => "image/png",
            Self::Webp => "image/webp",
        }
    }
}

/// Response from a `render_pages` call (CBOR-encoded).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RenderResponse {
    Ok(RenderedPages),
    Err { code: String, message: String },
}

/// A batch of rendered pages.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RenderedPages {
    /// Renderer identifier (e.g. "memvault-pdfrender")
    pub renderer: String,
    /// Renderer version
    pub renderer_version: String,
    /// Total page count of the document (not just this batch).
    pub total_pages: u32,
    /// Rendered pages for the requested batch window.
    pub pages: Vec<RenderedPage>,
    #[serde(default)]
    pub warnings: Vec<String>,
}

/// One rendered page with its text layer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RenderedPage {
    /// 1-based page number.
    pub page_no: u32,
    pub width_px: u32,
    pub height_px: u32,
    /// Encoded image bytes (format per `RenderParams::image_format`).
    pub image: Vec<u8>,
    /// Text layer word boxes in image pixel coordinates.
    pub words: Vec<WordBox>,
    /// Where the text layer came from.
    pub text_source: TextSource,
}

/// Origin of a page's text layer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum TextSource {
    /// Embedded text extracted from the document.
    Embedded,
    /// Recognized via OCR.
    Ocr,
    /// No text available for this page.
    #[default]
    None,
}

/// A positioned word in image pixel coordinates (origin top-left).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WordBox {
    pub text: String,
    pub x: f32,
    pub y: f32,
    pub w: f32,
    pub h: f32,
}

/// Encode a render request into the binary envelope format:
/// `[4 bytes LE header_len][header CBOR][raw content]`
pub fn encode_render_envelope(input: &RenderInput, content: &[u8]) -> Vec<u8> {
    let mut header_cbor = Vec::new();
    ciborium::into_writer(input, &mut header_cbor).expect("CBOR serialization cannot fail");

    let header_len = header_cbor.len() as u32;
    let mut envelope = Vec::with_capacity(4 + header_cbor.len() + content.len());
    envelope.extend_from_slice(&header_len.to_le_bytes());
    envelope.extend_from_slice(&header_cbor);
    envelope.extend_from_slice(content);
    envelope
}

/// Decode a binary render envelope into the header and raw content slice.
pub fn decode_render_envelope(data: &[u8]) -> Result<(RenderInput, &[u8]), EnvelopeError> {
    if data.len() < 4 {
        return Err(EnvelopeError::TooShort);
    }
    let header_len = u32::from_le_bytes([data[0], data[1], data[2], data[3]]) as usize;
    let header_end = 4 + header_len;
    if data.len() < header_end {
        return Err(EnvelopeError::TooShort);
    }
    let header: RenderInput =
        ciborium::from_reader(&data[4..header_end]).map_err(EnvelopeError::Cbor)?;
    Ok((header, &data[header_end..]))
}

/// Encode a render response to CBOR bytes.
pub fn encode_render_response(response: &RenderResponse) -> Vec<u8> {
    let mut buf = Vec::new();
    ciborium::into_writer(response, &mut buf).expect("CBOR serialization cannot fail");
    buf
}

/// Decode a render response from CBOR bytes.
pub fn decode_render_response(data: &[u8]) -> Result<RenderResponse, EnvelopeError> {
    ciborium::from_reader(data).map_err(EnvelopeError::Cbor)
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
                ..Default::default()
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
            segments: vec![],
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
                ExtractorCapability::extract(MatchRule::Mime("text/html".to_string()), 0),
                ExtractorCapability::extract(MatchRule::Extension("htm".to_string()), 5),
            ],
        };

        let encoded = encode_capabilities(&caps);
        let decoded = decode_capabilities(&encoded).unwrap();

        assert_eq!(decoded.capabilities.len(), 2);
        assert_eq!(decoded.capabilities[1].priority, 5);
    }

    #[test]
    fn render_envelope_roundtrip() {
        let input = RenderInput {
            mime: "application/pdf".to_string(),
            extension: Some("pdf".to_string()),
            params: RenderParams {
                dpi: 144,
                page_start: 8,
                page_count: 8,
                image_format: RenderImageFormat::Png,
                max_edge_px: Some(4096),
                model_paths: Default::default(),
            },
        };
        let content = b"%PDF-1.7 fake";

        let envelope = encode_render_envelope(&input, content);
        let (decoded, decoded_content) = decode_render_envelope(&envelope).unwrap();

        assert_eq!(decoded.mime, "application/pdf");
        assert_eq!(decoded.params.dpi, 144);
        assert_eq!(decoded.params.page_start, 8);
        assert_eq!(decoded.params.image_format, RenderImageFormat::Png);
        assert_eq!(decoded_content, content);
    }

    #[test]
    fn render_response_roundtrip() {
        let response = RenderResponse::Ok(RenderedPages {
            renderer: "memvault-pdfrender".to_string(),
            renderer_version: "0.1.0".to_string(),
            total_pages: 12,
            pages: vec![RenderedPage {
                page_no: 9,
                width_px: 1224,
                height_px: 1584,
                image: vec![0x89, b'P', b'N', b'G'],
                words: vec![WordBox { text: "Invoice".into(), x: 72.0, y: 54.1, w: 88.2, h: 14.0 }],
                text_source: TextSource::Embedded,
            }],
            warnings: vec![],
        });

        let encoded = encode_render_response(&response);
        match decode_render_response(&encoded).unwrap() {
            RenderResponse::Ok(p) => {
                assert_eq!(p.total_pages, 12);
                assert_eq!(p.pages[0].words[0].text, "Invoice");
                assert_eq!(p.pages[0].text_source, TextSource::Embedded);
            }
            _ => panic!("expected Ok"),
        }
    }

    #[test]
    fn capability_op_defaults_to_extract() {
        // A capability serialized by an old plugin (no `op` field) must
        // decode as Extract.
        let minimal = ciborium::Value::Map(vec![(
            ciborium::Value::Text("match_rule".to_string()),
            ciborium::Value::Map(vec![(
                ciborium::Value::Text("Mime".to_string()),
                ciborium::Value::Text("text/html".to_string()),
            )]),
        )]);
        let mut buf = Vec::new();
        ciborium::into_writer(&minimal, &mut buf).unwrap();

        let decoded: ExtractorCapability = ciborium::from_reader(buf.as_slice()).unwrap();
        assert_eq!(decoded.op, PluginOp::Extract);
        assert_eq!(decoded.priority, 0);
    }

    #[test]
    fn extracted_text_without_segments_decodes() {
        // Old extractors omit `segments`.
        let response = ExtractionResponse::Ok(ExtractedText {
            extractor: "x".into(),
            extractor_version: "1".into(),
            text: "hi".into(),
            page_breaks: vec![],
            warnings: vec![],
            links: vec![],
            segments: vec![],
        });
        let encoded = encode_response(&response);
        let decoded = decode_response(&encoded).unwrap();
        match decoded {
            ExtractionResponse::Ok(t) => assert!(t.segments.is_empty()),
            _ => panic!("expected Ok"),
        }
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

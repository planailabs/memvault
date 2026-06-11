pub mod error;
pub mod registry;
pub mod wasm_host;

pub use error::ExtractError;
pub use memvault_extract_abi::{
    ExtractedText, ExtractionHints, ExtractionResponse, ExtractorCapability, MatchRule,
    PluginCapabilities, PluginOp, RenderImageFormat, RenderInput, RenderParams, RenderResponse,
    RenderedPage, RenderedPages, TextSource, TranscriptSegment, WordBox,
};
pub use registry::{ExtractionRegistry, MediaPlugins};
pub use wasm_host::{PluginOptions, ResourceLimits, WasmExtractor};

/// Embedded built-in text extractor WASM module.
/// Built from memvault-extract-guest-text targeting wasm32-unknown-unknown.
const BUILTIN_TEXT_WASM: &[u8] = include_bytes!(env!("MEMVAULT_EXTRACT_GUEST_TEXT_WASM"));

/// Embedded PDF page-render WASM module (hayro + pdfplumber, wasm32-wasip1).
#[cfg(feature = "media-plugins")]
const BUILTIN_PDFRENDER_WASM: &[u8] = include_bytes!(env!("MEMVAULT_EXTRACT_GUEST_PDFRENDER_WASM"));

/// Embedded OCR WASM module (ocrs/rten, wasm32-wasip1).
#[cfg(feature = "media-plugins")]
const BUILTIN_OCR_WASM: &[u8] = include_bytes!(env!("MEMVAULT_EXTRACT_GUEST_OCR_WASM"));

/// Embedded audio transcription WASM module (symphonia + candle whisper, wasm32-wasip1).
#[cfg(feature = "media-plugins")]
const BUILTIN_AUDIO_WASM: &[u8] = include_bytes!(env!("MEMVAULT_EXTRACT_GUEST_AUDIO_WASM"));

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_text_utf8_roundtrip() {
        let reg = ExtractionRegistry::with_defaults();
        let input = "Hello, world! Some UTF-8: über, café, 日本語";
        let result = reg
            .extract(input.as_bytes(), "text/plain", &ExtractionHints::default())
            .unwrap();
        assert_eq!(result.text, input);
        assert_eq!(result.extractor, "plain-text@1.0");
    }

    #[test]
    fn plain_text_invalid_bytes_replaced() {
        let reg = ExtractionRegistry::with_defaults();
        let input: &[u8] = &[0x48, 0x65, 0x6C, 0x6C, 0x6F, 0xFF, 0xFE];
        let result = reg
            .extract(input, "text/plain", &ExtractionHints::default())
            .unwrap();
        assert!(result.text.contains("Hello"));
        assert!(result.text.contains('\u{FFFD}')); // replacement char
    }

    #[test]
    fn markdown_strips_formatting() {
        let reg = ExtractionRegistry::with_defaults();
        let input =
            "Intro paragraph.\n\n# Title\n\nSome **bold** text and [a link](http://example.com).\n";
        let result = reg
            .extract(
                input.as_bytes(),
                "text/markdown",
                &ExtractionHints::default(),
            )
            .unwrap();
        assert!(result.text.contains("Title"));
        assert!(result.text.contains("bold"));
        assert!(result.text.contains("a link"));
        assert!(!result.text.contains("**"));
        assert!(!result.text.contains("http://example.com"));
        assert!(!result.page_breaks.is_empty()); // heading creates break
    }

    #[test]
    fn html_strips_tags() {
        let reg = ExtractionRegistry::with_defaults();
        let input = "<html><body><div>Hello</div><a href='x'>world</a></body></html>";
        let result = reg
            .extract(input.as_bytes(), "text/html", &ExtractionHints::default())
            .unwrap();
        assert!(result.text.contains("Hello"));
        assert!(result.text.contains("world"));
        assert!(!result.text.contains("<div>"));
        assert!(!result.text.contains("<a"));
    }

    #[test]
    fn pdf_non_pdf_returns_error() {
        let reg = ExtractionRegistry::with_defaults();
        let result = reg.extract(b"not a pdf", "application/pdf", &ExtractionHints::default());
        assert!(result.is_err());
    }

    #[test]
    fn registry_unsupported_mime() {
        let reg = ExtractionRegistry::with_defaults();
        let result = reg.extract(
            b"data",
            "application/octet-stream",
            &ExtractionHints::default(),
        );
        assert!(matches!(result, Err(ExtractError::UnsupportedMime(_))));
    }

    #[test]
    fn registry_can_extract() {
        let reg = ExtractionRegistry::with_defaults();
        assert!(reg.can_extract("text/plain"));
        assert!(reg.can_extract("text/markdown"));
        assert!(reg.can_extract("text/html"));
        assert!(reg.can_extract("application/pdf"));
        assert!(!reg.can_extract("application/octet-stream"));
    }

    #[test]
    fn registry_can_extract_extension() {
        let reg = ExtractionRegistry::with_defaults();
        assert!(reg.can_extract_extension("txt"));
        assert!(reg.can_extract_extension("md"));
        assert!(reg.can_extract_extension("html"));
        assert!(reg.can_extract_extension("pdf"));
        assert!(reg.can_extract_extension("docx"));
        assert!(!reg.can_extract_extension("exe"));
    }

    #[test]
    fn max_text_bytes_truncation() {
        let reg = ExtractionRegistry::with_defaults();
        let input = "a".repeat(1000);
        let hints = ExtractionHints {
            max_text_bytes: Some(100),
            ..Default::default()
        };
        let result = reg.extract(input.as_bytes(), "text/plain", &hints).unwrap();
        assert_eq!(result.text.len(), 100);
    }

    #[cfg(feature = "media-plugins")]
    #[test]
    fn media_registry_op_dispatch() {
        let set = MediaPlugins {
            pdfrender: Some(PluginOptions::default()),
            ocr: Some(PluginOptions::default()),
            audio: Some(PluginOptions::default()),
        };
        let reg = ExtractionRegistry::with_media_plugins(&set);

        // RenderPages routes to pdfrender for PDFs and ocr for images.
        assert!(reg.can_render("application/pdf"));
        assert!(reg.can_render("image/png"));
        assert!(!reg.can_render("text/plain"));

        // Extract routes to ocr for images and audio via MimePrefix.
        assert!(reg.can_extract("image/png"));
        assert!(reg.can_extract("audio/mpeg"));
        assert!(reg.can_extract("audio/x-flac"));

        // The text registry serves Extract only — no render capability.
        let text_reg = ExtractionRegistry::with_defaults();
        assert!(!text_reg.can_render("application/pdf"));
        // And the media registry must not shadow text extraction for PDFs.
        assert!(!reg.can_extract("application/pdf"));

        // Stub guests route correctly and report unimplemented.
        let params = RenderParams {
            dpi: 144,
            page_start: 0,
            page_count: 1,
            image_format: RenderImageFormat::Png,
            max_edge_px: None,
            model_paths: Default::default(),
        };
        let err = reg.render_pages(b"%PDF", "application/pdf", &params).unwrap_err();
        assert!(matches!(err, ExtractError::ExtractionFailed(m) if m.contains("not yet implemented")));
    }

    #[test]
    fn extract_by_extension() {
        let reg = ExtractionRegistry::with_defaults();
        let input = "# Hello\n\nWorld";
        let result = reg
            .extract_by_extension(input.as_bytes(), "md", &ExtractionHints::default())
            .unwrap();
        assert!(result.text.contains("Hello"));
        assert!(result.text.contains("World"));
    }
}

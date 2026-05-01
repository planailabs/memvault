pub mod async_queue;
pub mod error;
pub mod extracted;
pub mod extractor;
pub mod extractors;
pub mod registry;

pub use async_queue::{ExtractionJob, ExtractionQueue, ASYNC_THRESHOLD_BYTES};
pub use error::ExtractError;
pub use extracted::{ExtractedText, PiiFindingsBlock};
pub use extractor::{ExtractionHints, Extractor};
pub use memvault_policy::PiiFinding;
pub use registry::ExtractionRegistry;

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
        let input = "Intro paragraph.\n\n# Title\n\nSome **bold** text and [a link](http://example.com).\n";
        let result = reg
            .extract(input.as_bytes(), "text/markdown", &ExtractionHints::default())
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
        let result = reg.extract(b"data", "application/octet-stream", &ExtractionHints::default());
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
    fn extraction_queue_fifo() {
        let mut queue = ExtractionQueue::new();
        assert_eq!(queue.pending_count(), 0);
        assert!(queue.dequeue().is_none());

        queue.enqueue(ExtractionJob {
            manifest_cid: vec![1],
            mime_type: "text/plain".into(),
            content_size: 100,
            queued_at_ns: 1000,
        });
        queue.enqueue(ExtractionJob {
            manifest_cid: vec![2],
            mime_type: "text/html".into(),
            content_size: 200,
            queued_at_ns: 2000,
        });

        assert_eq!(queue.pending_count(), 2);
        let first = queue.dequeue().unwrap();
        assert_eq!(first.manifest_cid, vec![1]);
        let second = queue.dequeue().unwrap();
        assert_eq!(second.manifest_cid, vec![2]);
        assert!(queue.dequeue().is_none());
    }

    #[test]
    fn max_text_bytes_truncation() {
        let reg = ExtractionRegistry::with_defaults();
        let input = "a".repeat(1000);
        let hints = ExtractionHints {
            max_text_bytes: Some(100),
            ..Default::default()
        };
        let result = reg
            .extract(input.as_bytes(), "text/plain", &hints)
            .unwrap();
        assert_eq!(result.text.len(), 100);
    }
}

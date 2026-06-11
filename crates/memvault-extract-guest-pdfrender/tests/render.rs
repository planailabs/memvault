//! Native tests against a minimal hand-built fixture PDF (one US Letter
//! page, Helvetica "Hello Memvault" at 24pt, text origin 72/700 in PDF
//! user space).

use memvault_extract_abi::{
    RenderImageFormat, RenderInput, RenderParams, RenderResponse, TextSource,
    encode_render_envelope,
};
use memvault_extract_guest_pdfrender::render_pages_envelope;

const SIMPLE_PDF: &[u8] = include_bytes!("fixtures/simple.pdf");

fn params(dpi: u32, page_start: u32, page_count: u32) -> RenderParams {
    RenderParams {
        dpi,
        page_start,
        page_count,
        image_format: RenderImageFormat::Png,
        max_edge_px: None,
        model_paths: Default::default(),
    }
}

fn render(content: &[u8], params: RenderParams) -> RenderResponse {
    let input = RenderInput {
        mime: "application/pdf".to_string(),
        extension: Some("pdf".to_string()),
        params,
    };
    render_pages_envelope(&encode_render_envelope(&input, content))
}

fn expect_ok(response: RenderResponse) -> memvault_extract_abi::RenderedPages {
    match response {
        RenderResponse::Ok(pages) => pages,
        RenderResponse::Err { code, message } => panic!("expected Ok, got {code}: {message}"),
    }
}

#[test]
fn renders_page_with_dpi_scaling_and_png_magic() {
    let at_72 = expect_ok(render(SIMPLE_PDF, params(72, 0, 1)));
    assert_eq!(at_72.total_pages, 1);
    assert_eq!(at_72.pages.len(), 1);
    let page = &at_72.pages[0];
    assert_eq!(page.page_no, 1);
    // US Letter is 612x792pt; dpi 72 renders at scale 1.
    assert_eq!((page.width_px, page.height_px), (612, 792));
    assert_eq!(&page.image[..8], b"\x89PNG\r\n\x1a\n");

    let at_144 = expect_ok(render(SIMPLE_PDF, params(144, 0, 1)));
    let page2 = &at_144.pages[0];
    assert_eq!((page2.width_px, page2.height_px), (1224, 1584));
}

#[test]
fn max_edge_px_caps_the_longest_edge() {
    let capped = expect_ok(render(SIMPLE_PDF, {
        let mut p = params(144, 0, 1);
        p.max_edge_px = Some(396);
        p
    }));
    let page = &capped.pages[0];
    assert_eq!(page.height_px, 396);
    assert!(page.width_px <= 396);
}

#[test]
fn embedded_words_have_sane_boxes() {
    let result = expect_ok(render(SIMPLE_PDF, params(144, 0, 1)));
    let page = &result.pages[0];
    assert_eq!(page.text_source, TextSource::Embedded);

    let texts: Vec<&str> = page.words.iter().map(|w| w.text.as_str()).collect();
    assert!(texts.contains(&"Hello"), "words: {texts:?}");
    assert!(texts.contains(&"Memvault"), "words: {texts:?}");

    let hello = page.words.iter().find(|w| w.text == "Hello").unwrap();
    // Text origin is x=72pt, baseline y=700pt from the bottom of a 792pt
    // page → top-left y ≈ 792-700-ascent ≈ 75pt. At dpi 144 (scale 2):
    // x ≈ 144px, y ≈ 150px. Allow slack for font metrics.
    assert!(hello.w > 0.0 && hello.h > 0.0);
    assert!((hello.x - 144.0).abs() < 10.0, "x = {}", hello.x);
    assert!((hello.y - 150.0).abs() < 40.0, "y = {}", hello.y);
    assert!(hello.x + hello.w <= page.width_px as f32);
    assert!(hello.y + hello.h <= page.height_px as f32);
}

#[test]
fn page_start_past_end_yields_empty_batch() {
    let result = expect_ok(render(SIMPLE_PDF, params(72, 5, 1)));
    assert_eq!(result.total_pages, 1);
    assert!(result.pages.is_empty());
}

#[test]
fn zero_page_count_yields_empty_batch() {
    let result = expect_ok(render(SIMPLE_PDF, params(72, 0, 0)));
    assert_eq!(result.total_pages, 1);
    assert!(result.pages.is_empty());
}

#[test]
fn webp_request_falls_back_to_png_with_warning() {
    let result = expect_ok(render(SIMPLE_PDF, {
        let mut p = params(72, 0, 1);
        p.image_format = RenderImageFormat::Webp;
        p
    }));
    assert!(result.warnings.iter().any(|w| w.contains("webp")));
    assert_eq!(&result.pages[0].image[..8], b"\x89PNG\r\n\x1a\n");
}

#[test]
fn malformed_pdf_is_a_parse_error() {
    match render(b"%PDF", params(72, 0, 1)) {
        RenderResponse::Err { code, .. } => assert_eq!(code, "parse"),
        RenderResponse::Ok(_) => panic!("expected parse error"),
    }
}

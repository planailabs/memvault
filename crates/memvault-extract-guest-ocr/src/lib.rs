//! OCR guest plugin for raster images.
//!
//! Recognizes text (ocrs/rten) in images for the `extract` op and produces
//! a 1-page render with word boxes for the `render_pages` op. Runs
//! sandboxed under Extism on `wasm32-wasip1`. Model files are read from
//! the guest-visible path passed via `model_paths` (host maps its models
//! dir read-only into the sandbox).

use std::collections::BTreeMap;

use image::RgbImage;
use memvault_extract_abi::{
    ExtractedText, ExtractionHints, ExtractionResponse, ExtractorCapability, MatchRule,
    PluginCapabilities, RenderImageFormat, RenderParams, RenderResponse, RenderedPage,
    RenderedPages, TextSource, WordBox,
};
use crate::ocrs::{ImageSource, OcrEngine, TextItem};

// Vendored engine keeps its full upstream public surface; parts of it are
// unused here.
#[allow(dead_code, unused_imports)]
mod ocrs;

pub const EXTRACTOR: &str = "memvault-ocr";

const IMAGE_MIMES: &[&str] = &["image/png", "image/jpeg", "image/webp", "image/tiff"];
const IMAGE_EXTS: &[&str] = &["png", "jpg", "jpeg", "webp", "tif", "tiff"];

/// `model_paths` keys for the ocrs detection / recognition models.
pub const MODEL_KEY_DETECTION: &str = "ocr-detection";
pub const MODEL_KEY_RECOGNITION: &str = "ocr-recognition";

/// Build this plugin's capability declaration.
pub fn plugin_capabilities() -> PluginCapabilities {
    let mut capabilities = Vec::new();
    for mime in IMAGE_MIMES {
        capabilities.push(ExtractorCapability::extract(MatchRule::Mime(mime.to_string()), 0));
        capabilities.push(ExtractorCapability::render(MatchRule::Mime(mime.to_string()), 0));
    }
    for ext in IMAGE_EXTS {
        capabilities.push(ExtractorCapability::extract(MatchRule::Extension(ext.to_string()), 0));
        capabilities.push(ExtractorCapability::render(MatchRule::Extension(ext.to_string()), 0));
    }
    PluginCapabilities {
        id: EXTRACTOR.to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        capabilities,
    }
}

// ─── Errors ────────────────────────────────────────────────────────────────────

/// Internal error carrying the ABI error code ("config", "decode", "model",
/// "ocr") plus a message; converted into the op-specific Err response.
struct OcrError {
    code: &'static str,
    message: String,
}

impl OcrError {
    fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self { code, message: message.into() }
    }
}

// ─── extract op ────────────────────────────────────────────────────────────────

/// OCR an image from a raw extraction envelope. Pure logic, natively testable.
pub fn extract_envelope(envelope: &[u8]) -> ExtractionResponse {
    let (input, content) = match memvault_extract_abi::decode_envelope(envelope) {
        Ok(v) => v,
        Err(e) => {
            return ExtractionResponse::Err {
                code: "envelope".to_string(),
                message: format!("invalid envelope: {e}"),
            };
        }
    };
    extract_image(content, &input.hints)
}

/// OCR raw image bytes into text, honoring `max_text_bytes`.
pub fn extract_image(content: &[u8], hints: &ExtractionHints) -> ExtractionResponse {
    match ocr_text(content, &hints.model_paths) {
        Ok(lines) => {
            let mut text = lines.join("\n");
            truncate_to_bytes(&mut text, hints.max_text_bytes);
            ExtractionResponse::Ok(ExtractedText {
                extractor: EXTRACTOR.to_string(),
                extractor_version: env!("CARGO_PKG_VERSION").to_string(),
                text,
                page_breaks: Vec::new(),
                warnings: Vec::new(),
                links: Vec::new(),
                segments: Vec::new(),
            })
        }
        Err(e) => ExtractionResponse::Err { code: e.code.to_string(), message: e.message },
    }
}

fn ocr_text(content: &[u8], model_paths: &BTreeMap<String, String>) -> Result<Vec<String>, OcrError> {
    let (det, rec) = required_model_paths(model_paths)?;
    let rgb = decode_image(content)?;
    engine::with_engine(&det, &rec, |eng| run_ocr(eng, &rgb))?.map(|out| out.lines)
}

// ─── render_pages op ───────────────────────────────────────────────────────────

/// Produce a 1-page render with OCR word boxes from a raw render envelope.
pub fn render_pages_envelope(envelope: &[u8]) -> RenderResponse {
    let (input, content) = match memvault_extract_abi::decode_render_envelope(envelope) {
        Ok(v) => v,
        Err(e) => {
            return RenderResponse::Err {
                code: "envelope".to_string(),
                message: format!("invalid render envelope: {e}"),
            };
        }
    };
    render_image_page(content, &input.params)
}

/// Render an image as a single page (page_no 1) with an OCR word layer.
pub fn render_image_page(content: &[u8], params: &RenderParams) -> RenderResponse {
    let mut warnings = Vec::new();
    if params.image_format == RenderImageFormat::Webp {
        warnings.push("webp encoding not supported; pages encoded as png".to_string());
    }

    // Images are always exactly one page; later batch windows are empty.
    if params.page_start > 0 || params.page_count == 0 {
        return ok_pages(Vec::new(), warnings);
    }

    let page = match render_one_page(content, params, &mut warnings) {
        Ok(p) => p,
        Err(e) => {
            return RenderResponse::Err { code: e.code.to_string(), message: e.message };
        }
    };
    ok_pages(vec![page], warnings)
}

fn ok_pages(pages: Vec<RenderedPage>, warnings: Vec<String>) -> RenderResponse {
    RenderResponse::Ok(RenderedPages {
        renderer: EXTRACTOR.to_string(),
        renderer_version: env!("CARGO_PKG_VERSION").to_string(),
        total_pages: 1,
        pages,
        warnings,
    })
}

fn render_one_page(
    content: &[u8],
    params: &RenderParams,
    warnings: &mut Vec<String>,
) -> Result<RenderedPage, OcrError> {
    let (det, rec) = required_model_paths(&params.model_paths)?;
    let rgb = decode_image(content)?;
    // OCR runs on the final (possibly downscaled) pixels so word boxes are
    // already in output-image coordinates.
    let rgb = downscale_to_max_edge(rgb, params.max_edge_px);
    let (width_px, height_px) = rgb.dimensions();

    // OCR inference failures degrade to an image-only page; model load
    // failures are hard errors (the whole point of this plugin).
    let words = match engine::with_engine(&det, &rec, |eng| run_ocr(eng, &rgb))? {
        Ok(out) => out.words,
        Err(e) => {
            warnings.push(format!("ocr failed: {}", e.message));
            Vec::new()
        }
    };
    let text_source = if words.is_empty() { TextSource::None } else { TextSource::Ocr };

    let image = encode_png(&rgb)
        .map_err(|e| OcrError::new("encode", format!("png encoding failed: {e}")))?;

    Ok(RenderedPage { page_no: 1, width_px, height_px, image, words, text_source })
}

// ─── Model path / cache plumbing ───────────────────────────────────────────────

/// Resolve the two required model paths from a `model_paths` map.
fn required_model_paths(map: &BTreeMap<String, String>) -> Result<(String, String), OcrError> {
    match (map.get(MODEL_KEY_DETECTION), map.get(MODEL_KEY_RECOGNITION)) {
        (Some(det), Some(rec)) => Ok((det.clone(), rec.clone())),
        _ => Err(OcrError::new("config", "ocr models not configured")),
    }
}

/// True when the cached engine (if any) was loaded from different paths
/// and must be reloaded. Pure, natively testable.
fn needs_reload(cached: Option<(&str, &str)>, det: &str, rec: &str) -> bool {
    cached != Some((det, rec))
}

mod engine {
    use super::{OcrError, needs_reload};
    use crate::ocrs::{OcrEngine, OcrEngineParams};

    struct CachedEngine {
        det_path: String,
        rec_path: String,
        engine: OcrEngine,
    }

    // The plugin instance persists across calls (the host keeps it alive),
    // so the loaded engine is cached and only reloaded when the model paths
    // change. thread_local because OcrEngine need not be Sync; the wasm
    // guest is single-threaded anyway.
    thread_local! {
        static ENGINE: std::cell::RefCell<Option<CachedEngine>> = const { std::cell::RefCell::new(None) };
    }

    fn load_model(path: &str, role: &str) -> Result<rten::Model, OcrError> {
        let bytes = std::fs::read(path).map_err(|e| {
            OcrError::new("model", format!("failed to read {role} model {path}: {e}"))
        })?;
        rten::Model::load(bytes).map_err(|e| {
            OcrError::new("model", format!("failed to load {role} model {path}: {e}"))
        })
    }

    fn load_engine(det: &str, rec: &str) -> Result<OcrEngine, OcrError> {
        let detection_model = load_model(det, "detection")?;
        let recognition_model = load_model(rec, "recognition")?;
        OcrEngine::new(OcrEngineParams {
            detection_model: Some(detection_model),
            recognition_model: Some(recognition_model),
            ..Default::default()
        })
        .map_err(|e| OcrError::new("model", format!("failed to initialize ocr engine: {e}")))
    }

    /// Run `f` with the cached engine, (re)loading it first if the model
    /// paths changed since the last call.
    pub(super) fn with_engine<R>(
        det: &str,
        rec: &str,
        f: impl FnOnce(&OcrEngine) -> R,
    ) -> Result<R, OcrError> {
        ENGINE.with(|cell| {
            let mut slot = cell.borrow_mut();
            let cached = slot
                .as_ref()
                .map(|c| (c.det_path.as_str(), c.rec_path.as_str()));
            if needs_reload(cached, det, rec) {
                *slot = None; // drop the old engine before loading a new one
                *slot = Some(CachedEngine {
                    det_path: det.to_string(),
                    rec_path: rec.to_string(),
                    engine: load_engine(det, rec)?,
                });
            }
            Ok(f(&slot.as_ref().expect("engine just cached").engine))
        })
    }
}

// ─── Image handling ────────────────────────────────────────────────────────────

/// Decode raster image bytes (format sniffed from magic bytes) to RGB8.
fn decode_image(content: &[u8]) -> Result<RgbImage, OcrError> {
    let img = image::load_from_memory(content)
        .map_err(|e| OcrError::new("decode", format!("failed to decode image: {e}")))?;
    Ok(img.into_rgb8())
}

/// Dimensions after downscaling so the longest edge is at most `max_edge`,
/// preserving aspect ratio. Never upscales. Pure, natively testable.
fn downscaled_dimensions(width: u32, height: u32, max_edge: u32) -> (u32, u32) {
    let longest = width.max(height).max(1);
    let max_edge = max_edge.max(1);
    if longest <= max_edge {
        return (width, height);
    }
    let scale = max_edge as f64 / longest as f64;
    let w = ((width as f64 * scale).round() as u32).max(1);
    let h = ((height as f64 * scale).round() as u32).max(1);
    (w, h)
}

/// Downscale so the longest edge is at most `max_edge_px` (no-op if already
/// within bounds or no limit given).
fn downscale_to_max_edge(img: RgbImage, max_edge_px: Option<u32>) -> RgbImage {
    let Some(max_edge) = max_edge_px else { return img };
    let (w, h) = img.dimensions();
    let (nw, nh) = downscaled_dimensions(w, h, max_edge);
    if (nw, nh) == (w, h) {
        return img;
    }
    image::imageops::resize(&img, nw, nh, image::imageops::FilterType::Triangle)
}

fn encode_png(img: &RgbImage) -> Result<Vec<u8>, image::ImageError> {
    use image::ImageEncoder;
    let mut buf = Vec::new();
    image::codecs::png::PngEncoder::new(&mut buf).write_image(
        img.as_raw(),
        img.width(),
        img.height(),
        image::ExtendedColorType::Rgb8,
    )?;
    Ok(buf)
}

// ─── OCR ───────────────────────────────────────────────────────────────────────

struct OcrOutcome {
    /// Recognized text lines in reading order (whitespace-only lines removed).
    lines: Vec<String>,
    /// Word boxes in image pixel coordinates (whitespace-only words removed).
    words: Vec<WordBox>,
}

/// Run detection + recognition over an RGB image. Inference failures are
/// reported with code "ocr".
fn run_ocr(engine: &OcrEngine, rgb: &RgbImage) -> Result<OcrOutcome, OcrError> {
    fn ocr_err(stage: &str) -> impl Fn(&dyn std::fmt::Display) -> OcrError + '_ {
        move |e| OcrError::new("ocr", format!("{stage} failed: {e}"))
    }
    let source = ImageSource::from_bytes(rgb.as_raw(), rgb.dimensions())
        .map_err(|e| OcrError::new("ocr", format!("invalid image buffer: {e}")))?;
    let input = engine
        .prepare_input(source)
        .map_err(|e| ocr_err("input preparation")(&e))?;
    let word_rects = engine
        .detect_words(&input)
        .map_err(|e| ocr_err("text detection")(&e))?;
    let line_rects = engine.find_text_lines(&input, &word_rects);
    let recognized = engine
        .recognize_text(&input, &line_rects)
        .map_err(|e| ocr_err("text recognition")(&e))?;

    let mut lines = Vec::new();
    let mut words = Vec::new();
    for line in recognized.into_iter().flatten() {
        let line_text = line.to_string();
        if line_text.trim().is_empty() {
            continue;
        }
        lines.push(line_text);
        for word in line.words() {
            let text = word.to_string();
            if text.trim().is_empty() {
                continue;
            }
            let corners = word.rotated_rect().corners();
            let (x, y, w, h) = aabb_from_corners(corners.map(|p| (p.x, p.y)));
            words.push(WordBox { text, x, y, w, h });
        }
    }
    Ok(OcrOutcome { lines, words })
}

/// Axis-aligned bounding box (x, y, w, h) of a rotated rect's corner points.
/// Pure, natively testable.
fn aabb_from_corners(corners: [(f32, f32); 4]) -> (f32, f32, f32, f32) {
    let mut min_x = f32::INFINITY;
    let mut min_y = f32::INFINITY;
    let mut max_x = f32::NEG_INFINITY;
    let mut max_y = f32::NEG_INFINITY;
    for (x, y) in corners {
        min_x = min_x.min(x);
        min_y = min_y.min(y);
        max_x = max_x.max(x);
        max_y = max_y.max(y);
    }
    (min_x, min_y, (max_x - min_x).max(0.0), (max_y - min_y).max(0.0))
}

/// Truncate `text` to at most `max` bytes on a char boundary.
fn truncate_to_bytes(text: &mut String, max: Option<usize>) {
    if let Some(max) = max {
        if text.len() > max {
            let mut end = max;
            while end > 0 && !text.is_char_boundary(end) {
                end -= 1;
            }
            text.truncate(end);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use memvault_extract_abi::{ExtractionInput, PluginOp, RenderInput};

    fn model_paths(det: &str, rec: &str) -> BTreeMap<String, String> {
        BTreeMap::from([
            (MODEL_KEY_DETECTION.to_string(), det.to_string()),
            (MODEL_KEY_RECOGNITION.to_string(), rec.to_string()),
        ])
    }

    fn png_bytes(width: u32, height: u32) -> Vec<u8> {
        let img = RgbImage::from_pixel(width, height, image::Rgb([255, 255, 255]));
        encode_png(&img).unwrap()
    }

    fn extract_with(content: &[u8], hints: ExtractionHints) -> ExtractionResponse {
        let input = ExtractionInput { mime: "image/png".to_string(), extension: None, hints };
        let envelope = memvault_extract_abi::encode_envelope(&input, content);
        extract_envelope(&envelope)
    }

    fn render_params(model_paths: BTreeMap<String, String>) -> RenderParams {
        RenderParams {
            dpi: 144,
            page_start: 0,
            page_count: 1,
            image_format: RenderImageFormat::Png,
            max_edge_px: None,
            model_paths,
        }
    }

    fn render_with(content: &[u8], params: RenderParams) -> RenderResponse {
        let input =
            RenderInput { mime: "image/png".to_string(), extension: None, params };
        let envelope = memvault_extract_abi::encode_render_envelope(&input, content);
        render_pages_envelope(&envelope)
    }

    #[test]
    fn capabilities_cover_extract_and_render_for_png() {
        let caps = plugin_capabilities();
        assert_eq!(caps.id, "memvault-ocr");
        let has = |op: PluginOp| {
            caps.capabilities.iter().any(|c| {
                c.op == op && matches!(&c.match_rule, MatchRule::Mime(m) if m == "image/png")
            })
        };
        assert!(has(PluginOp::Extract));
        assert!(has(PluginOp::RenderPages));
    }

    #[test]
    fn extract_missing_model_paths_is_config_error() {
        let resp = extract_with(&png_bytes(8, 8), ExtractionHints::default());
        match resp {
            ExtractionResponse::Err { code, message } => {
                assert_eq!(code, "config");
                assert_eq!(message, "ocr models not configured");
            }
            _ => panic!("expected Err"),
        }
    }

    #[test]
    fn extract_one_model_path_is_config_error() {
        let hints = ExtractionHints {
            model_paths: BTreeMap::from([(
                MODEL_KEY_DETECTION.to_string(),
                "/models/ocrs/text-detection.rten".to_string(),
            )]),
            ..Default::default()
        };
        let resp = extract_with(&png_bytes(8, 8), hints);
        assert!(matches!(resp, ExtractionResponse::Err { code, .. } if code == "config"));
    }

    #[test]
    fn extract_undecodable_image_is_decode_error() {
        let hints = ExtractionHints {
            model_paths: model_paths("/nonexistent/det.rten", "/nonexistent/rec.rten"),
            ..Default::default()
        };
        let resp = extract_with(b"definitely not an image", hints);
        assert!(matches!(resp, ExtractionResponse::Err { code, .. } if code == "decode"));
    }

    #[test]
    fn extract_missing_model_file_is_model_error() {
        let hints = ExtractionHints {
            model_paths: model_paths("/nonexistent/det.rten", "/nonexistent/rec.rten"),
            ..Default::default()
        };
        let resp = extract_with(&png_bytes(8, 8), hints);
        assert!(matches!(resp, ExtractionResponse::Err { code, .. } if code == "model"));
    }

    #[test]
    fn extract_garbage_model_file_is_model_error() {
        let path = std::env::temp_dir()
            .join(format!("memvault-ocr-test-garbage-{}.rten", std::process::id()));
        std::fs::write(&path, b"not an rten model").unwrap();
        let p = path.to_string_lossy().to_string();
        let hints = ExtractionHints {
            model_paths: model_paths(&p, &p),
            ..Default::default()
        };
        let resp = extract_with(&png_bytes(8, 8), hints);
        std::fs::remove_file(&path).ok();
        assert!(matches!(resp, ExtractionResponse::Err { code, .. } if code == "model"));
    }

    #[test]
    fn render_missing_model_paths_is_config_error() {
        let resp = render_with(&png_bytes(8, 8), render_params(BTreeMap::new()));
        assert!(matches!(resp, RenderResponse::Err { code, .. } if code == "config"));
    }

    #[test]
    fn render_undecodable_image_is_decode_error() {
        let params = render_params(model_paths("/nonexistent/d.rten", "/nonexistent/r.rten"));
        let resp = render_with(b"nope", params);
        assert!(matches!(resp, RenderResponse::Err { code, .. } if code == "decode"));
    }

    #[test]
    fn render_page_start_past_end_is_ok_and_empty() {
        // No models needed: later batch windows short-circuit.
        let mut params = render_params(BTreeMap::new());
        params.page_start = 1;
        match render_with(&png_bytes(8, 8), params) {
            RenderResponse::Ok(pages) => {
                assert_eq!(pages.total_pages, 1);
                assert!(pages.pages.is_empty());
                assert_eq!(pages.renderer, "memvault-ocr");
            }
            _ => panic!("expected Ok"),
        }
    }

    #[test]
    fn render_webp_format_warns() {
        let mut params = render_params(BTreeMap::new());
        params.page_start = 1; // short-circuit before config check
        params.image_format = RenderImageFormat::Webp;
        match render_with(&png_bytes(8, 8), params) {
            RenderResponse::Ok(pages) => {
                assert!(pages.warnings.iter().any(|w| w.contains("webp")));
            }
            _ => panic!("expected Ok"),
        }
    }

    #[test]
    fn downscaled_dimensions_math() {
        // Longest edge above limit: scale down, preserve aspect.
        assert_eq!(downscaled_dimensions(4000, 1000, 1000), (1000, 250));
        assert_eq!(downscaled_dimensions(1000, 4000, 1000), (250, 1000));
        // Already within limit: unchanged (never upscale).
        assert_eq!(downscaled_dimensions(800, 600, 1000), (800, 600));
        assert_eq!(downscaled_dimensions(1000, 1000, 1000), (1000, 1000));
        // Extreme aspect ratios never collapse to zero.
        assert_eq!(downscaled_dimensions(10_000, 1, 100), (100, 1));
        // Degenerate max edge clamps to 1.
        assert_eq!(downscaled_dimensions(10, 5, 0), (1, 1));
    }

    #[test]
    fn downscale_and_png_encode() {
        let img = RgbImage::from_pixel(400, 100, image::Rgb([10, 20, 30]));
        let small = downscale_to_max_edge(img, Some(200));
        assert_eq!(small.dimensions(), (200, 50));
        let png = encode_png(&small).unwrap();
        assert_eq!(&png[..8], b"\x89PNG\r\n\x1a\n");

        // None and large limits leave the image untouched.
        let img = RgbImage::from_pixel(40, 10, image::Rgb([0, 0, 0]));
        assert_eq!(downscale_to_max_edge(img.clone(), None).dimensions(), (40, 10));
        assert_eq!(downscale_to_max_edge(img, Some(40)).dimensions(), (40, 10));
    }

    #[test]
    fn aabb_from_rotated_corners() {
        // Axis-aligned input.
        let (x, y, w, h) = aabb_from_corners([(1.0, 2.0), (5.0, 2.0), (5.0, 4.0), (1.0, 4.0)]);
        assert_eq!((x, y, w, h), (1.0, 2.0, 4.0, 2.0));
        // Rotated 45°: diamond around (10, 10) with "radius" 2.
        let (x, y, w, h) =
            aabb_from_corners([(10.0, 8.0), (12.0, 10.0), (10.0, 12.0), (8.0, 10.0)]);
        assert_eq!((x, y, w, h), (8.0, 8.0, 4.0, 4.0));
        // Degenerate (single point) has zero size, not negative.
        let (_, _, w, h) = aabb_from_corners([(3.0, 3.0); 4]);
        assert_eq!((w, h), (0.0, 0.0));
    }

    #[test]
    fn cache_reload_logic() {
        assert!(needs_reload(None, "/m/det.rten", "/m/rec.rten"));
        assert!(!needs_reload(Some(("/m/det.rten", "/m/rec.rten")), "/m/det.rten", "/m/rec.rten"));
        assert!(needs_reload(Some(("/m/det.rten", "/m/rec.rten")), "/m/det2.rten", "/m/rec.rten"));
        assert!(needs_reload(Some(("/m/det.rten", "/m/rec.rten")), "/m/det.rten", "/m/rec2.rten"));
    }

    #[test]
    fn truncation_respects_char_boundaries() {
        let mut text = "héllo wörld".to_string();
        truncate_to_bytes(&mut text, Some(2)); // would split 'é' (2 bytes at index 1)
        assert_eq!(text, "h");

        let mut text = "abcdef".to_string();
        truncate_to_bytes(&mut text, Some(4));
        assert_eq!(text, "abcd");

        let mut text = "abc".to_string();
        truncate_to_bytes(&mut text, None);
        assert_eq!(text, "abc");
    }

    /// End-to-end OCR against real models. Gated on MEMVAULT_TEST_MODELS_DIR
    /// pointing at a models dir containing ocrs/text-detection.rten and
    /// ocrs/text-recognition.rten; skipped (passes) otherwise.
    #[test]
    fn real_models_end_to_end() {
        let Ok(dir) = std::env::var("MEMVAULT_TEST_MODELS_DIR") else {
            eprintln!("MEMVAULT_TEST_MODELS_DIR not set; skipping real-model OCR test");
            return;
        };
        let det = format!("{dir}/ocrs/text-detection.rten");
        let rec = format!("{dir}/ocrs/text-recognition.rten");

        // Synthetic image: white background with a few black bars. We only
        // assert the engine runs end-to-end, not that it finds real text.
        let mut img = RgbImage::from_pixel(400, 200, image::Rgb([255, 255, 255]));
        for x in 40..160 {
            for y in 60..80 {
                img.put_pixel(x, y, image::Rgb([0, 0, 0]));
            }
        }
        let png = encode_png(&img).unwrap();

        let hints = ExtractionHints {
            model_paths: model_paths(&det, &rec),
            ..Default::default()
        };
        match extract_with(&png, hints) {
            ExtractionResponse::Ok(t) => {
                assert_eq!(t.extractor, "memvault-ocr");
            }
            ExtractionResponse::Err { code, message } => {
                panic!("expected Ok, got {code}: {message}")
            }
        }

        // Render path with downscale: words (if any) must fit the final image.
        let mut params = render_params(model_paths(&det, &rec));
        params.max_edge_px = Some(200);
        match render_with(&png, params) {
            RenderResponse::Ok(pages) => {
                assert_eq!(pages.total_pages, 1);
                let page = &pages.pages[0];
                assert_eq!((page.width_px, page.height_px), (200, 100));
                assert_eq!(&page.image[..8], b"\x89PNG\r\n\x1a\n");
                for w in &page.words {
                    assert!(w.x >= 0.0 && w.y >= 0.0);
                    assert!(w.x + w.w <= page.width_px as f32 + 1.0);
                    assert!(w.y + w.h <= page.height_px as f32 + 1.0);
                }
            }
            RenderResponse::Err { code, message } => {
                panic!("expected Ok, got {code}: {message}")
            }
        }
    }
}

#[cfg(target_arch = "wasm32")]
mod wasm {
    use extism_pdk::*;

    #[plugin_fn]
    pub fn capabilities(_input: Vec<u8>) -> FnResult<Vec<u8>> {
        Ok(memvault_extract_abi::encode_capabilities(
            &super::plugin_capabilities(),
        ))
    }

    #[plugin_fn]
    pub fn extract(input: Vec<u8>) -> FnResult<Vec<u8>> {
        let response = super::extract_envelope(&input);
        Ok(memvault_extract_abi::encode_response(&response))
    }

    #[plugin_fn]
    pub fn render_pages(input: Vec<u8>) -> FnResult<Vec<u8>> {
        let response = super::render_pages_envelope(&input);
        Ok(memvault_extract_abi::encode_render_response(&response))
    }
}

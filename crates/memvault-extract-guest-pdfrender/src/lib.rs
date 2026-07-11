//! Page pre-rendering guest plugin for PDF documents.
//!
//! Rasterizes PDF pages to images (hayro) and extracts the embedded text
//! layer with word bounding boxes (pdfplumber) so the web UI can overlay
//! selectable text on each page image. Runs sandboxed under Extism on
//! `wasm32-wasip1`.

use hayro::hayro_interpret::InterpreterSettings;
use hayro::vello_cpu::color::palette::css::WHITE;
use hayro::{RenderCache, RenderSettings};
use image::ImageEncoder;
use memvault_extract_abi::{
    ExtractorCapability, MatchRule, PluginCapabilities, RenderImageFormat, RenderParams,
    RenderResponse, RenderedPage, RenderedPages, TextSource, WordBox,
};
use pdfplumber::WordOptions;

pub const RENDERER: &str = "memvault-pdfrender";

/// Build this plugin's capability declaration.
pub fn plugin_capabilities() -> PluginCapabilities {
    PluginCapabilities {
        id: RENDERER.to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        capabilities: vec![
            ExtractorCapability::render(MatchRule::Mime("application/pdf".to_string()), 0),
            ExtractorCapability::render(MatchRule::Extension("pdf".to_string()), 0),
        ],
    }
}

/// Render a batch of pages from a raw envelope. Pure logic, natively testable.
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
    render_pdf_pages(content, &input.params)
}

/// Render a window of PDF pages to PNG with an embedded-text word layer.
pub fn render_pdf_pages(content: &[u8], params: &RenderParams) -> RenderResponse {
    let mut warnings = Vec::new();
    if params.image_format == RenderImageFormat::Webp {
        warnings.push("webp encoding not supported; pages encoded as png".to_string());
    }

    let pdf = match hayro::hayro_syntax::Pdf::new(content.to_vec()) {
        Ok(pdf) => pdf,
        Err(e) => {
            return RenderResponse::Err {
                code: "parse".to_string(),
                message: format!("failed to parse pdf: {e:?}"),
            };
        }
    };
    let pages = pdf.pages();
    let total_pages = pages.len() as u32;

    // Text layer failures degrade to image-only pages, never to a call error.
    let plumber = match pdfplumber::Pdf::open(content, None) {
        Ok(p) => Some(p),
        Err(e) => {
            warnings.push(format!("text layer unavailable: {e}"));
            None
        }
    };

    let start = (params.page_start as usize).min(pages.len());
    let end = start
        .saturating_add(params.page_count as usize)
        .min(pages.len());

    let cache = RenderCache::new();
    let interpreter = InterpreterSettings::default();
    let mut rendered = Vec::with_capacity(end - start);
    for idx in start..end {
        let page = &pages[idx];
        let (width_pt, height_pt) = page.render_dimensions();
        let scale = effective_scale(params.dpi, params.max_edge_px, width_pt, height_pt);

        let pixmap = hayro::render(
            page,
            &cache,
            &interpreter,
            &RenderSettings {
                x_scale: scale,
                y_scale: scale,
                width: None,
                height: None,
                bg_color: WHITE,
            },
        );
        let (width_px, height_px) = (pixmap.width() as u32, pixmap.height() as u32);
        if width_px == 0 || height_px == 0 {
            warnings.push(format!("page {} rendered with zero area; skipped", idx + 1));
            continue;
        }
        let image = match encode_png(pixmap) {
            Ok(bytes) => bytes,
            Err(e) => {
                warnings.push(format!("page {} png encoding failed: {e}", idx + 1));
                continue;
            }
        };

        let words = match &plumber {
            Some(p) => extract_words(p, idx, scale, &mut warnings),
            None => Vec::new(),
        };
        let text_source = if words.is_empty() {
            TextSource::None
        } else {
            TextSource::Embedded
        };

        rendered.push(RenderedPage {
            page_no: (idx + 1) as u32,
            width_px,
            height_px,
            image,
            words,
            text_source,
        });
    }

    RenderResponse::Ok(RenderedPages {
        renderer: RENDERER.to_string(),
        renderer_version: env!("CARGO_PKG_VERSION").to_string(),
        total_pages,
        pages: rendered,
        warnings,
    })
}

/// Raster scale for a page: dpi over PDF's 72 units/inch, reduced so the
/// longest edge fits `max_edge_px` (and vello's u16 pixmap dimensions).
fn effective_scale(dpi: u32, max_edge_px: Option<u32>, width_pt: f32, height_pt: f32) -> f32 {
    let mut scale = dpi.max(1) as f32 / 72.0;
    let longest = width_pt.max(height_pt).max(1.0);
    if let Some(max_edge) = max_edge_px {
        if longest * scale > max_edge as f32 {
            scale = max_edge as f32 / longest;
        }
    }
    if longest * scale > u16::MAX as f32 {
        scale = u16::MAX as f32 / longest;
    }
    scale
}

/// Word boxes for one page, scaled from PDF points (top-left origin, crop
/// box viewport — matching hayro's render viewport) into image pixels.
fn extract_words(
    pdf: &pdfplumber::Pdf,
    page_idx: usize,
    scale: f32,
    warnings: &mut Vec<String>,
) -> Vec<WordBox> {
    let page = match pdf.page(page_idx) {
        Ok(p) => p,
        Err(e) => {
            warnings.push(format!("page {} text layer unavailable: {e}", page_idx + 1));
            return Vec::new();
        }
    };
    page.extract_words(&WordOptions::default())
        .into_iter()
        .filter(|w| !w.text.trim().is_empty())
        .map(|w| WordBox {
            text: w.text,
            x: w.bbox.x0 as f32 * scale,
            y: w.bbox.top as f32 * scale,
            w: (w.bbox.x1 - w.bbox.x0) as f32 * scale,
            h: (w.bbox.bottom - w.bbox.top) as f32 * scale,
        })
        .collect()
}

fn encode_png(pixmap: hayro::vello_cpu::Pixmap) -> Result<Vec<u8>, image::ImageError> {
    let (width, height) = (pixmap.width() as u32, pixmap.height() as u32);
    // White background makes alpha fully opaque, so premultiplied data is
    // already straight RGBA; unpremultiply anyway for correctness.
    let mut rgba = Vec::with_capacity(width as usize * height as usize * 4);
    for px in pixmap.take_unpremultiplied() {
        rgba.extend_from_slice(&[px.r, px.g, px.b, px.a]);
    }
    let mut buf = Vec::new();
    image::codecs::png::PngEncoder::new(&mut buf).write_image(
        &rgba,
        width,
        height,
        image::ExtendedColorType::Rgba8,
    )?;
    Ok(buf)
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
    pub fn render_pages(input: Vec<u8>) -> FnResult<Vec<u8>> {
        let response = super::render_pages_envelope(&input);
        Ok(memvault_extract_abi::encode_render_response(&response))
    }
}

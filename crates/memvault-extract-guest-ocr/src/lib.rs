//! OCR guest plugin for raster images.
//!
//! Recognizes text (ocrs/rten) in images for the `extract` op and produces
//! a 1-page render with word boxes for the `render_pages` op. Runs
//! sandboxed under Extism on `wasm32-wasip1`. Model files are read from
//! the guest-visible path passed via `model_paths` (host maps its models
//! dir read-only into the sandbox).

use memvault_extract_abi::{
    ExtractionResponse, ExtractorCapability, MatchRule, PluginCapabilities, RenderResponse,
};

pub const EXTRACTOR: &str = "memvault-ocr";

const IMAGE_MIMES: &[&str] = &["image/png", "image/jpeg", "image/webp", "image/tiff"];
const IMAGE_EXTS: &[&str] = &["png", "jpg", "jpeg", "webp", "tif", "tiff"];

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

/// OCR an image from a raw extraction envelope. Pure logic, natively testable.
pub fn extract_envelope(envelope: &[u8]) -> ExtractionResponse {
    let (_input, _content) = match memvault_extract_abi::decode_envelope(envelope) {
        Ok(v) => v,
        Err(e) => {
            return ExtractionResponse::Err {
                code: "envelope".to_string(),
                message: format!("invalid envelope: {e}"),
            };
        }
    };
    ExtractionResponse::Err {
        code: "unimplemented".to_string(),
        message: "ocr not yet implemented".to_string(),
    }
}

/// Produce a 1-page render with OCR word boxes from a raw render envelope.
pub fn render_pages_envelope(envelope: &[u8]) -> RenderResponse {
    let (_input, _content) = match memvault_extract_abi::decode_render_envelope(envelope) {
        Ok(v) => v,
        Err(e) => {
            return RenderResponse::Err {
                code: "envelope".to_string(),
                message: format!("invalid render envelope: {e}"),
            };
        }
    };
    RenderResponse::Err {
        code: "unimplemented".to_string(),
        message: "image page rendering not yet implemented".to_string(),
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

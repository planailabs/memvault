//! Page pre-rendering guest plugin for PDF documents.
//!
//! Rasterizes PDF pages to images (hayro) and extracts the embedded text
//! layer with word bounding boxes (pdfplumber) so the web UI can overlay
//! selectable text on each page image. Runs sandboxed under Extism on
//! `wasm32-wasip1`.

use memvault_extract_abi::{
    ExtractorCapability, MatchRule, PluginCapabilities, RenderResponse,
};

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
        message: "pdf page rendering not yet implemented".to_string(),
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
    pub fn render_pages(input: Vec<u8>) -> FnResult<Vec<u8>> {
        let response = super::render_pages_envelope(&input);
        Ok(memvault_extract_abi::encode_render_response(&response))
    }
}

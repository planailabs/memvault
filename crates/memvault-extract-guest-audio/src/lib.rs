//! Audio transcription guest plugin.
//!
//! Decodes audio (symphonia), resamples to 16 kHz mono (rubato), and runs
//! Whisper inference (candle) to produce a transcript with timed segments.
//! Runs sandboxed under Extism on `wasm32-wasip1`. Whisper model files are
//! read from the guest-visible path passed via `model_paths["whisper"]`.

use memvault_extract_abi::{
    ExtractionResponse, ExtractorCapability, MatchRule, PluginCapabilities,
};

pub const EXTRACTOR: &str = "memvault-whisper";

const AUDIO_EXTS: &[&str] = &["mp3", "m4a", "wav", "flac", "ogg", "oga", "opus"];

/// Build this plugin's capability declaration.
pub fn plugin_capabilities() -> PluginCapabilities {
    let mut capabilities = vec![ExtractorCapability::extract(
        MatchRule::MimePrefix("audio/".to_string()),
        0,
    )];
    for ext in AUDIO_EXTS {
        capabilities.push(ExtractorCapability::extract(MatchRule::Extension(ext.to_string()), 0));
    }
    PluginCapabilities {
        id: EXTRACTOR.to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        capabilities,
    }
}

/// Transcribe audio from a raw extraction envelope. Pure logic, natively testable.
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
        message: "audio transcription not yet implemented".to_string(),
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
}

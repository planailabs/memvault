use std::sync::Mutex;

use extism::{Manifest, Plugin, PluginBuilder, Wasm};
use memvault_extract_abi::{
    ExtractedText, ExtractionHints, ExtractionInput, ExtractionResponse, PluginCapabilities,
};

use crate::error::ExtractError;

/// Resource limits for a WASM extractor plugin.
#[derive(Debug, Clone)]
pub struct ResourceLimits {
    /// Maximum memory in pages (1 page = 64 KiB). None = unlimited.
    pub memory_max_pages: Option<u32>,
    /// Fuel limit (instruction count proxy). None = unlimited.
    pub fuel: Option<u64>,
}

impl Default for ResourceLimits {
    fn default() -> Self {
        Self {
            // 2560 MB (2.5 GiB) default
            memory_max_pages: Some(40960),
            // ~50 billion instructions
            fuel: Some(50_000_000_000),
        }
    }
}

/// A WASM-sandboxed extractor loaded via Extism.
pub struct WasmExtractor {
    plugin: Mutex<Plugin>,
    capabilities: PluginCapabilities,
}

impl WasmExtractor {
    /// Load a WASM extractor from raw bytes.
    pub fn from_bytes(wasm: &[u8], limits: &ResourceLimits) -> Result<Self, ExtractError> {
        let manifest = Self::build_manifest(Wasm::data(wasm.to_vec()), limits);
        Self::from_manifest(manifest, limits)
    }

    /// Load a WASM extractor from a file path.
    pub fn from_path(
        path: impl AsRef<std::path::Path>,
        limits: &ResourceLimits,
    ) -> Result<Self, ExtractError> {
        let wasm_data = std::fs::read(path.as_ref())
            .map_err(|e| ExtractError::PluginError(format!("failed to read plugin: {e}")))?;
        Self::from_bytes(&wasm_data, limits)
    }

    fn build_manifest(wasm: Wasm, limits: &ResourceLimits) -> Manifest {
        let mut manifest = Manifest::new([wasm]);
        if let Some(pages) = limits.memory_max_pages {
            manifest = manifest.with_memory_max(pages);
        }
        manifest
    }

    fn from_manifest(manifest: Manifest, limits: &ResourceLimits) -> Result<Self, ExtractError> {
        let mut builder = PluginBuilder::new(manifest).with_wasi(true);
        if let Some(fuel) = limits.fuel {
            builder = builder.with_fuel_limit(fuel);
        }
        let mut plugin = builder
            .build()
            .map_err(|e| ExtractError::PluginError(format!("failed to instantiate plugin: {e}")))?;

        // Query capabilities
        let caps_bytes = plugin
            .call::<&[u8], Vec<u8>>("capabilities", &[])
            .map_err(|e| ExtractError::PluginError(format!("failed to query capabilities: {e}")))?;

        let capabilities = memvault_extract_abi::decode_capabilities(&caps_bytes)
            .map_err(|e| ExtractError::PluginError(format!("invalid capabilities: {e}")))?;

        Ok(Self {
            plugin: Mutex::new(plugin),
            capabilities,
        })
    }

    /// Get the plugin capabilities.
    pub fn capabilities(&self) -> &PluginCapabilities {
        &self.capabilities
    }

    /// Check if this plugin supports a given MIME type.
    pub fn supports_mime(&self, mime: &str) -> bool {
        self.capabilities
            .capabilities
            .iter()
            .any(|c| match &c.match_rule {
                memvault_extract_abi::MatchRule::Mime(m) => m == mime,
                _ => false,
            })
    }

    /// Check if this plugin supports a given file extension.
    pub fn supports_extension(&self, ext: &str) -> bool {
        self.capabilities
            .capabilities
            .iter()
            .any(|c| match &c.match_rule {
                memvault_extract_abi::MatchRule::Extension(e) => e == ext,
                _ => false,
            })
    }

    /// Get the priority for a specific MIME type.
    pub fn priority_for_mime(&self, mime: &str) -> Option<i32> {
        self.capabilities
            .capabilities
            .iter()
            .find_map(|c| match &c.match_rule {
                memvault_extract_abi::MatchRule::Mime(m) if m == mime => Some(c.priority),
                _ => None,
            })
    }

    /// Get the priority for a specific extension.
    pub fn priority_for_extension(&self, ext: &str) -> Option<i32> {
        self.capabilities
            .capabilities
            .iter()
            .find_map(|c| match &c.match_rule {
                memvault_extract_abi::MatchRule::Extension(e) if e == ext => Some(c.priority),
                _ => None,
            })
    }

    /// Run extraction.
    pub fn extract(
        &self,
        content: &[u8],
        mime: &str,
        extension: Option<&str>,
        hints: &ExtractionHints,
    ) -> Result<ExtractedText, ExtractError> {
        let input = ExtractionInput {
            mime: mime.to_string(),
            extension: extension.map(|s| s.to_string()),
            hints: hints.clone(),
        };

        let envelope = memvault_extract_abi::encode_envelope(&input, content);

        let mut plugin = self.plugin.lock().unwrap();

        let output = plugin
            .call::<&[u8], Vec<u8>>("extract", &envelope)
            .map_err(|e| {
                let msg = e.to_string();
                if msg.contains("fuel") || msg.contains("Fuel") {
                    ExtractError::Timeout(hints.timeout_ms.unwrap_or(0))
                } else {
                    ExtractError::ExtractionFailed(msg)
                }
            })?;

        let response = memvault_extract_abi::decode_response(&output)
            .map_err(|e| ExtractError::ExtractionFailed(format!("invalid response: {e}")))?;

        match response {
            ExtractionResponse::Ok(text) => Ok(text),
            ExtractionResponse::Err { code, message } => {
                if code == "unsupported" {
                    Err(ExtractError::UnsupportedMime(message))
                } else {
                    Err(ExtractError::ExtractionFailed(message))
                }
            }
        }
    }
}

// Safety: Plugin is protected by Mutex
unsafe impl Send for WasmExtractor {}
unsafe impl Sync for WasmExtractor {}

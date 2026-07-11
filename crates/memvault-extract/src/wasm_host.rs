use std::sync::Mutex;

use extism::{Manifest, Plugin, PluginBuilder, Wasm};
use memvault_extract_abi::{
    ExtractedText, ExtractionHints, ExtractionInput, ExtractionResponse, MatchRule,
    PluginCapabilities, PluginOp, RenderInput, RenderResponse, RenderedPages,
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

/// Full loading options for a WASM extractor plugin. Supersedes bare
/// [`ResourceLimits`] for plugins that need wall-clock timeouts (instead of
/// fuel) or read-only host paths mapped into the sandbox (model files).
#[derive(Debug, Clone, Default)]
pub struct PluginOptions {
    /// Memory/fuel limits. Built-in media plugins run with `fuel: None`
    /// (whisper inference exceeds any sensible fuel budget) and are bounded
    /// by `timeout_ms` instead.
    pub limits: ResourceLimits,
    /// Wall-clock timeout per plugin call (epoch interruption).
    pub timeout_ms: Option<u64>,
    /// Host directory → guest path mappings (e.g. models dir → "/models").
    pub allowed_paths: Vec<(std::path::PathBuf, String)>,
}

impl PluginOptions {
    /// Options matching the legacy `ResourceLimits`-only behavior.
    pub fn from_limits(limits: ResourceLimits) -> Self {
        Self {
            limits,
            ..Default::default()
        }
    }
}

/// A WASM-sandboxed extractor loaded via Extism.
pub struct WasmExtractor {
    plugin: Mutex<Plugin>,
    capabilities: PluginCapabilities,
}

impl WasmExtractor {
    /// Load a WASM extractor from raw bytes with legacy limits.
    pub fn from_bytes(wasm: &[u8], limits: &ResourceLimits) -> Result<Self, ExtractError> {
        Self::from_bytes_with(wasm, &PluginOptions::from_limits(limits.clone()))
    }

    /// Load a WASM extractor from raw bytes with full options.
    pub fn from_bytes_with(wasm: &[u8], opts: &PluginOptions) -> Result<Self, ExtractError> {
        let manifest = Self::build_manifest(Wasm::data(wasm.to_vec()), opts);
        Self::from_manifest(manifest, opts)
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

    fn build_manifest(wasm: Wasm, opts: &PluginOptions) -> Manifest {
        let mut manifest = Manifest::new([wasm]);
        if let Some(pages) = opts.limits.memory_max_pages {
            manifest = manifest.with_memory_max(pages);
        }
        if let Some(ms) = opts.timeout_ms {
            manifest = manifest.with_timeout(std::time::Duration::from_millis(ms));
        }
        for (host_dir, guest_path) in &opts.allowed_paths {
            manifest =
                manifest.with_allowed_path(host_dir.display().to_string(), guest_path.clone());
        }
        manifest
    }

    fn from_manifest(manifest: Manifest, opts: &PluginOptions) -> Result<Self, ExtractError> {
        let mut builder = PluginBuilder::new(manifest).with_wasi(true);
        if let Some(fuel) = opts.limits.fuel {
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

    /// Check if this plugin supports a given MIME type (for `Extract`).
    pub fn supports_mime(&self, mime: &str) -> bool {
        self.priority_for_mime_op(mime, PluginOp::Extract).is_some()
    }

    /// Check if this plugin supports a given file extension (for `Extract`).
    pub fn supports_extension(&self, ext: &str) -> bool {
        self.priority_for_extension_op(ext, PluginOp::Extract)
            .is_some()
    }

    /// Check if this plugin serves `op` for the given MIME type.
    pub fn supports_op(&self, op: PluginOp, mime: &str) -> bool {
        self.priority_for_mime_op(mime, op).is_some()
    }

    /// Get the priority for a specific MIME type (for `Extract`).
    pub fn priority_for_mime(&self, mime: &str) -> Option<i32> {
        self.priority_for_mime_op(mime, PluginOp::Extract)
    }

    /// Highest priority among this plugin's capabilities matching `mime`
    /// for the given op. Exact `Mime` matches and `MimePrefix` matches both
    /// qualify.
    pub fn priority_for_mime_op(&self, mime: &str, op: PluginOp) -> Option<i32> {
        self.capabilities
            .capabilities
            .iter()
            .filter(|c| c.op == op)
            .filter_map(|c| match &c.match_rule {
                MatchRule::Mime(m) if m == mime => Some(c.priority),
                MatchRule::MimePrefix(p) if mime.starts_with(p.as_str()) => Some(c.priority),
                _ => None,
            })
            .max()
    }

    /// Get the priority for a specific extension (for `Extract`).
    pub fn priority_for_extension(&self, ext: &str) -> Option<i32> {
        self.priority_for_extension_op(ext, PluginOp::Extract)
    }

    /// Highest priority among this plugin's capabilities matching `ext`
    /// for the given op.
    pub fn priority_for_extension_op(&self, ext: &str, op: PluginOp) -> Option<i32> {
        self.capabilities
            .capabilities
            .iter()
            .filter(|c| c.op == op)
            .filter_map(|c| match &c.match_rule {
                MatchRule::Extension(e) if e == ext => Some(c.priority),
                _ => None,
            })
            .max()
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

        let mut plugin = self
            .plugin
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

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

    /// Render a batch of pages via the plugin's `render_pages` export.
    pub fn render_pages(
        &self,
        content: &[u8],
        input: &RenderInput,
    ) -> Result<RenderedPages, ExtractError> {
        let envelope = memvault_extract_abi::encode_render_envelope(input, content);

        let mut plugin = self
            .plugin
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        let output = plugin
            .call::<&[u8], Vec<u8>>("render_pages", &envelope)
            .map_err(|e| {
                let msg = e.to_string();
                if msg.contains("timeout") || msg.contains("epoch") {
                    ExtractError::Timeout(0)
                } else if msg.contains("fuel") || msg.contains("Fuel") {
                    ExtractError::Timeout(0)
                } else {
                    ExtractError::ExtractionFailed(msg)
                }
            })?;

        let response = memvault_extract_abi::decode_render_response(&output)
            .map_err(|e| ExtractError::ExtractionFailed(format!("invalid render response: {e}")))?;

        match response {
            RenderResponse::Ok(pages) => Ok(pages),
            RenderResponse::Err { code, message } => {
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

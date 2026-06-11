use std::path::Path;

use memvault_extract_abi::{ExtractionHints, PluginOp, RenderInput, RenderParams, RenderedPages};

use crate::error::ExtractError;
use crate::wasm_host::{PluginOptions, ResourceLimits, WasmExtractor};

/// Which built-in media plugins to load, each with its own sandbox options
/// (wall-clock timeouts instead of fuel, model dirs mapped via
/// `allowed_paths`). `None` entries are not loaded — the caller gates each
/// capability on its configuration.
#[derive(Debug, Clone, Default)]
pub struct MediaPlugins {
    /// PDF page rendering (hayro + pdfplumber).
    pub pdfrender: Option<PluginOptions>,
    /// Image OCR (ocrs/rten).
    pub ocr: Option<PluginOptions>,
    /// Audio transcription (candle whisper).
    pub audio: Option<PluginOptions>,
}

/// Registry that dispatches extraction to WASM-sandboxed plugins by MIME type or extension.
pub struct ExtractionRegistry {
    plugins: Vec<WasmExtractor>,
}

impl ExtractionRegistry {
    pub fn new() -> Self {
        Self {
            plugins: Vec::new(),
        }
    }

    /// Create with built-in extractors loaded.
    pub fn with_defaults() -> Self {
        let mut reg = Self::new();
        let limits = ResourceLimits::default();

        match WasmExtractor::from_bytes(crate::BUILTIN_TEXT_WASM, &limits) {
            Ok(plugin) => reg.plugins.push(plugin),
            Err(e) => {
                tracing::error!("failed to load built-in extractors: {e}");
            }
        }

        reg
    }

    /// Create a registry holding only the requested built-in media plugins.
    /// Meant to be long-lived (plugin instances persist across calls, so
    /// guests can cache loaded models), unlike the per-call `with_defaults`
    /// text registry.
    #[cfg(feature = "media-plugins")]
    pub fn with_media_plugins(set: &MediaPlugins) -> Self {
        let mut reg = Self::new();
        let builtins: [(&str, &Option<PluginOptions>, &[u8]); 3] = [
            ("pdfrender", &set.pdfrender, crate::BUILTIN_PDFRENDER_WASM),
            ("ocr", &set.ocr, crate::BUILTIN_OCR_WASM),
            ("audio", &set.audio, crate::BUILTIN_AUDIO_WASM),
        ];
        for (name, opts, wasm) in builtins {
            let Some(opts) = opts else { continue };
            match WasmExtractor::from_bytes_with(wasm, opts) {
                Ok(plugin) => reg.plugins.push(plugin),
                Err(e) => {
                    tracing::error!("failed to load built-in media plugin {name}: {e}");
                }
            }
        }
        reg
    }

    /// Create with built-in extractors and custom plugins from a directory.
    pub fn with_defaults_and_plugins(plugin_dir: &Path) -> Self {
        let mut reg = Self::with_defaults();
        reg.load_plugins_from(plugin_dir, &ResourceLimits::default());
        reg
    }

    /// Create with built-in extractors and custom plugins from the default
    /// plugin directory relative to a store path: `$store_dir/extractor-plugins/`.
    pub fn with_defaults_and_store_plugins(store_path: &Path) -> Self {
        let plugin_dir = store_path
            .parent()
            .unwrap_or(store_path)
            .join("extractor-plugins");
        Self::with_defaults_and_plugins(&plugin_dir)
    }

    /// Register a WASM extractor plugin.
    pub fn register(&mut self, plugin: WasmExtractor) {
        self.plugins.push(plugin);
    }

    /// Load all `.wasm` plugins from a directory.
    pub fn load_plugins_from(&mut self, dir: &Path, limits: &ResourceLimits) {
        let entries = match std::fs::read_dir(dir) {
            Ok(e) => e,
            Err(e) => {
                tracing::debug!("plugin directory {dir:?} not readable: {e}");
                return;
            }
        };

        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().is_some_and(|e| e == "wasm") {
                match WasmExtractor::from_path(&path, limits) {
                    Ok(plugin) => {
                        tracing::info!(
                            "loaded extractor plugin: {} v{} from {path:?}",
                            plugin.capabilities().id,
                            plugin.capabilities().version
                        );
                        self.plugins.push(plugin);
                    }
                    Err(e) => {
                        tracing::warn!("failed to load plugin {path:?}: {e}");
                    }
                }
            }
        }
    }

    /// Extract text from content with given MIME type.
    pub fn extract(
        &self,
        content: &[u8],
        mime: &str,
        hints: &ExtractionHints,
    ) -> Result<memvault_extract_abi::ExtractedText, ExtractError> {
        let plugin = self
            .find_by_mime(mime)
            .ok_or_else(|| ExtractError::UnsupportedMime(mime.to_string()))?;

        plugin.extract(content, mime, None, hints)
    }

    /// Extract text from content using file extension for dispatch.
    pub fn extract_by_extension(
        &self,
        content: &[u8],
        ext: &str,
        hints: &ExtractionHints,
    ) -> Result<memvault_extract_abi::ExtractedText, ExtractError> {
        let plugin = self
            .find_by_extension(ext)
            .ok_or_else(|| ExtractError::UnsupportedExtension(ext.to_string()))?;

        // Pass extension info so the guest can dispatch
        plugin.extract(content, "", Some(ext), hints)
    }

    /// Check if any plugin supports this MIME type.
    pub fn can_extract(&self, mime: &str) -> bool {
        self.find_by_mime(mime).is_some()
    }

    /// Check if any plugin supports this file extension.
    pub fn can_extract_extension(&self, ext: &str) -> bool {
        self.find_by_extension(ext).is_some()
    }

    /// Check if any plugin can render pages for this MIME type.
    pub fn can_render(&self, mime: &str) -> bool {
        self.find_by_mime_op(mime, PluginOp::RenderPages).is_some()
    }

    /// Render a batch of pages for content with the given MIME type.
    pub fn render_pages(
        &self,
        content: &[u8],
        mime: &str,
        params: &RenderParams,
    ) -> Result<RenderedPages, ExtractError> {
        let plugin = self
            .find_by_mime_op(mime, PluginOp::RenderPages)
            .ok_or_else(|| ExtractError::UnsupportedMime(mime.to_string()))?;

        let input = RenderInput {
            mime: mime.to_string(),
            extension: None,
            params: params.clone(),
        };
        plugin.render_pages(content, &input)
    }

    /// Find the highest-priority plugin for a MIME type (for `Extract`).
    fn find_by_mime(&self, mime: &str) -> Option<&WasmExtractor> {
        self.find_by_mime_op(mime, PluginOp::Extract)
    }

    /// Find the highest-priority plugin serving `op` for a MIME type.
    fn find_by_mime_op(&self, mime: &str, op: PluginOp) -> Option<&WasmExtractor> {
        self.plugins
            .iter()
            .filter_map(|p| p.priority_for_mime_op(mime, op).map(|pri| (p, pri)))
            .max_by_key(|(_, pri)| *pri)
            .map(|(p, _)| p)
    }

    /// Find the highest-priority plugin for a file extension (for `Extract`).
    fn find_by_extension(&self, ext: &str) -> Option<&WasmExtractor> {
        self.plugins
            .iter()
            .filter_map(|p| p.priority_for_extension(ext).map(|pri| (p, pri)))
            .max_by_key(|(_, pri)| *pri)
            .map(|(p, _)| p)
    }
}

impl Default for ExtractionRegistry {
    fn default() -> Self {
        Self::new()
    }
}

use std::path::Path;

use memvault_extract_abi::ExtractionHints;

use crate::error::ExtractError;
use crate::wasm_host::{ResourceLimits, WasmExtractor};

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

        match WasmExtractor::from_bytes(crate::BUILTIN_WASM, &limits) {
            Ok(plugin) => reg.plugins.push(plugin),
            Err(e) => {
                tracing::error!("failed to load built-in extractors: {e}");
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
        let plugin = self.find_by_mime(mime).ok_or_else(|| {
            ExtractError::UnsupportedMime(mime.to_string())
        })?;

        plugin.extract(content, mime, None, hints)
    }

    /// Extract text from content using file extension for dispatch.
    pub fn extract_by_extension(
        &self,
        content: &[u8],
        ext: &str,
        hints: &ExtractionHints,
    ) -> Result<memvault_extract_abi::ExtractedText, ExtractError> {
        let plugin = self.find_by_extension(ext).ok_or_else(|| {
            ExtractError::UnsupportedExtension(ext.to_string())
        })?;

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

    /// Find the highest-priority plugin for a MIME type.
    fn find_by_mime(&self, mime: &str) -> Option<&WasmExtractor> {
        self.plugins
            .iter()
            .filter_map(|p| p.priority_for_mime(mime).map(|pri| (p, pri)))
            .max_by_key(|(_, pri)| *pri)
            .map(|(p, _)| p)
    }

    /// Find the highest-priority plugin for a file extension.
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

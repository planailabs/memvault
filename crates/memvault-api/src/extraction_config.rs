//! Extraction pipeline configuration.
//!
//! Loaded from `<data_dir>/extraction.toml` (path overridable via the
//! `MEMVAULT_EXTRACTION_CONFIG` env var). Every option is optional and the
//! file itself may be absent: a capability is enabled only when its
//! prerequisites are configured, and each section takes an explicit
//! `enabled = false` override. Built-in text extraction is never gated by
//! this config.
//!
//! Disabled-capability contract (uniform across all surfaces): uploads do
//! not enqueue the op, lazy read triggers do not spawn, nothing is cached
//! as a failure, and status reads report `unavailable` with a reason.
//! Disabled means "don't run jobs on this node" — annotations synced from
//! peers that do have the capability are still served and indexed.

use std::path::{Path, PathBuf};

use serde::Deserialize;

/// Top-level `[extraction]` config.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ExtractionConfig {
    /// Directory holding model files, mapped read-only into media plugin
    /// sandboxes as `/models`. Unset → OCR and transcription unavailable.
    pub models_dir: Option<PathBuf>,
    /// Path to the LibreOffice binary for office→PDF conversion. Unset →
    /// autodetect `soffice` on PATH; missing → office conversion unavailable.
    pub libreoffice_path: Option<PathBuf>,
    pub render: RenderConfig,
    pub whisper: WhisperConfig,
    pub ocr: OcrConfig,
    pub limits: LimitsConfig,
}

/// `[render]` — PDF/image page pre-rendering. Works with zero config;
/// `enabled = false` switches it off.
#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RenderConfig {
    pub enabled: bool,
    /// Raster resolution (PDF points are 72/inch).
    pub dpi: u32,
    /// Hard cap on rendered pages per document.
    pub max_pages: u32,
    /// Pages per render_pages sandbox call (bounds guest memory).
    pub page_batch: u32,
    /// "png" (default) or "webp".
    pub image_format: String,
}

impl Default for RenderConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            dpi: 144,
            max_pages: 200,
            page_batch: 8,
            image_format: "png".to_string(),
        }
    }
}

/// `[whisper]` — audio transcription. Requires `models_dir` and
/// `model_dir` to be enabled.
#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct WhisperConfig {
    pub enabled: bool,
    /// Model directory (config.json, tokenizer.json, model.safetensors),
    /// relative to `models_dir` (absolute also accepted). Unset →
    /// transcription unavailable.
    pub model_dir: Option<PathBuf>,
    /// BCP-47 language tag or "auto".
    pub language: String,
    /// Skip audio longer than this many seconds.
    pub max_duration_secs: u64,
}

impl Default for WhisperConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            model_dir: None,
            language: "auto".to_string(),
            max_duration_secs: 2 * 60 * 60,
        }
    }
}

/// `[ocr]` — image OCR. Requires `models_dir` (with the default ocrs
/// model layout) to be enabled.
#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct OcrConfig {
    pub enabled: bool,
    /// Detection model path relative to `models_dir`.
    pub detection_model: PathBuf,
    /// Recognition model path relative to `models_dir`.
    pub recognition_model: PathBuf,
}

impl Default for OcrConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            detection_model: PathBuf::from("ocrs/text-detection.rten"),
            recognition_model: PathBuf::from("ocrs/text-recognition.rten"),
        }
    }
}

/// `[limits]` — per-plugin sandbox overrides. Media built-ins run without
/// fuel; wall-clock timeouts are the meaningful bound.
#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct LimitsConfig {
    pub audio_timeout_ms: u64,
    pub ocr_timeout_ms: u64,
    pub pdfrender_timeout_ms: u64,
    /// Memory cap in 64 KiB wasm pages for each media plugin.
    pub memory_max_pages: u32,
}

impl Default for LimitsConfig {
    fn default() -> Self {
        Self {
            audio_timeout_ms: 15 * 60 * 1000,
            ocr_timeout_ms: 2 * 60 * 1000,
            pdfrender_timeout_ms: 5 * 60 * 1000,
            memory_max_pages: 40960,
        }
    }
}

impl ExtractionConfig {
    /// Load from `<data_dir>/extraction.toml`, the `MEMVAULT_EXTRACTION_CONFIG`
    /// override path, or defaults when no file exists. A malformed file is
    /// an error worth surfacing loudly (silent defaults would mask typos),
    /// but the caller may choose to log-and-default.
    pub fn load(data_dir: &Path) -> Result<Self, String> {
        let path = std::env::var_os("MEMVAULT_EXTRACTION_CONFIG")
            .map(PathBuf::from)
            .unwrap_or_else(|| data_dir.join("extraction.toml"));
        if !path.exists() {
            return Ok(Self::default());
        }
        let raw = std::fs::read_to_string(&path)
            .map_err(|e| format!("read {}: {e}", path.display()))?;
        toml::from_str(&raw).map_err(|e| format!("parse {}: {e}", path.display()))
    }

    /// Absolute whisper model dir, when transcription is configured.
    pub fn whisper_model_dir(&self) -> Option<PathBuf> {
        if !self.whisper.enabled {
            return None;
        }
        let models_dir = self.models_dir.as_ref()?;
        let model_dir = self.whisper.model_dir.as_ref()?;
        let abs = if model_dir.is_absolute() {
            model_dir.clone()
        } else {
            models_dir.join(model_dir)
        };
        abs.is_dir().then_some(abs)
    }

    /// Why transcription is unavailable, when it is. `None` = available.
    pub fn whisper_unavailable_reason(&self) -> Option<String> {
        if !self.whisper.enabled {
            return Some("transcription disabled: whisper.enabled = false".into());
        }
        if self.models_dir.is_none() {
            return Some("transcription disabled: models_dir not set".into());
        }
        if self.whisper.model_dir.is_none() {
            return Some("transcription disabled: whisper.model_dir not set".into());
        }
        if self.whisper_model_dir().is_none() {
            return Some("transcription disabled: whisper model dir missing".into());
        }
        None
    }

    /// Absolute (detection, recognition) model paths, when OCR is configured.
    pub fn ocr_model_paths(&self) -> Option<(PathBuf, PathBuf)> {
        if !self.ocr.enabled {
            return None;
        }
        let models_dir = self.models_dir.as_ref()?;
        let abs = |p: &PathBuf| if p.is_absolute() { p.clone() } else { models_dir.join(p) };
        let det = abs(&self.ocr.detection_model);
        let rec = abs(&self.ocr.recognition_model);
        (det.is_file() && rec.is_file()).then_some((det, rec))
    }

    /// Why OCR is unavailable, when it is. `None` = available.
    pub fn ocr_unavailable_reason(&self) -> Option<String> {
        if !self.ocr.enabled {
            return Some("ocr disabled: ocr.enabled = false".into());
        }
        if self.models_dir.is_none() {
            return Some("ocr disabled: models_dir not set".into());
        }
        if self.ocr_model_paths().is_none() {
            return Some("ocr disabled: model files missing under models_dir".into());
        }
        None
    }

    /// Why page rendering is unavailable, when it is. `None` = available.
    pub fn render_unavailable_reason(&self) -> Option<String> {
        if !self.render.enabled {
            return Some("page rendering disabled: render.enabled = false".into());
        }
        None
    }

    /// Stable hash of the render parameters, recorded in page_render
    /// annotations for observability. Param changes do NOT auto-invalidate
    /// existing renders (a cluster of nodes with different configs would
    /// re-render in a ping-pong loop) — re-rendering happens only when no
    /// annotation exists or on an explicit re-render request.
    pub fn render_params_hash(&self) -> String {
        let canonical = format!(
            "dpi={};max_pages={};image_format={}",
            self.render.dpi, self.render.max_pages, self.render.image_format
        );
        let mut hasher = blake3::Hasher::new();
        hasher.update(canonical.as_bytes());
        format!("blake3:{}", hex::encode(&hasher.finalize().as_bytes()[..16]))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_when_no_file() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = ExtractionConfig::load(dir.path()).unwrap();
        assert!(cfg.render.enabled);
        assert_eq!(cfg.render.dpi, 144);
        assert!(cfg.whisper_unavailable_reason().is_some());
        assert!(cfg.ocr_unavailable_reason().is_some());
        assert!(cfg.render_unavailable_reason().is_none());
    }

    #[test]
    fn partial_file_overrides() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("extraction.toml"),
            "[render]\ndpi = 96\n\n[whisper]\nenabled = false\n",
        )
        .unwrap();
        let cfg = ExtractionConfig::load(dir.path()).unwrap();
        assert_eq!(cfg.render.dpi, 96);
        assert_eq!(cfg.render.max_pages, 200); // untouched default
        assert!(cfg
            .whisper_unavailable_reason()
            .unwrap()
            .contains("whisper.enabled"));
    }

    #[test]
    fn malformed_file_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("extraction.toml"), "[render]\ndpi = \"x\"\n").unwrap();
        assert!(ExtractionConfig::load(dir.path()).is_err());
    }

    #[test]
    fn unknown_keys_rejected() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("extraction.toml"), "[render]\ndpis = 96\n").unwrap();
        assert!(ExtractionConfig::load(dir.path()).is_err());
    }

    #[test]
    fn whisper_available_when_model_dir_exists() {
        let dir = tempfile::tempdir().unwrap();
        let models = dir.path().join("models");
        std::fs::create_dir_all(models.join("whisper-small")).unwrap();
        std::fs::write(
            dir.path().join("extraction.toml"),
            format!(
                "models_dir = \"{}\"\n[whisper]\nmodel_dir = \"whisper-small\"\n",
                models.display()
            ),
        )
        .unwrap();
        let cfg = ExtractionConfig::load(dir.path()).unwrap();
        assert!(cfg.whisper_unavailable_reason().is_none());
        assert!(cfg.whisper_model_dir().unwrap().ends_with("whisper-small"));
    }
}

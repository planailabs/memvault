//! Unified extraction pipeline — one funnel for every extraction op.
//!
//! Text extraction, audio transcription, OCR, and page pre-rendering all
//! flow through this module; execution policy (inline vs background) is a
//! per-op property, not a separate subsystem (the structural companion to
//! `standards/block-ingestion.md`). Inline ops run synchronously on the
//! write path exactly as before; background ops run in tokio tasks after
//! upload (or lazily on first read) and persist their results as
//! annotation blocks — the durable, cluster-synced record. The in-memory
//! job map only dedupes concurrent work on this node.
//!
//! Trigger policy across the cluster: jobs auto-run on the node that
//! ingests the upload. Peers serve synced annotations; a peer only
//! lazily triggers when it holds the file content locally (a job whose
//! content read fails is dropped without caching a failure).

use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock, Weak};

use memvault_extract::{
    ExtractionRegistry, MediaPlugins, PluginOptions, RenderImageFormat, RenderParams,
    ResourceLimits, TextSource,
};

use crate::client::MemvaultClient;
use crate::extraction_config::ExtractionConfig;
use crate::local::LocalClient;
use crate::types::{
    ExtractionInfo, MediaJobStatus, PageDims, PageRenderInfo, PageTextLayer, PageWord,
    TranscriptSegmentInfo,
};

/// Annotation type for page renders (extraction results reuse the
/// existing `"extraction"` annotation type).
pub(crate) const PAGE_RENDER_ANNOTATION: &str = "page_render";

/// Inline words per page are capped at this serialized size; larger text
/// layers are stored as a separate blob block referenced by CID.
const WORDS_INLINE_MAX_BYTES: usize = 32 * 1024;

/// Background extraction operations. Inline text extraction flows through
/// [`ExtractionPipeline::text_registry`] on the existing synchronous path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ExtractOp {
    /// Audio → transcript (extraction annotation + segments).
    Transcribe,
    /// Image → text (extraction annotation).
    Ocr,
    /// PDF/image/office → page images + text layers (page_render annotation).
    RenderPages,
}

/// Broad media class of a file, derived from its MIME type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum MediaClass {
    Audio,
    Image,
    Pdf,
    Office,
    Other,
}

pub(crate) fn classify_mime(mime: &str) -> MediaClass {
    if mime.starts_with("audio/") {
        return MediaClass::Audio;
    }
    if matches!(
        mime,
        "image/png" | "image/jpeg" | "image/webp" | "image/tiff"
    ) {
        return MediaClass::Image;
    }
    if mime == "application/pdf" {
        return MediaClass::Pdf;
    }
    if matches!(
        mime,
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
            | "application/vnd.openxmlformats-officedocument.presentationml.presentation"
            | "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
            | "application/vnd.oasis.opendocument.text"
            | "application/vnd.oasis.opendocument.presentation"
            | "application/vnd.oasis.opendocument.spreadsheet"
            | "application/msword"
    ) {
        return MediaClass::Office;
    }
    MediaClass::Other
}

/// The unified pipeline. One instance per [`LocalClient`], installed via
/// [`LocalClient::install_extraction_pipeline`]; clients without one (CLI
/// one-shots, old tests) degrade to inline-only extraction as before.
pub struct ExtractionPipeline {
    config: ExtractionConfig,
    client: Weak<LocalClient>,
    /// Long-lived text registry — replaces the per-call rebuild in
    /// `safe_extract_text` (a win on every doc save).
    text_registry: OnceLock<Arc<ExtractionRegistry>>,
    /// Long-lived media registry; plugin instances persist so guests can
    /// cache loaded models across calls. Built lazily off the hot path.
    media_registry: OnceLock<Arc<ExtractionRegistry>>,
    /// Ops queued or running on this node, keyed by (manifest CID, op).
    jobs: Mutex<HashMap<(Vec<u8>, ExtractOp), ()>>,
}

impl ExtractionPipeline {
    pub(crate) fn new(config: ExtractionConfig, client: Weak<LocalClient>) -> Self {
        Self {
            config,
            client,
            text_registry: OnceLock::new(),
            media_registry: OnceLock::new(),
            jobs: Mutex::new(HashMap::new()),
        }
    }

    /// The shared text-extraction registry (inline op path).
    pub(crate) fn text_registry(&self) -> &ExtractionRegistry {
        self.text_registry
            .get_or_init(|| Arc::new(ExtractionRegistry::with_defaults()))
    }

    fn media_registry(&self) -> &ExtractionRegistry {
        self.media_registry.get_or_init(|| {
            let cfg = &self.config;
            let limits = |timeout_ms: u64| PluginOptions {
                limits: ResourceLimits {
                    memory_max_pages: Some(cfg.limits.memory_max_pages),
                    // Media inference exceeds any sensible fuel budget;
                    // the wall-clock timeout is the meaningful bound.
                    fuel: None,
                },
                timeout_ms: Some(timeout_ms),
                allowed_paths: Vec::new(),
            };
            let models_mount = cfg
                .models_dir
                .as_ref()
                .map(|dir| (dir.clone(), "/models".to_string()));

            let mut set = MediaPlugins::default();
            if cfg.render_unavailable_reason().is_none() {
                set.pdfrender = Some(limits(cfg.limits.pdfrender_timeout_ms));
            }
            if cfg.ocr_unavailable_reason().is_none() {
                let mut opts = limits(cfg.limits.ocr_timeout_ms);
                opts.allowed_paths.extend(models_mount.clone());
                set.ocr = Some(opts);
            }
            if cfg.whisper_unavailable_reason().is_none() {
                let mut opts = limits(cfg.limits.audio_timeout_ms);
                opts.allowed_paths.extend(models_mount.clone());
                set.audio = Some(opts);
            }
            Arc::new(ExtractionRegistry::with_media_plugins(&set))
        })
    }

    /// Why `op` cannot run on this node, or `None` when it can.
    pub(crate) fn unavailable_reason(&self, op: ExtractOp, class: MediaClass) -> Option<String> {
        match op {
            ExtractOp::Transcribe => self.config.whisper_unavailable_reason(),
            ExtractOp::Ocr => self.config.ocr_unavailable_reason(),
            ExtractOp::RenderPages => match class {
                MediaClass::Pdf => self.config.render_unavailable_reason(),
                // Image page renders only carry value through their OCR
                // text layer; without models there is nothing to add over
                // the raw image itself.
                MediaClass::Image => self
                    .config
                    .render_unavailable_reason()
                    .or_else(|| self.config.ocr_unavailable_reason()),
                MediaClass::Office => self
                    .config
                    .render_unavailable_reason()
                    .or_else(|| office_unavailable_reason(&self.config)),
                _ => Some(format!("page rendering unsupported for this type")),
            },
        }
    }

    /// Background ops applicable to a MIME class (availability not yet
    /// considered).
    fn ops_for_class(class: MediaClass) -> &'static [ExtractOp] {
        match class {
            MediaClass::Audio => &[ExtractOp::Transcribe],
            MediaClass::Image => &[ExtractOp::Ocr, ExtractOp::RenderPages],
            MediaClass::Pdf | MediaClass::Office => &[ExtractOp::RenderPages],
            MediaClass::Other => &[],
        }
    }

    /// Upload-path trigger: queue every applicable, available background
    /// op. Inline text extraction has already run by the time this is
    /// called.
    pub(crate) fn on_ingest(self: &Arc<Self>, manifest_cid: &[u8], mime: &str) {
        let class = classify_mime(mime);
        for &op in Self::ops_for_class(class) {
            if self.unavailable_reason(op, class).is_none() {
                self.ensure_job(op, manifest_cid, mime);
            }
        }
    }

    /// Queue `op` for the file unless it is already queued or running on
    /// this node. The annotation cache is re-checked inside the job right
    /// before work starts (cluster sync may have delivered a result in
    /// the meantime).
    pub(crate) fn ensure_job(self: &Arc<Self>, op: ExtractOp, manifest_cid: &[u8], mime: &str) {
        {
            let mut jobs = self.jobs.lock().unwrap_or_else(|p| p.into_inner());
            if jobs.contains_key(&(manifest_cid.to_vec(), op)) {
                return;
            }
            jobs.insert((manifest_cid.to_vec(), op), ());
        }

        let pipeline = Arc::clone(self);
        let cid = manifest_cid.to_vec();
        let mime = mime.to_string();
        tokio::spawn(async move {
            pipeline.run_job(op, &cid, &mime).await;
            pipeline
                .jobs
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .remove(&(cid, op));
        });
    }

    async fn run_job(self: &Arc<Self>, op: ExtractOp, manifest_cid: &[u8], mime: &str) {
        let Some(client) = self.client.upgrade() else {
            return;
        };

        // Re-check the durable cache: a peer's result may have synced in
        // since this job was queued.
        match op {
            ExtractOp::RenderPages => {
                if client.load_page_render_annotation(manifest_cid).is_some() {
                    return;
                }
            }
            ExtractOp::Transcribe | ExtractOp::Ocr => {
                if client.has_extraction_annotation(manifest_cid) {
                    return;
                }
            }
        }

        // Content not fully present locally (lazy attachment on a peer):
        // drop the job without caching a failure — sync will deliver the
        // origin node's result, or a later read retries once content lands.
        let data = match client.read_file(manifest_cid).await {
            Ok(data) => data,
            Err(e) => {
                tracing::debug!(
                    cid = %hex::encode(manifest_cid),
                    error = %e,
                    "extraction job skipped: content not readable locally"
                );
                return;
            }
        };

        match op {
            ExtractOp::RenderPages => self.run_render_job(&client, manifest_cid, mime, data).await,
            ExtractOp::Transcribe => {
                self.run_media_extract_job(&client, manifest_cid, mime, data, "whisper")
                    .await
            }
            ExtractOp::Ocr => {
                self.run_media_extract_job(&client, manifest_cid, mime, data, "ocr")
                    .await
            }
        }
    }

    /// Transcription and OCR both produce a standard `"extraction"`
    /// annotation (so search indexing and `read_extracted_text` work
    /// unchanged), plus a `media` extra carrying segments/metadata.
    async fn run_media_extract_job(
        self: &Arc<Self>,
        client: &Arc<LocalClient>,
        manifest_cid: &[u8],
        mime: &str,
        data: Vec<u8>,
        role: &str,
    ) {
        let pipeline = Arc::clone(self);
        let mime_owned = mime.to_string();
        let role_owned = role.to_string();
        let result = tokio::task::spawn_blocking(move || {
            let registry = pipeline.media_registry();
            let mut hints = memvault_extract::ExtractionHints::default();
            if let Some(paths) = pipeline.guest_model_paths() {
                hints.model_paths = paths;
            }
            if role_owned == "whisper" {
                hints.language = Some(pipeline.config.whisper.language.clone());
            }
            registry.extract(&data, &mime_owned, &hints)
        })
        .await;

        let result = match result {
            Ok(r) => r,
            Err(join_err) => {
                tracing::warn!(error = %join_err, "media extraction task panicked");
                client.store_media_extraction_failure(manifest_cid, "extractor panicked");
                return;
            }
        };

        match result {
            Ok(extracted) => {
                client
                    .store_media_extraction_success(manifest_cid, mime, &extracted)
                    .await;
            }
            Err(e) => {
                tracing::warn!(mime, error = %e, "media extraction failed");
                client.store_media_extraction_failure(manifest_cid, &e.to_string());
            }
        }
    }

    /// Guest-visible model paths (host models dir is mounted at /models).
    fn guest_model_paths(&self) -> Option<std::collections::BTreeMap<String, String>> {
        let models_dir = self.config.models_dir.as_ref()?;
        let mut map = std::collections::BTreeMap::new();
        if let Some(dir) = self.config.whisper_model_dir() {
            if let Ok(rel) = dir.strip_prefix(models_dir) {
                map.insert("whisper".to_string(), format!("/models/{}", rel.display()));
            }
        }
        if let Some((det, rec)) = self.config.ocr_model_paths() {
            if let Ok(rel) = det.strip_prefix(models_dir) {
                map.insert(
                    "ocr-detection".to_string(),
                    format!("/models/{}", rel.display()),
                );
            }
            if let Ok(rel) = rec.strip_prefix(models_dir) {
                map.insert(
                    "ocr-recognition".to_string(),
                    format!("/models/{}", rel.display()),
                );
            }
        }
        Some(map)
    }

    /// Render every page (batched), store page images as chunked blocks,
    /// and persist one `page_render` annotation. Failures (other than
    /// locally-missing content, handled by the caller) are cached in the
    /// annotation so the cluster converges on the same state.
    async fn run_render_job(
        self: &Arc<Self>,
        client: &Arc<LocalClient>,
        manifest_cid: &[u8],
        mime: &str,
        data: Vec<u8>,
    ) {
        let class = classify_mime(mime);

        // Office docs convert to PDF first (host-side LibreOffice), then
        // reuse the PDF render path.
        let (render_data, render_mime, source_pdf_root) = match class {
            MediaClass::Office => {
                match crate::office_convert::convert_office_to_pdf(&self.config, &data, mime).await
                {
                    Ok(pdf) => {
                        let root = client.store_blob(&pdf);
                        match root {
                            Ok(root) => (pdf, "application/pdf".to_string(), Some(root)),
                            Err(e) => {
                                client.store_page_render_failure(
                                    manifest_cid,
                                    &self.config,
                                    &format!("storing converted pdf failed: {e}"),
                                );
                                return;
                            }
                        }
                    }
                    Err(e) => {
                        client.store_page_render_failure(manifest_cid, &self.config, &e);
                        return;
                    }
                }
            }
            _ => (data, mime.to_string(), None),
        };

        let cfg = &self.config.render;
        let image_format = match cfg.image_format.as_str() {
            "webp" => RenderImageFormat::Webp,
            _ => RenderImageFormat::Png,
        };

        let mut pages_json: Vec<serde_json::Value> = Vec::new();
        let mut total_pages = 0u32;
        let mut page_start = 0u32;
        let mut error: Option<String> = None;
        let mut ocr_used = false;
        let mut page_texts: Vec<String> = Vec::new();

        loop {
            let remaining = cfg.max_pages.saturating_sub(page_start);
            if remaining == 0 {
                break;
            }
            let params = RenderParams {
                dpi: cfg.dpi,
                page_start,
                page_count: cfg.page_batch.min(remaining),
                image_format,
                max_edge_px: Some(8192),
                model_paths: self.guest_model_paths().unwrap_or_default(),
            };

            let pipeline = Arc::clone(self);
            let batch_data = render_data.clone();
            let batch_mime = render_mime.clone();
            let ocr_fallback =
                class != MediaClass::Image && self.config.ocr_unavailable_reason().is_none();
            let batch = tokio::task::spawn_blocking(move || {
                let registry = pipeline.media_registry();
                let mut batch = registry.render_pages(&batch_data, &batch_mime, &params)?;
                // Scanned-page fallback: pages without embedded text get an
                // OCR text layer from their own rendered image.
                if ocr_fallback {
                    for page in &mut batch.pages {
                        if page.text_source != TextSource::None || !registry.can_render("image/png")
                        {
                            continue;
                        }
                        let ocr_params = RenderParams {
                            dpi: params.dpi,
                            page_start: 0,
                            page_count: 1,
                            image_format: params.image_format,
                            max_edge_px: None,
                            model_paths: params.model_paths.clone(),
                        };
                        match registry.render_pages(&page.image, "image/png", &ocr_params) {
                            Ok(ocr) => {
                                if let Some(ocr_page) = ocr.pages.into_iter().next() {
                                    if !ocr_page.words.is_empty() {
                                        page.words = ocr_page.words;
                                        page.text_source = TextSource::Ocr;
                                    }
                                }
                            }
                            Err(e) => {
                                batch.warnings.push(format!(
                                    "page {} ocr fallback failed: {e}",
                                    page.page_no
                                ));
                            }
                        }
                    }
                }
                Ok::<_, memvault_extract::ExtractError>(batch)
            })
            .await;

            let batch = match batch {
                Ok(Ok(batch)) => batch,
                Ok(Err(e)) => {
                    error = Some(e.to_string());
                    break;
                }
                Err(join_err) => {
                    error = Some(format!("render task panicked: {join_err}"));
                    break;
                }
            };

            total_pages = batch.total_pages;
            for warning in &batch.warnings {
                tracing::debug!(cid = %hex::encode(manifest_cid), warning, "page render warning");
            }

            let batch_len = batch.pages.len() as u32;
            for page in batch.pages {
                if page.text_source == TextSource::Ocr {
                    ocr_used = true;
                }
                page_texts.push(
                    page.words
                        .iter()
                        .map(|w| w.text.as_str())
                        .collect::<Vec<_>>()
                        .join(" "),
                );
                match client.store_rendered_page(&page, cfg.dpi, image_format) {
                    Ok(json) => pages_json.push(json),
                    Err(e) => {
                        error = Some(format!("storing page {} failed: {e}", page.page_no));
                        break;
                    }
                }
            }
            if error.is_some() {
                break;
            }

            page_start += cfg.page_batch.min(remaining).max(1);
            if page_start >= total_pages.min(cfg.max_pages) || batch_len == 0 {
                break;
            }
        }

        if let Some(error) = error {
            // Pages already stored stay referenced in the failure record so
            // sync keeps them alive for debugging/retry; status is failed.
            client.store_page_render_annotation_record(
                manifest_cid,
                &self.config,
                "failed",
                Some(&error),
                total_pages,
                source_pdf_root.as_deref(),
                pages_json,
            );
            return;
        }

        client.store_page_render_annotation_record(
            manifest_cid,
            &self.config,
            "ok",
            None,
            total_pages,
            source_pdf_root.as_deref(),
            pages_json,
        );

        // Scanned-document upgrade: when OCR supplied the text layer and
        // the fast text extractor found (almost) nothing embedded, promote
        // the OCR text into the standard extraction annotation so search
        // and read_extracted_text see it.
        if ocr_used {
            let existing_len = client
                .load_file_annotation(manifest_cid, "extraction")
                .and_then(|d| {
                    d.get("extracted_text_inline")
                        .and_then(|v| v.as_str())
                        .map(|s| s.trim().len())
                })
                .unwrap_or(0);
            if existing_len < 64 {
                let mut text = String::new();
                let mut page_breaks = Vec::new();
                for (i, page_text) in page_texts.iter().enumerate() {
                    if i > 0 {
                        page_breaks.push(text.len() as u32);
                    }
                    text.push_str(page_text);
                    text.push('\n');
                }
                if !text.trim().is_empty() {
                    let extracted = memvault_extract::ExtractedText {
                        extractor: "memvault-ocr".to_string(),
                        extractor_version: env!("CARGO_PKG_VERSION").to_string(),
                        text,
                        page_breaks,
                        warnings: vec![],
                        links: vec![],
                        segments: vec![],
                    };
                    client
                        .store_media_extraction_success(manifest_cid, mime, &extracted)
                        .await;
                }
            }
        }
    }
}

/// Why office→PDF conversion is unavailable, or `None` when it can run.
pub(crate) fn office_unavailable_reason(config: &ExtractionConfig) -> Option<String> {
    crate::office_convert::detect_soffice(config)
        .is_none()
        .then(|| "office conversion disabled: libreoffice (soffice) not found".to_string())
}

// ─── Annotation projection helpers ─────────────────────────────────────────────

/// Project a cached `page_render` annotation `data` object plus job state
/// into the wire `PageRenderInfo` (dims only).
pub(crate) fn project_page_render(data: &serde_json::Value) -> PageRenderInfo {
    let status = match data.get("status").and_then(|v| v.as_str()) {
        Some("ok") => MediaJobStatus::Done,
        _ => MediaJobStatus::Failed,
    };
    let pages = data
        .get("pages")
        .and_then(|v| v.as_array())
        .map(|pages| {
            pages
                .iter()
                .filter_map(|p| {
                    Some(PageDims {
                        page_no: p.get("page_no")?.as_u64()? as u32,
                        width: p.get("width_px")?.as_u64()? as u32,
                        height: p.get("height_px")?.as_u64()? as u32,
                    })
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    PageRenderInfo {
        status,
        page_count: pages.len() as u32,
        pages,
        error: data.get("error").and_then(|v| v.as_str()).map(String::from),
    }
}

/// Parse the inline words array of a page entry into the wire form.
pub(crate) fn parse_words(words: &serde_json::Value) -> Vec<PageWord> {
    words
        .as_array()
        .map(|arr| {
            arr.iter()
                .filter_map(|w| {
                    Some(PageWord {
                        text: w.get("t")?.as_str()?.to_string(),
                        x: w.get("x")?.as_f64()? as f32,
                        y: w.get("y")?.as_f64()? as f32,
                        w: w.get("w")?.as_f64()? as f32,
                        h: w.get("h")?.as_f64()? as f32,
                    })
                })
                .collect()
        })
        .unwrap_or_default()
}

/// Build the text layer for one page entry of a `page_render` annotation.
/// `read_blob` resolves a `words_root` CID to the serialized words JSON.
pub(crate) fn page_text_layer(
    page: &serde_json::Value,
    read_blob: impl Fn(&[u8]) -> Option<Vec<u8>>,
) -> Option<PageTextLayer> {
    let page_no = page.get("page_no")?.as_u64()? as u32;
    let width = page.get("width_px")?.as_u64()? as u32;
    let height = page.get("height_px")?.as_u64()? as u32;

    let words = if let Some(inline) = page.get("words_inline").filter(|v| !v.is_null()) {
        parse_words(inline)
    } else if let Some(root) = page
        .get("words_root")
        .filter(|v| !v.is_null())
        .and_then(|v| serde_json::from_value::<Vec<u8>>(v.clone()).ok())
    {
        let bytes = read_blob(&root)?;
        let value: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
        parse_words(&value)
    } else {
        Vec::new()
    };

    Some(PageTextLayer {
        page_no,
        width,
        height,
        words,
    })
}

/// Project a cached `"extraction"` annotation `data` object into the wire
/// `ExtractionInfo`.
pub(crate) fn project_extraction(data: &serde_json::Value) -> ExtractionInfo {
    let error = data
        .get("extraction_error")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .map(String::from);
    let text = data
        .get("extracted_text_inline")
        .and_then(|v| v.as_str())
        .map(String::from);
    let segments = data
        .get("media")
        .and_then(|m| m.get("segments"))
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|s| {
                    Some(TranscriptSegmentInfo {
                        start_ms: s.get("start_ms")?.as_u64()?,
                        end_ms: s.get("end_ms")?.as_u64()?,
                        text: s.get("text")?.as_str()?.to_string(),
                    })
                })
                .collect::<Vec<_>>()
        })
        .filter(|v: &Vec<TranscriptSegmentInfo>| !v.is_empty());
    ExtractionInfo {
        status: if error.is_some() {
            MediaJobStatus::Failed
        } else {
            MediaJobStatus::Done
        },
        text,
        segments,
        error,
        extractor: data
            .get("extractor")
            .and_then(|v| v.as_str())
            .map(String::from),
    }
}

/// Serialize ABI word boxes into the compact annotation form, splitting
/// into (inline value, overflow blob bytes) per the inline size cap.
pub(crate) fn words_to_json(
    words: &[memvault_extract::WordBox],
) -> (Option<serde_json::Value>, Option<Vec<u8>>) {
    let arr: Vec<serde_json::Value> = words
        .iter()
        .map(|w| {
            serde_json::json!({
                "t": w.text,
                "x": w.x,
                "y": w.y,
                "w": w.w,
                "h": w.h,
            })
        })
        .collect();
    let value = serde_json::Value::Array(arr);
    let serialized = serde_json::to_vec(&value).unwrap_or_default();
    if serialized.len() <= WORDS_INLINE_MAX_BYTES {
        (Some(value), None)
    } else {
        (None, Some(serialized))
    }
}

/// Map a `TextSource` into its annotation string form.
pub(crate) fn text_source_str(source: TextSource) -> &'static str {
    match source {
        TextSource::Embedded => "embedded",
        TextSource::Ocr => "ocr",
        TextSource::None => "none",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_known_mimes() {
        assert_eq!(classify_mime("audio/mpeg"), MediaClass::Audio);
        assert_eq!(classify_mime("image/png"), MediaClass::Image);
        assert_eq!(classify_mime("application/pdf"), MediaClass::Pdf);
        assert_eq!(
            classify_mime(
                "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
            ),
            MediaClass::Office
        );
        assert_eq!(classify_mime("text/plain"), MediaClass::Other);
    }

    #[test]
    fn project_page_render_dims_only() {
        let data = serde_json::json!({
            "status": "ok",
            "error": null,
            "pages": [
                { "page_no": 1, "width_px": 1224, "height_px": 1584,
                  "image_root": [1,2,3], "words_inline": [{"t":"x","x":1.0,"y":2.0,"w":3.0,"h":4.0}] }
            ]
        });
        let info = project_page_render(&data);
        assert_eq!(info.status, MediaJobStatus::Done);
        assert_eq!(info.page_count, 1);
        assert_eq!(info.pages[0].width, 1224);
    }

    #[test]
    fn project_extraction_with_segments() {
        let data = serde_json::json!({
            "extracted_text_inline": "hello world",
            "extraction_error": null,
            "extractor": "memvault-whisper@0.1.0",
            "media": { "kind": "transcript", "segments": [
                { "start_ms": 0, "end_ms": 1500, "text": "hello world" }
            ]}
        });
        let info = project_extraction(&data);
        assert_eq!(info.status, MediaJobStatus::Done);
        assert_eq!(info.segments.unwrap()[0].end_ms, 1500);
    }

    #[test]
    fn words_overflow_to_blob() {
        let many: Vec<memvault_extract::WordBox> = (0..4000)
            .map(|i| memvault_extract::WordBox {
                text: format!("word-{i}-padding-padding"),
                x: i as f32,
                y: 0.0,
                w: 10.0,
                h: 12.0,
            })
            .collect();
        let (inline, blob) = words_to_json(&many);
        assert!(inline.is_none());
        let blob = blob.unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&blob).unwrap();
        assert_eq!(parse_words(&parsed).len(), 4000);
    }
}

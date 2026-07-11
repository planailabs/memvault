//! Office document → PDF conversion via headless LibreOffice.
//!
//! The only non-WASM step in the extraction pipeline: there is no viable
//! pure-Rust (let alone wasm-sandboxable) renderer for the OOXML/ODF
//! family, so office docs are converted to PDF host-side and then flow
//! through the sandboxed PDF render path. Optional: when LibreOffice is
//! absent the capability reports `unavailable` and nothing else changes.

use std::path::PathBuf;
use std::process::Stdio;

use crate::extraction_config::ExtractionConfig;

const CONVERT_TIMEOUT_SECS: u64 = 120;

/// Resolve the LibreOffice binary: explicit config path first, then
/// `soffice` on PATH. `None` = office conversion unavailable.
pub(crate) fn detect_soffice(config: &ExtractionConfig) -> Option<PathBuf> {
    if let Some(path) = &config.libreoffice_path {
        return path.is_file().then(|| path.clone());
    }
    let path_var = std::env::var_os("PATH")?;
    std::env::split_paths(&path_var)
        .map(|dir| dir.join("soffice"))
        .find(|candidate| candidate.is_file())
}

fn extension_for_mime(mime: &str) -> &'static str {
    match mime {
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document" => "docx",
        "application/vnd.openxmlformats-officedocument.presentationml.presentation" => "pptx",
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet" => "xlsx",
        "application/vnd.oasis.opendocument.text" => "odt",
        "application/vnd.oasis.opendocument.presentation" => "odp",
        "application/vnd.oasis.opendocument.spreadsheet" => "ods",
        "application/msword" => "doc",
        _ => "bin",
    }
}

/// Convert an office document to PDF in an isolated temp profile.
/// Errors are strings destined for the failure annotation.
pub(crate) async fn convert_office_to_pdf(
    config: &ExtractionConfig,
    data: &[u8],
    mime: &str,
) -> Result<Vec<u8>, String> {
    let soffice =
        detect_soffice(config).ok_or_else(|| "libreoffice (soffice) not found".to_string())?;

    let dir = tempfile::tempdir().map_err(|e| format!("tempdir: {e}"))?;
    let ext = extension_for_mime(mime);
    let input_path = dir.path().join(format!("input.{ext}"));
    std::fs::write(&input_path, data).map_err(|e| format!("write temp input: {e}"))?;

    // A dedicated UserInstallation avoids lock contention with any other
    // LibreOffice instance (including concurrent conversions).
    let profile = format!(
        "-env:UserInstallation=file://{}/lo-profile",
        dir.path().display()
    );

    let child = tokio::process::Command::new(&soffice)
        .arg(profile)
        .arg("--headless")
        .arg("--convert-to")
        .arg("pdf")
        .arg("--outdir")
        .arg(dir.path())
        .arg(&input_path)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .map_err(|e| format!("spawn {}: {e}", soffice.display()))?;

    let output = tokio::time::timeout(
        std::time::Duration::from_secs(CONVERT_TIMEOUT_SECS),
        child.wait_with_output(),
    )
    .await
    .map_err(|_| format!("libreoffice conversion timed out after {CONVERT_TIMEOUT_SECS}s"))?
    .map_err(|e| format!("libreoffice: {e}"))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!(
            "libreoffice conversion failed ({}): {}",
            output.status,
            stderr.trim()
        ));
    }

    let pdf_path = dir.path().join("input.pdf");
    std::fs::read(&pdf_path).map_err(|e| format!("converted pdf missing: {e}"))
}

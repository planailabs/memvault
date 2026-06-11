use extism_pdk::*;
use memvault_extract_abi::{
    ExtractionHints, ExtractionResponse, ExtractedText, ExtractorCapability, MatchRule,
    PluginCapabilities,
};

mod docx;
mod html;
mod markdown;
mod pdf;
mod plain_text;

/// Return plugin capabilities as CBOR.
#[plugin_fn]
pub fn capabilities(_input: Vec<u8>) -> FnResult<Vec<u8>> {
    let caps = PluginCapabilities {
        id: "memvault-builtin".to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        capabilities: vec![
            // Plain text
            ExtractorCapability::extract(MatchRule::Mime("text/plain".to_string()), 0),
            ExtractorCapability::extract(MatchRule::Mime("text/csv".to_string()), 0),
            ExtractorCapability::extract(MatchRule::Mime("application/json".to_string()), 0),
            ExtractorCapability::extract(MatchRule::Extension("txt".to_string()), 0),
            ExtractorCapability::extract(MatchRule::Extension("csv".to_string()), 0),
            ExtractorCapability::extract(MatchRule::Extension("json".to_string()), 0),
            // Markdown
            ExtractorCapability::extract(MatchRule::Mime("text/markdown".to_string()), 0),
            ExtractorCapability::extract(MatchRule::Mime("text/x-markdown".to_string()), 0),
            ExtractorCapability::extract(MatchRule::Extension("md".to_string()), 0),
            ExtractorCapability::extract(MatchRule::Extension("markdown".to_string()), 0),
            // HTML
            ExtractorCapability::extract(MatchRule::Mime("text/html".to_string()), 0),
            ExtractorCapability::extract(MatchRule::Mime("application/xhtml+xml".to_string()), 0),
            ExtractorCapability::extract(MatchRule::Extension("html".to_string()), 0),
            ExtractorCapability::extract(MatchRule::Extension("htm".to_string()), 0),
            // PDF
            ExtractorCapability::extract(MatchRule::Mime("application/pdf".to_string()), 0),
            ExtractorCapability::extract(MatchRule::Extension("pdf".to_string()), 0),
            // DOCX
            ExtractorCapability::extract(MatchRule::Mime(
                    "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
                        .to_string(),
                ), 0),
            ExtractorCapability::extract(MatchRule::Extension("docx".to_string()), 0),
        ],
    };
    Ok(memvault_extract_abi::encode_capabilities(&caps))
}

/// Extract text from a file. Input is the binary envelope format.
#[plugin_fn]
pub fn extract(input: Vec<u8>) -> FnResult<Vec<u8>> {
    let (header, content) = match memvault_extract_abi::decode_envelope(&input) {
        Ok(v) => v,
        Err(e) => {
            let resp = ExtractionResponse::Err {
                code: "envelope_error".to_string(),
                message: format!("{e}"),
            };
            return Ok(memvault_extract_abi::encode_response(&resp));
        }
    };

    let result = dispatch(&header.mime, header.extension.as_deref(), content, &header.hints);

    let resp = match result {
        Ok(text) => ExtractionResponse::Ok(text),
        Err(e) => ExtractionResponse::Err {
            code: "extraction_failed".to_string(),
            message: e,
        },
    };

    Ok(memvault_extract_abi::encode_response(&resp))
}

/// Dispatch to the correct extractor based on MIME type or extension.
fn dispatch(
    mime: &str,
    extension: Option<&str>,
    content: &[u8],
    hints: &ExtractionHints,
) -> Result<ExtractedText, String> {
    // Try MIME-based dispatch first
    if matches!(mime, "text/plain" | "text/csv" | "application/json") || mime.starts_with("text/x-")
    {
        return plain_text::extract(content, hints);
    }
    if matches!(mime, "text/markdown" | "text/x-markdown") {
        return markdown::extract(content, hints);
    }
    if matches!(mime, "text/html" | "application/xhtml+xml") {
        return html::extract(content, hints);
    }
    if mime == "application/pdf" {
        return pdf::extract(content, hints);
    }
    if mime
        == "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
    {
        return docx::extract(content, hints);
    }

    // Fall back to extension-based dispatch
    if let Some(ext) = extension {
        match ext {
            "txt" | "csv" | "json" | "log" => return plain_text::extract(content, hints),
            "md" | "markdown" => return markdown::extract(content, hints),
            "html" | "htm" | "xhtml" => return html::extract(content, hints),
            "pdf" => return pdf::extract(content, hints),
            "docx" => return docx::extract(content, hints),
            _ => {}
        }
    }

    Err(format!("unsupported: mime={mime}, ext={extension:?}"))
}

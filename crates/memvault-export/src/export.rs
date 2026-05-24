//! Core export execution — orchestrates plan + sink.

use std::path::PathBuf;

use anyhow::Result;
use memvault_api::MemvaultClient;
use memvault_core::{DocId, EntityId};
use tracing::info;

use crate::plan;
use crate::sink::ExportSink;
use crate::title;
use crate::vfs_tree;
use crate::ExportOptions;

/// Statistics from an export run.
#[derive(Debug, Default)]
pub struct ExportStats {
    pub documents: usize,
    pub files: usize,
    pub entities: usize,
    pub history_versions: usize,
}

/// Run a full vault export.
pub async fn run_export(
    client: &dyn MemvaultClient,
    mut sink: Box<dyn ExportSink>,
    opts: ExportOptions,
) -> Result<ExportStats> {
    let plan = plan::build_plan(client, &opts).await?;
    let mut stats = ExportStats::default();

    // Export documents
    for entry in &plan.documents {
        export_document(client, &mut *sink, &entry.doc_id, opts.history, &mut stats).await?;
    }

    // Export files
    for entry in &plan.files {
        export_file(client, &mut *sink, &entry.manifest_cid, entry.filename.as_deref(), &mut stats).await?;
    }

    // Export entities
    for entry in &plan.entities {
        export_entity(client, &mut *sink, &entry.entity_id, &mut stats).await?;
    }

    // Export VFS symlinks
    if opts.include_vfs {
        let symlinks = vfs_tree::build_vfs_symlinks(client).await?;
        for symlink in symlinks {
            let link_path = PathBuf::from("vfs").join(&symlink.link_path);
            sink.write_symlink(&link_path, &symlink.target)?;
        }
    }

    sink.finish()?;
    info!(
        "export complete: {} docs, {} files, {} entities, {} history versions",
        stats.documents, stats.files, stats.entities, stats.history_versions
    );
    Ok(stats)
}

/// Export a single document to the sink.
async fn export_document(
    client: &dyn MemvaultClient,
    sink: &mut dyn ExportSink,
    doc_id: &DocId,
    include_history: bool,
    stats: &mut ExportStats,
) -> Result<()> {
    let doc = match client.get_doc(doc_id).await? {
        Some(d) => d,
        None => return Ok(()), // retracted or missing
    };

    let filename = title::doc_filename(&doc);
    let content = render_doc_markdown(&doc);
    sink.write_file(&PathBuf::from("documents").join(&filename), content.as_bytes())?;
    stats.documents += 1;

    if include_history {
        export_doc_history(client, sink, doc_id, stats).await?;
    }

    Ok(())
}

/// Export historical versions of a document.
async fn export_doc_history(
    client: &dyn MemvaultClient,
    sink: &mut dyn ExportSink,
    doc_id: &DocId,
    stats: &mut ExportStats,
) -> Result<()> {
    let history = client.history_of(doc_id).await?;
    if history.is_empty() {
        return Ok(());
    }

    let doc_hex = hex::encode(doc_id.0);
    let history_dir = PathBuf::from("documents").join(&doc_hex);

    for record in &history {
        let timestamp = format_ns_timestamp(record.wall_ns);
        let path = history_dir.join(format!("{timestamp}.md"));

        // Each audit record has a CID — we write a summary of the operation
        let content = format!(
            "---\ntimestamp: {timestamp}\nop: {:?}\nauthor: {}\n---\n",
            record.op_kind,
            hex::encode(&record.author),
        );
        sink.write_file(&path, content.as_bytes())?;
        stats.history_versions += 1;
    }

    Ok(())
}

/// Export a single file attachment.
async fn export_file(
    client: &dyn MemvaultClient,
    sink: &mut dyn ExportSink,
    manifest_cid: &[u8],
    filename_hint: Option<&str>,
    stats: &mut ExportStats,
) -> Result<()> {
    // Try to read the manifest to get filename/mime_type
    let (filename, _mime) = match client.get_file_manifest(manifest_cid).await? {
        Some(manifest_json) => {
            let manifest: serde_json::Value = serde_json::from_slice(&manifest_json)?;
            let fname = manifest["filename"]
                .as_str()
                .map(String::from)
                .or_else(|| filename_hint.map(String::from));
            let mime = manifest["mime_type"]
                .as_str()
                .unwrap_or("application/octet-stream")
                .to_string();
            (fname, mime)
        }
        None => (filename_hint.map(String::from), "application/octet-stream".to_string()),
    };

    let cid_hex = hex::encode(manifest_cid);
    let ext = filename
        .as_deref()
        .and_then(|f| std::path::Path::new(f).extension())
        .and_then(|e| e.to_str())
        .unwrap_or("bin");
    let out_filename = format!("{cid_hex}.{ext}");

    let data = client.read_file(manifest_cid).await?;
    sink.write_file(&PathBuf::from("files").join(&out_filename), &data)?;
    stats.files += 1;

    Ok(())
}

/// Export a single graph entity as JSON.
async fn export_entity(
    client: &dyn MemvaultClient,
    sink: &mut dyn ExportSink,
    entity_id: &EntityId,
    stats: &mut ExportStats,
) -> Result<()> {
    let entity = match client.get_entity(entity_id).await? {
        Some(e) => e,
        None => return Ok(()),
    };

    let entity_hex = hex::encode(entity_id.0);
    let json = serde_json::to_string_pretty(&serde_json::json!({
        "id": entity_hex,
        "kind": entity.kind,
        "props": entity.props,
        "edges": entity.edges_out.iter().map(|e| serde_json::json!({
            "id": hex::encode(e.id.0),
            "relation": e.relation,
            "target": format_node_ref(&e.target),
            "weight": e.weight,
            "props": e.props,
        })).collect::<Vec<_>>(),
    }))?;

    sink.write_file(
        &PathBuf::from("graph").join(format!("{entity_hex}.json")),
        json.as_bytes(),
    )?;
    stats.entities += 1;

    Ok(())
}

// -- Public helpers for MCP single-item exports --

/// Export a single document, returning (relative_path, content) pairs.
/// Includes history entries if requested.
pub async fn export_single_doc(
    client: &dyn MemvaultClient,
    doc_id: &DocId,
    include_history: bool,
) -> Result<Vec<(String, Vec<u8>)>> {
    let mut results = Vec::new();

    let doc = client
        .get_doc(doc_id)
        .await?
        .ok_or_else(|| anyhow::anyhow!("document not found"))?;

    let filename = title::doc_filename(&doc);
    let content = render_doc_markdown(&doc);
    results.push((format!("documents/{filename}"), content.into_bytes()));

    if include_history {
        let history = client.history_of(doc_id).await?;
        let doc_hex = hex::encode(doc_id.0);
        for record in &history {
            let timestamp = format_ns_timestamp(record.wall_ns);
            let content = format!(
                "---\ntimestamp: {timestamp}\nop: {:?}\nauthor: {}\n---\n",
                record.op_kind,
                hex::encode(&record.author),
            );
            results.push((
                format!("documents/{doc_hex}/{timestamp}.md"),
                content.into_bytes(),
            ));
        }
    }

    Ok(results)
}

/// Export a single entity as JSON, returning (relative_path, content).
pub async fn export_single_entity(
    client: &dyn MemvaultClient,
    entity_id: &EntityId,
) -> Result<(String, Vec<u8>)> {
    let entity = client
        .get_entity(entity_id)
        .await?
        .ok_or_else(|| anyhow::anyhow!("entity not found"))?;

    let entity_hex = hex::encode(entity_id.0);
    let json = serde_json::to_string_pretty(&serde_json::json!({
        "id": entity_hex,
        "kind": entity.kind,
        "props": entity.props,
        "edges": entity.edges_out.iter().map(|e| serde_json::json!({
            "id": hex::encode(e.id.0),
            "relation": e.relation,
            "target": format_node_ref(&e.target),
            "weight": e.weight,
            "props": e.props,
        })).collect::<Vec<_>>(),
    }))?;

    Ok((format!("graph/{entity_hex}.json"), json.into_bytes()))
}

/// Export a single file attachment, returning (relative_path, content).
pub async fn export_single_file(
    client: &dyn MemvaultClient,
    manifest_cid: &[u8],
) -> Result<(String, Vec<u8>)> {
    let (filename, _mime) = match client.get_file_manifest(manifest_cid).await? {
        Some(manifest_json) => {
            let manifest: serde_json::Value = serde_json::from_slice(&manifest_json)?;
            let fname = manifest["filename"].as_str().map(String::from);
            let mime = manifest["mime_type"]
                .as_str()
                .unwrap_or("application/octet-stream")
                .to_string();
            (fname, mime)
        }
        None => (None, "application/octet-stream".to_string()),
    };

    let cid_hex = hex::encode(manifest_cid);
    let ext = filename
        .as_deref()
        .and_then(|f| std::path::Path::new(f).extension())
        .and_then(|e| e.to_str())
        .unwrap_or("bin");
    let out_filename = format!("{cid_hex}.{ext}");

    let data = client.read_file(manifest_cid).await?;
    Ok((format!("files/{out_filename}"), data))
}

// -- Internal helpers --

fn render_doc_markdown(doc: &memvault_doc::Document) -> String {
    let mut out = String::new();
    if !doc.frontmatter.is_empty() {
        out.push_str("---\n");
        // Write frontmatter as YAML-like key: value
        for (key, value) in &doc.frontmatter {
            match value {
                serde_json::Value::String(s) => {
                    out.push_str(&format!("{key}: {s}\n"));
                }
                other => {
                    out.push_str(&format!("{key}: {other}\n"));
                }
            }
        }
        out.push_str("---\n\n");
    }
    out.push_str(&doc.body);
    if !doc.body.ends_with('\n') {
        out.push('\n');
    }
    out
}

fn format_node_ref(node: &memvault_core::NodeRef) -> String {
    match node {
        memvault_core::NodeRef::Entity(id) => format!("entity:{}", hex::encode(id.0)),
        memvault_core::NodeRef::Doc(id) => format!("doc:{}", hex::encode(id.0)),
        memvault_core::NodeRef::Attachment(cid) => format!("file:{}", hex::encode(cid)),
    }
}

fn format_ns_timestamp(ns: u64) -> String {
    let secs = (ns / 1_000_000_000) as i64;
    let nanos = (ns % 1_000_000_000) as u32;
    let dt = chrono::DateTime::from_timestamp(secs, nanos)
        .unwrap_or_else(|| chrono::DateTime::from_timestamp(0, 0).unwrap());
    dt.format("%Y-%m-%dT%H:%M:%S").to_string()
}

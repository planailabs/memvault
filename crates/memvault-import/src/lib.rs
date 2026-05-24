//! Memvault import — import files and documents into a memvault store.

use std::path::{Path, PathBuf};

use anyhow::Result;
use memvault_api::LocalClient;
use memvault_core::Visibility;

/// Import files recursively, optionally placing them in the VFS.
pub async fn import_files(
    client: &LocalClient,
    path: &Path,
    vfs_folder: Option<&str>,
    tags: &[(String, String)],
    visibility: &str,
) -> Result<usize> {
    let mut files: Vec<PathBuf> = Vec::new();
    if path.is_file() {
        files.push(path.to_path_buf());
    } else if path.is_dir() {
        collect_files_recursive(path, &mut files, None)?;
    } else {
        anyhow::bail!("path does not exist: {}", path.display());
    }
    if files.is_empty() {
        println!("No files found at {}", path.display());
        return Ok(0);
    }

    let base_dir = if path.is_dir() { path } else { path.parent().unwrap_or(Path::new(".")) };
    let mut count = 0usize;

    for file_path in &files {
        let data = std::fs::read(file_path)?;
        let filename = file_path.file_name().and_then(|n| n.to_str()).unwrap_or("unnamed");
        let mime = memvault_api::files::detect_mime(file_path);
        let vfs_path = vfs_folder.map(|f| compute_vfs_path(f, base_dir, file_path, path.is_dir()));
        let (_cid, node_id) = memvault_api::files::upload_file(
            client, &data, Some(filename), mime, tags.to_vec(), visibility, vfs_path.as_deref(),
        ).await?;
        println!("  {} -> {node_id}", file_path.display());
        count += 1;
    }
    Ok(count)
}

/// Import text/markdown files as documents, optionally placing them in the VFS.
pub async fn import_docs(
    client: &LocalClient,
    path: &Path,
    vfs_folder: Option<&str>,
    tags: &[(String, String)],
    vis: Visibility,
) -> Result<usize> {
    let doc_extensions = &["md", "txt", "markdown", "text", "rst"];
    let mut files: Vec<PathBuf> = Vec::new();
    if path.is_file() {
        files.push(path.to_path_buf());
    } else if path.is_dir() {
        collect_files_recursive(path, &mut files, Some(doc_extensions))?;
    } else {
        anyhow::bail!("path does not exist: {}", path.display());
    }
    if files.is_empty() {
        println!("No document files found at {}", path.display());
        return Ok(0);
    }

    let base_dir = if path.is_dir() { path } else { path.parent().unwrap_or(Path::new(".")) };
    let mut count = 0usize;

    for file_path in &files {
        let body = std::fs::read_to_string(file_path)?;
        let title = file_path.file_stem().and_then(|s| s.to_str()).map(|s| s.to_string());
        let vfs_path = vfs_folder.map(|f| compute_vfs_path(f, base_dir, file_path, path.is_dir()));
        let result = memvault_api::docs::create_doc(
            client, &body, title.as_deref(), None, tags.to_vec(), vis, vfs_path.as_deref(),
        ).await?;
        println!("  {} -> {}", file_path.display(), result.node_id);
        count += 1;
    }
    Ok(count)
}

/// Compute the VFS path for a file being imported.
pub fn compute_vfs_path(vfs_folder: &str, base_dir: &Path, file_path: &Path, is_dir_import: bool) -> String {
    let folder = vfs_folder.trim_end_matches('/');
    if is_dir_import {
        let rel = file_path.strip_prefix(base_dir).unwrap_or(file_path);
        let rel_str = rel.to_string_lossy();
        format!("{folder}/{rel_str}")
    } else {
        let filename = file_path.file_name().and_then(|n| n.to_str()).unwrap_or("unnamed");
        format!("{folder}/{filename}")
    }
}

/// Collect files recursively, skipping hidden entries.
/// If `extensions` is Some, only includes files with matching extensions.
pub fn collect_files_recursive(dir: &Path, out: &mut Vec<PathBuf>, extensions: Option<&[&str]>) -> Result<()> {
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        if name.starts_with('.') {
            continue;
        }
        if path.is_file() {
            if let Some(exts) = extensions {
                let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
                if !exts.iter().any(|e| e.eq_ignore_ascii_case(ext)) {
                    continue;
                }
            }
            out.push(path);
        } else if path.is_dir() {
            collect_files_recursive(&path, out, extensions)?;
        }
    }
    Ok(())
}

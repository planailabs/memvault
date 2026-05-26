//! VFS tree walker — produces symlink entries for the export.

use std::path::PathBuf;

use crate::title;
use anyhow::Result;
use memvault_api::MemvaultClient;
use memvault_api::vfs::{self, VFS_DIR_KIND};
use memvault_core::NodeRef;

/// A symlink to create in the VFS export tree.
pub struct VfsSymlink {
    /// Relative path under `vfs/` for the symlink.
    pub link_path: PathBuf,
    /// Target relative path (e.g., `../../documents/<name>.md`).
    pub target: PathBuf,
}

/// Walk the VFS tree for the default bucket and produce symlink entries.
pub async fn build_vfs_symlinks(client: &dyn MemvaultClient) -> Result<Vec<VfsSymlink>> {
    let bucket = vfs::default_bucket(client).await;
    let root = match vfs::ensure_root(client, &bucket).await {
        Ok(id) => id,
        Err(_) => return Ok(Vec::new()), // no VFS tree
    };

    let mut symlinks = Vec::new();
    let mut stack: Vec<(NodeRef, PathBuf)> = vec![(NodeRef::Entity(root), PathBuf::new())];

    while let Some((node, prefix)) = stack.pop() {
        let children = vfs::list_children(client, &node).await?;
        for (name, target, _edge_id) in children {
            let child_path = prefix.join(&name);
            match &target {
                NodeRef::Entity(id) => {
                    // Check if it's a directory
                    if let Ok(Some(entity)) = client.get_entity(id).await {
                        if entity.kind == VFS_DIR_KIND {
                            stack.push((target, child_path));
                            continue;
                        }
                    }
                    // Non-directory entity → symlink to graph/
                    let target_path = relative_prefix(&child_path)
                        .join("graph")
                        .join(format!("{}.json", hex::encode(id.0)));
                    symlinks.push(VfsSymlink {
                        link_path: child_path,
                        target: target_path,
                    });
                }
                NodeRef::Doc(doc_id) => {
                    // Resolve the document to get its filename
                    let filename = match client.get_doc(doc_id).await {
                        Ok(Some(doc)) => title::doc_filename(&doc),
                        _ => format!("{}.md", hex::encode(doc_id.0)),
                    };
                    let target_path = relative_prefix(&child_path)
                        .join("documents")
                        .join(&filename);
                    symlinks.push(VfsSymlink {
                        link_path: child_path,
                        target: target_path,
                    });
                }
                NodeRef::Attachment(cid) => {
                    // Use the VFS name's extension, falling back to the manifest
                    let ext = std::path::Path::new(&name)
                        .extension()
                        .and_then(|e| e.to_str())
                        .unwrap_or("bin");
                    let file_name = format!("{}.{}", hex::encode(cid), ext);
                    let target_path = relative_prefix(&child_path).join("files").join(&file_name);
                    symlinks.push(VfsSymlink {
                        link_path: child_path,
                        target: target_path,
                    });
                }
            }
        }
    }

    Ok(symlinks)
}

/// Compute the `../../..` prefix to get from the symlink location back to the export root.
fn relative_prefix(link_path: &PathBuf) -> PathBuf {
    let depth = link_path.components().count();
    let mut prefix = PathBuf::new();
    for _ in 0..depth {
        prefix.push("..");
    }
    prefix
}

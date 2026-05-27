//! VFS tree walker — produces symlink entries for the export.

use std::path::{Path, PathBuf};

use crate::title;
use anyhow::Result;
use memvault_api::MemvaultClient;
use memvault_api::vfs::{self, VfsTreeNode};
use memvault_core::{BucketId, NodeRef};

/// A symlink to create in the VFS export tree.
pub struct VfsSymlink {
    /// Relative path under `vfs/` for the symlink.
    pub link_path: PathBuf,
    /// Target relative path (e.g., `../../documents/<name>.md`).
    pub target: PathBuf,
}

/// Walk the VFS tree for the given bucket and produce symlink entries.
/// Returns an empty list if the bucket has no VFS root yet.
pub async fn build_vfs_symlinks(
    client: &dyn MemvaultClient,
    bucket: &BucketId,
) -> Result<Vec<VfsSymlink>> {
    if vfs::ensure_root(client, bucket).await.is_err() {
        return Ok(Vec::new());
    }
    let tree = vfs::walk_tree(client, bucket, "/", usize::MAX).await?;
    let mut symlinks = Vec::new();
    collect_symlinks(client, &tree, Path::new(""), &mut symlinks).await?;
    Ok(symlinks)
}

fn collect_symlinks<'a>(
    client: &'a dyn MemvaultClient,
    node: &'a VfsTreeNode,
    prefix: &'a Path,
    out: &'a mut Vec<VfsSymlink>,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<()>> + Send + 'a>> {
    Box::pin(async move {
        for child in &node.children {
            let child_path = prefix.join(&child.name);
            match &child.node {
                NodeRef::Entity(id) => {
                    if child.node_type == "dir" {
                        collect_symlinks(client, child, &child_path, out).await?;
                    } else {
                        let target_path = relative_prefix(&child_path)
                            .join("graph")
                            .join(format!("{}.json", hex::encode(id.0)));
                        out.push(VfsSymlink {
                            link_path: child_path,
                            target: target_path,
                        });
                    }
                }
                NodeRef::Doc(doc_id) => {
                    let filename = match client.get_doc(doc_id).await {
                        Ok(Some(doc)) => title::doc_filename(&doc),
                        _ => format!("{}.md", hex::encode(doc_id.0)),
                    };
                    let target_path = relative_prefix(&child_path)
                        .join("documents")
                        .join(&filename);
                    out.push(VfsSymlink {
                        link_path: child_path,
                        target: target_path,
                    });
                }
                NodeRef::Attachment(cid) => {
                    let ext = Path::new(&child.name)
                        .extension()
                        .and_then(|e| e.to_str())
                        .unwrap_or("bin");
                    let file_name = format!("{}.{}", hex::encode(cid), ext);
                    let target_path = relative_prefix(&child_path).join("files").join(&file_name);
                    out.push(VfsSymlink {
                        link_path: child_path,
                        target: target_path,
                    });
                }
            }
        }
        Ok(())
    })
}

/// Compute the `../../..` prefix to get from the symlink location back to the export root.
fn relative_prefix(link_path: &Path) -> PathBuf {
    let depth = link_path.components().count();
    let mut prefix = PathBuf::new();
    for _ in 0..depth {
        prefix.push("..");
    }
    prefix
}

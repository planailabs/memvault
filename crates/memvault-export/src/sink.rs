//! Export sinks — write exported content to filesystem or TAR archive.

use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

/// Trait for writing exported content to a destination.
pub trait ExportSink: Send {
    /// Write a file at the given relative path with the given content.
    fn write_file(&mut self, rel_path: &Path, content: &[u8]) -> Result<()>;
    /// Create a symlink at `link_path` pointing to `target`.
    fn write_symlink(&mut self, link_path: &Path, target: &Path) -> Result<()>;
    /// Finalize the sink (flush tar, etc).
    fn finish(self: Box<Self>) -> Result<()>;
}

/// Writes files to a real directory on the filesystem.
pub struct DirSink {
    root: PathBuf,
}

impl DirSink {
    pub fn new(root: PathBuf) -> Result<Self> {
        std::fs::create_dir_all(&root)
            .with_context(|| format!("creating output directory {}", root.display()))?;
        Ok(Self { root })
    }
}

impl ExportSink for DirSink {
    fn write_file(&mut self, rel_path: &Path, content: &[u8]) -> Result<()> {
        let full = self.root.join(rel_path);
        if let Some(parent) = full.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&full, content)
            .with_context(|| format!("writing {}", full.display()))?;
        Ok(())
    }

    fn write_symlink(&mut self, link_path: &Path, target: &Path) -> Result<()> {
        let full_link = self.root.join(link_path);
        if let Some(parent) = full_link.parent() {
            std::fs::create_dir_all(parent)?;
        }
        // Remove existing symlink if present
        let _ = std::fs::remove_file(&full_link);
        #[cfg(unix)]
        std::os::unix::fs::symlink(target, &full_link)
            .with_context(|| format!("symlink {} -> {}", full_link.display(), target.display()))?;
        #[cfg(not(unix))]
        {
            // On non-unix, write a placeholder file with the target path
            std::fs::write(&full_link, format!("-> {}", target.display()))?;
        }
        Ok(())
    }

    fn finish(self: Box<Self>) -> Result<()> {
        Ok(())
    }
}

/// Writes files into a tar archive.
pub struct TarSink<W: Write + Send> {
    builder: tar::Builder<W>,
}

impl<W: Write + Send> TarSink<W> {
    pub fn new(writer: W) -> Self {
        Self {
            builder: tar::Builder::new(writer),
        }
    }
}

impl<W: Write + Send> ExportSink for TarSink<W> {
    fn write_file(&mut self, rel_path: &Path, content: &[u8]) -> Result<()> {
        let mut header = tar::Header::new_gnu();
        header.set_size(content.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        self.builder
            .append_data(&mut header, rel_path, content)
            .with_context(|| format!("appending {} to tar", rel_path.display()))?;
        Ok(())
    }

    fn write_symlink(&mut self, link_path: &Path, target: &Path) -> Result<()> {
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(tar::EntryType::Symlink);
        header.set_size(0);
        header.set_mode(0o777);
        header.set_cksum();
        self.builder
            .append_link(&mut header, link_path, target)
            .with_context(|| format!("appending symlink {} to tar", link_path.display()))?;
        Ok(())
    }

    fn finish(self: Box<Self>) -> Result<()> {
        self.builder.into_inner()?.flush()?;
        Ok(())
    }
}

/// Create the appropriate sink based on output path and flags.
pub fn create_sink(
    output: &Path,
    force_tar: bool,
    gzip: bool,
) -> Result<Box<dyn ExportSink>> {
    let is_tar = force_tar
        || output.extension().is_some_and(|e| e == "tar")
        || output
            .file_name()
            .and_then(|n| n.to_str())
            .is_some_and(|n| n.ends_with(".tar.gz") || n.ends_with(".tgz"));

    if is_tar {
        let file = std::fs::File::create(output)
            .with_context(|| format!("creating tar file {}", output.display()))?;
        if gzip || output.to_str().is_some_and(|s| s.ends_with(".gz") || s.ends_with(".tgz")) {
            let encoder = flate2::write::GzEncoder::new(file, flate2::Compression::default());
            Ok(Box::new(TarSink::new(encoder)))
        } else {
            Ok(Box::new(TarSink::new(file)))
        }
    } else {
        Ok(Box::new(DirSink::new(output.to_path_buf())?))
    }
}

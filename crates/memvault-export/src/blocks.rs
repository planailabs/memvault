//! Export raw blocks from the store, one file per CID.

use std::path::Path;

use anyhow::{Context, Result};
use memvault_store::MemvaultStore;

use crate::sink::ExportSink;

/// Export every block in the store to the sink, using the hex-encoded CID
/// as the filename.  Returns the number of blocks written.
pub fn export_blocks(store: &MemvaultStore, sink: &mut dyn ExportSink) -> Result<usize> {
    let blocks = store
        .iter_blocks()
        .context("iterating blocks")?;

    let mut count = 0usize;
    for (cid, data) in &blocks {
        let name = hex::encode(cid);
        sink.write_file(Path::new(&name), data)
            .with_context(|| format!("writing block {name}"))?;
        count += 1;
    }

    Ok(count)
}

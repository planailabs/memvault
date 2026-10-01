//! Export raw blocks from the store, one file per CID.

use std::path::Path;

use anyhow::{Context, Result};
use memvault_store::MemvaultStore;

use crate::sink::ExportSink;

/// Export every block in the store to the sink, using the hex-encoded CID
/// as the filename.  Returns the number of blocks written.
pub fn export_blocks(store: &MemvaultStore, sink: &mut dyn ExportSink) -> Result<usize> {
    // One block at a time: an export must not hold the whole store.
    let mut count = 0usize;
    for block in store.blocks() {
        let (cid, data) = block.context("iterating blocks")?;
        let name = hex::encode(cid);
        sink.write_file(Path::new(&name), &data)
            .with_context(|| format!("writing block {name}"))?;
        count += 1;
    }

    Ok(count)
}

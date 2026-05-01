//! Atomic envelope insertion: stores block + all index entries in one transaction.

use crate::error::StoreError;
use crate::keys;
use crate::tables::*;
use crate::MemvaultStore;

/// Metadata extracted from an envelope for indexing.
#[derive(Debug, Clone)]
pub struct EnvelopeMeta {
    pub author: Vec<u8>,
    pub tags: Vec<(String, String)>,
    pub wall_ns: u64,
    pub causal: Vec<Vec<u8>>,
    pub provenance: Vec<Vec<u8>>,
    pub cluster_id: Option<Vec<u8>>,
}

impl MemvaultStore {
    /// Atomically insert an envelope: stores the block and updates all relevant indexes.
    pub fn insert_envelope(
        &self,
        cid_bytes: &[u8],
        envelope_bytes: &[u8],
        meta: &EnvelopeMeta,
    ) -> Result<(), StoreError> {
        let txn = self.db.begin_write()?;
        {
            // Store block
            let mut blocks = txn.open_table(BLOCKS)?;
            blocks.insert(cid_bytes, envelope_bytes)?;

            // Tag index
            let mut tag_table = txn.open_table(BY_TAG)?;
            for (scope, label) in &meta.tags {
                let key = keys::pack_tag_key(scope, label, meta.wall_ns, cid_bytes);
                tag_table.insert(key.as_slice(), &[] as &[u8])?;
            }

            // Author index
            let mut author_table = txn.open_table(BY_AUTHOR)?;
            let author_key = keys::pack_author_key(&meta.author, meta.wall_ns, cid_bytes);
            author_table.insert(author_key.as_slice(), &[] as &[u8])?;

            // Time index
            let mut time_table = txn.open_table(BY_TIME)?;
            let time_key = keys::pack_time_key(meta.wall_ns, cid_bytes);
            time_table.insert(time_key.as_slice(), &[] as &[u8])?;

            // Causal links
            let mut causal_table = txn.open_table(BY_CAUSAL)?;
            for parent in &meta.causal {
                let link_key = keys::pack_link_key(parent, cid_bytes);
                causal_table.insert(link_key.as_slice(), &[] as &[u8])?;
            }

            // Provenance links
            let mut prov_table = txn.open_table(BY_PROVENANCE)?;
            for parent in &meta.provenance {
                let link_key = keys::pack_link_key(parent, cid_bytes);
                prov_table.insert(link_key.as_slice(), &[] as &[u8])?;
            }

            // Cluster origin
            if let Some(cluster_id) = &meta.cluster_id {
                let mut cluster_table = txn.open_table(CLUSTER_ORIGIN)?;
                let cluster_key = keys::pack_cluster_key(cluster_id, meta.wall_ns, cid_bytes);
                cluster_table.insert(cluster_key.as_slice(), &[] as &[u8])?;
            }
        }
        txn.commit()?;
        Ok(())
    }
}

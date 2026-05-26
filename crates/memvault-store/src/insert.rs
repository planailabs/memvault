//! Atomic envelope insertion: stores block + all index entries in one transaction.

use redb::ReadableTable;

use crate::MemvaultStore;
use crate::error::StoreError;
use crate::keys;
use crate::tables::*;

/// Metadata extracted from an envelope for indexing.
#[derive(Debug, Clone)]
pub struct EnvelopeMeta {
    pub author: Vec<u8>,
    pub tags: Vec<(String, String)>,
    pub wall_ns: u64,
    pub causal: Vec<Vec<u8>>,
    pub provenance: Vec<Vec<u8>>,
    pub cluster_id: Option<Vec<u8>>,
    /// Bucket this envelope belongs to (extracted from the envelope's bucket_id field).
    pub bucket_id: Option<Vec<u8>>,
}

impl MemvaultStore {
    /// Clear all secondary index tables (BY_TAG, BY_AUTHOR, BY_TIME, BY_CAUSAL, BY_PROVENANCE, CLUSTER_ORIGIN).
    /// Does NOT touch BLOCKS, HEADS, REVOCATIONS, RETRACTED, CONSUMED_TOKENS, ROTATIONS, or EDGES.
    pub fn clear_secondary_indexes(&self) -> Result<(), StoreError> {
        tracing::info!("clearing secondary index tables");
        let txn = self.db.begin_write()?;
        {
            // Drain each table by opening and removing all entries.
            let mut t = txn.open_table(BY_TAG)?;
            while let Some(entry) = t.pop_first()? {
                drop(entry);
            }
            let mut t = txn.open_table(BY_AUTHOR)?;
            while let Some(entry) = t.pop_first()? {
                drop(entry);
            }
            let mut t = txn.open_table(BY_TIME)?;
            while let Some(entry) = t.pop_first()? {
                drop(entry);
            }
            let mut t = txn.open_table(BY_CAUSAL)?;
            while let Some(entry) = t.pop_first()? {
                drop(entry);
            }
            let mut t = txn.open_table(BY_PROVENANCE)?;
            while let Some(entry) = t.pop_first()? {
                drop(entry);
            }
            let mut t = txn.open_table(CLUSTER_ORIGIN)?;
            while let Some(entry) = t.pop_first()? {
                drop(entry);
            }
            let mut t = txn.open_table(EDGES)?;
            while let Some(entry) = t.pop_first()? {
                drop(entry);
            }
            let mut t = txn.open_table(BY_BUCKET)?;
            while let Some(entry) = t.pop_first()? {
                drop(entry);
            }
        }
        txn.commit()?;
        Ok(())
    }

    /// Re-index a single block by CID, parsing it as an envelope and writing all secondary indexes.
    /// Blocks that don't parse as envelopes are silently skipped.
    pub fn reindex_block(
        &self,
        cid_bytes: &[u8],
        envelope_bytes: &[u8],
    ) -> Result<bool, StoreError> {
        let val: serde_json::Value = match serde_json::from_slice(envelope_bytes) {
            Ok(v) => v,
            Err(_) => return Ok(false), // not a JSON envelope, skip
        };

        // Extract envelope metadata
        let author: Vec<u8> = val
            .get("author")
            .and_then(|v| serde_json::from_value(v.clone()).ok())
            .unwrap_or_default();
        let mut tags: Vec<(String, String)> = val
            .get("tags")
            .and_then(|v| serde_json::from_value(v.clone()).ok())
            .unwrap_or_default();
        // Legacy annotation blocks stored tags only in EnvelopeMeta, not in
        // the body. Recover _ann tag from the annotation target field.
        if tags.is_empty() {
            if val.get("kind").and_then(|v| v.as_str()) == Some("annotation") {
                if let Some(target) = val.get("target").and_then(|v| v.as_str()) {
                    tags.push(("_ann".to_string(), target.to_string()));
                }
            }
        }
        // For attachment envelopes, add a manifest→envelope reverse lookup tag
        // so get_file_manifest can find the envelope when the manifest block
        // is missing (legacy files).
        if val.get("kind").and_then(|v| v.as_str()) == Some("attachment") {
            if let Some(mcid) = val
                .get("manifest_cid")
                .and_then(|v| serde_json::from_value::<Vec<u8>>(v.clone()).ok())
            {
                tags.push(("_manifest".to_string(), hex::encode(&mcid)));
            }
        }
        let wall_ns: u64 = val.get("wall_ns").and_then(|v| v.as_u64()).unwrap_or(0);
        let causal: Vec<Vec<u8>> = val
            .get("causal")
            .and_then(|v| serde_json::from_value(v.clone()).ok())
            .unwrap_or_default();
        let provenance: Vec<Vec<u8>> = val
            .get("provenance")
            .and_then(|v| serde_json::from_value(v.clone()).ok())
            .unwrap_or_default();
        let cluster_id: Option<Vec<u8>> = val
            .get("cluster_id")
            .and_then(|v| serde_json::from_value(v.clone()).ok());
        let bucket_id: Option<Vec<u8>> = val
            .get("bucket_id")
            .and_then(|v| serde_json::from_value(v.clone()).ok());

        if wall_ns == 0 && author.is_empty() && tags.is_empty() {
            return Ok(false); // not an envelope
        }

        let meta = EnvelopeMeta {
            author,
            tags,
            wall_ns,
            causal,
            provenance,
            cluster_id,
            bucket_id,
        };

        // Write index entries (without re-inserting the block itself)
        let txn = self.db.begin_write()?;
        {
            let mut tag_table = txn.open_table(BY_TAG)?;
            for (scope, label) in &meta.tags {
                let key = keys::pack_tag_key(scope, label, meta.wall_ns, cid_bytes);
                tag_table.insert(key.as_slice(), &[] as &[u8])?;
            }

            let mut author_table = txn.open_table(BY_AUTHOR)?;
            if !meta.author.is_empty() {
                let author_key = keys::pack_author_key(&meta.author, meta.wall_ns, cid_bytes);
                author_table.insert(author_key.as_slice(), &[] as &[u8])?;
            }

            let mut time_table = txn.open_table(BY_TIME)?;
            let time_key = keys::pack_time_key(meta.wall_ns, cid_bytes);
            time_table.insert(time_key.as_slice(), &[] as &[u8])?;

            let mut causal_table = txn.open_table(BY_CAUSAL)?;
            for parent in &meta.causal {
                let link_key = keys::pack_link_key(parent, cid_bytes);
                causal_table.insert(link_key.as_slice(), &[] as &[u8])?;
            }

            let mut prov_table = txn.open_table(BY_PROVENANCE)?;
            for parent in &meta.provenance {
                let link_key = keys::pack_link_key(parent, cid_bytes);
                prov_table.insert(link_key.as_slice(), &[] as &[u8])?;
            }

            if let Some(cluster_id) = &meta.cluster_id {
                let mut cluster_table = txn.open_table(CLUSTER_ORIGIN)?;
                let cluster_key = keys::pack_cluster_key(cluster_id, meta.wall_ns, cid_bytes);
                cluster_table.insert(cluster_key.as_slice(), &[] as &[u8])?;
            }

            if let Some(bucket_id) = &meta.bucket_id {
                let mut bucket_table = txn.open_table(BY_BUCKET)?;
                let bucket_key = keys::pack_bucket_key(bucket_id, meta.wall_ns, cid_bytes);
                bucket_table.insert(bucket_key.as_slice(), &[] as &[u8])?;
            }

            // ── Bucket metadata reconstruction ──────────────────
            // If this envelope is a bucket decl, also populate the BUCKETS table.
            let has_bucket_tag = meta
                .tags
                .iter()
                .any(|(s, l)| s == "kind" && l == "bucket-decl");
            if has_bucket_tag {
                // Try payload.BucketCreate.bucket_id (new envelope format)
                // then fall back to root bucket_id (legacy raw BucketDecl).
                let bid = val
                    .get("payload")
                    .and_then(|p| p.get("BucketCreate"))
                    .and_then(|bc| bc.get("bucket_id"))
                    .or_else(|| val.get("bucket_id"))
                    .and_then(|v| serde_json::from_value::<[u8; 32]>(v.clone()).ok());
                if let Some(bid) = bid {
                    let mut bucket_table = txn.open_table(BUCKETS)?;
                    bucket_table.insert(bid.as_slice(), cid_bytes)?;

                    // Also bind the bucket to the cluster from the envelope metadata.
                    if let Some(ref cid_val) = meta.cluster_id {
                        if cid_val.iter().any(|&b| b != 0) {
                            let mut bc_table = txn.open_table(BUCKET_CLUSTER)?;
                            // Only bind if not already bound (don't overwrite).
                            if bc_table.get(bid.as_slice())?.is_none() {
                                bc_table.insert(bid.as_slice(), cid_val.as_slice())?;
                            }
                        }
                    }
                }
            }
        }
        txn.commit()?;
        tracing::debug!("reindexed block");
        Ok(true)
    }

    /// Try to parse a block as a BucketDecl and register it in the BUCKETS table.
    /// Call this after storing a synced block that might be a bucket declaration.
    /// Returns true if the block was recognized as a bucket decl.
    pub fn reindex_bucket_decl(
        &self,
        cid_bytes: &[u8],
        block_bytes: &[u8],
    ) -> Result<bool, StoreError> {
        let val: serde_json::Value = match serde_json::from_slice(block_bytes) {
            Ok(v) => v,
            Err(_) => return Ok(false),
        };

        // Try envelope format: payload.BucketCreate.bucket_id
        let (bucket_id, cluster_id) =
            if let Some(bc) = val.get("payload").and_then(|p| p.get("BucketCreate")) {
                let bid = bc
                    .get("bucket_id")
                    .and_then(|v| serde_json::from_value::<[u8; 32]>(v.clone()).ok());
                let cid = val
                    .get("cluster_id")
                    .and_then(|v| serde_json::from_value::<Vec<u8>>(v.clone()).ok());
                (bid, cid)
            } else {
                // Legacy raw BucketDecl: has bucket_id + name at root.
                let bid = val
                    .get("bucket_id")
                    .and_then(|v| serde_json::from_value::<[u8; 32]>(v.clone()).ok());
                if bid.is_some() && val.get("name").and_then(|v| v.as_str()).is_none() {
                    return Ok(false); // Has bucket_id but no name — not a decl.
                }
                (bid, None)
            };

        let bucket_id = match bucket_id {
            Some(id) => id,
            None => return Ok(false),
        };

        let txn = self.db.begin_write()?;
        {
            let mut table = txn.open_table(BUCKETS)?;
            table.insert(bucket_id.as_slice(), cid_bytes)?;

            // Bind to cluster if we know it.
            if let Some(ref cid_val) = cluster_id {
                if cid_val.iter().any(|&b| b != 0) {
                    let mut bc_table = txn.open_table(BUCKET_CLUSTER)?;
                    if bc_table.get(bucket_id.as_slice())?.is_none() {
                        bc_table.insert(bucket_id.as_slice(), cid_val.as_slice())?;
                    }
                }
            }
        }
        txn.commit()?;
        tracing::debug!(bucket = %hex::encode(bucket_id), "reindexed bucket decl");
        Ok(true)
    }

    /// Add a single CLUSTER_ORIGIN index entry for a block.
    pub fn index_cluster_origin(
        &self,
        cid_bytes: &[u8],
        cluster_id: &[u8],
        wall_ns: u64,
    ) -> Result<(), StoreError> {
        let txn = self.db.begin_write()?;
        {
            let mut table = txn.open_table(CLUSTER_ORIGIN)?;
            let key = keys::pack_cluster_key(cluster_id, wall_ns, cid_bytes);
            table.insert(key.as_slice(), &[] as &[u8])?;
        }
        txn.commit()?;
        Ok(())
    }

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

            // Author index (skip empty authors, consistent with reindex_block)
            if !meta.author.is_empty() {
                let mut author_table = txn.open_table(BY_AUTHOR)?;
                let author_key = keys::pack_author_key(&meta.author, meta.wall_ns, cid_bytes);
                author_table.insert(author_key.as_slice(), &[] as &[u8])?;
            }

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

            // Bucket index
            if let Some(bucket_id) = &meta.bucket_id {
                let mut bucket_table = txn.open_table(BY_BUCKET)?;
                let bucket_key = keys::pack_bucket_key(bucket_id, meta.wall_ns, cid_bytes);
                bucket_table.insert(bucket_key.as_slice(), &[] as &[u8])?;
            }
        }
        txn.commit()?;
        Ok(())
    }
}

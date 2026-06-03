//! Atomic envelope insertion: stores block + all index entries in one transaction.

use redb::ReadableTable;

/// Deserialize block bytes as a JSON Value. Detects format by first
/// byte: `{` (0x7B) → JSON, otherwise → DAG-CBOR.
///
/// Signed<T> envelopes contain byte-string fields (signature,
/// agent_signature, the typed PeerId/Cid arrays) that DAG-CBOR encodes
/// as CBOR major-type-2 byte strings — those don't roundtrip cleanly
/// through `serde_json::Value`, which has no byte-string variant. When
/// the direct CBOR-to-Value decode fails, we fall back to decoding as
/// `Signed<serde_json::Value>` (the typed struct handles byte fields
/// correctly) and re-serialize via `serde_json::to_value` so callers
/// see a Value with all byte fields normalised to arrays of numbers.
pub fn deserialize_block(data: &[u8]) -> Option<serde_json::Value> {
    if data.first() == Some(&b'{') {
        return serde_json::from_slice(data).ok();
    }
    if let Ok(v) = serde_ipld_dagcbor::from_slice::<serde_json::Value>(data) {
        return Some(v);
    }
    // Fall back: Signed<T> with byte-string fields.
    let signed: memvault_core::Signed<serde_json::Value> =
        serde_ipld_dagcbor::from_slice(data).ok()?;
    serde_json::to_value(signed).ok()
}

/// Deserialize block bytes into a typed struct.  Same detection as
/// [`deserialize_block`].
pub fn deserialize_block_as<T: serde::de::DeserializeOwned>(data: &[u8]) -> Option<T> {
    if data.first() == Some(&b'{') {
        serde_json::from_slice(data).ok()
    } else {
        serde_ipld_dagcbor::from_slice(data).ok()
    }
}

use crate::MemvaultStore;
use crate::error::StoreError;
use crate::keys;
use crate::tables::*;

/// Metadata extracted from an envelope for indexing.
#[derive(Debug, Clone, Default)]
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
        let Some(view) = crate::EnvelopeView::parse(envelope_bytes) else {
            return Ok(false); // not an envelope
        };
        let val = view.raw().clone();

        // Extract envelope metadata via the canonical view — handles
        // both legacy raw-JSON envelopes and Signed<T> payload-nested
        // kind fields uniformly.
        let author: Vec<u8> = view.author();
        // Signed<T> envelopes serialize `tags` as a list of Tag structs
        // (`[{"scope":"x","label":"y"}, …]`); the legacy raw-JSON
        // fallback used the tuple shape (`[["x","y"], …]`). Try the
        // struct shape first and fall back to the tuple shape so the
        // secondary tag index gets populated for both. Without this,
        // every reindexed Signed<T> envelope would be invisible to
        // tag-scoped lookups (list_entities, list_docs, audit
        // edge_source/edge_target).
        let mut tags: Vec<(String, String)> = view
            .field("tags")
            .and_then(|raw| {
                if let Ok(structured) =
                    serde_json::from_value::<Vec<memvault_core::Tag>>(raw.clone())
                {
                    Some(
                        structured
                            .into_iter()
                            .map(|t| (t.scope, t.label))
                            .collect(),
                    )
                } else {
                    serde_json::from_value::<Vec<(String, String)>>(raw.clone()).ok()
                }
            })
            .unwrap_or_default();

        // Legacy annotation blocks stored tags only in EnvelopeMeta, not in
        // the body. Recover _ann tag from the annotation target field.
        if tags.is_empty() {
            if view.str_field("kind") == Some("annotation") {
                if let Some(target) = view.str_field("target") {
                    tags.push(("_ann".to_string(), target.to_string()));
                }
            }
        }
        // For attachment envelopes, add a manifest→envelope reverse lookup tag
        // so get_file_manifest can find the envelope when the manifest block
        // is missing (legacy files).
        if view.str_field("kind") == Some("attachment") {
            if let Some(mcid) = view.get_as::<Vec<u8>>("manifest_cid") {
                tags.push(("_manifest".to_string(), hex::encode(&mcid)));
            }
        }
        let wall_ns: u64 = view.field("wall_ns").and_then(|v| v.as_u64()).unwrap_or(0);
        let causal: Vec<Vec<u8>> = view.get_as("causal").unwrap_or_default();
        let provenance: Vec<Vec<u8>> = view.get_as("provenance").unwrap_or_default();
        let cluster_id: Option<Vec<u8>> = view.get_as("cluster_id");
        let bucket_id: Option<Vec<u8>> = view.get_as("bucket_id");

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
                    ..Default::default()
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

        if let Some(notify) = self.index_notifier.get() {
            for (scope, label) in &meta.tags {
                notify(scope, label, cid_bytes);
            }
        }

        tracing::debug!("reindexed block");
        Ok(true)
    }

    /// Try to parse a block as a BucketDecl and register it in the BUCKETS table.
    /// Call this after storing a synced block that might be a bucket declaration.
    /// Returns true if the block was recognized as a bucket decl.
    /// Register a (possibly synced) BucketDecl block in the BUCKETS table and
    /// bind it to a cluster. `fallback_cluster_id` is the LOCAL node's
    /// cluster, used when the block itself carries no cluster_id — current
    /// `Signed<T>` BucketDecls don't (cluster_id is not part of the signed
    /// envelope), so without this a synced bucket would arrive UNBOUND on
    /// the receiver until the next `bind_unbound_buckets` pass (restart).
    /// Binding to the local cluster live closes that window for the
    /// single-cluster case; an already-bound bucket is never overwritten.
    pub fn reindex_bucket_decl(
        &self,
        cid_bytes: &[u8],
        block_bytes: &[u8],
        fallback_cluster_id: Option<&[u8]>,
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

            // Bind to the block's cluster if it carries one (legacy raw
            // BucketDecls did); otherwise fall back to the local node's
            // cluster (current Signed<T> BucketDecls carry no cluster_id).
            // Only bind when currently unbound — never overwrite.
            let bind_cluster: Option<&[u8]> = cluster_id.as_deref().or(fallback_cluster_id);
            if let Some(cid_val) = bind_cluster {
                if cid_val.iter().any(|&b| b != 0) {
                    let mut bc_table = txn.open_table(BUCKET_CLUSTER)?;
                    if bc_table.get(bucket_id.as_slice())?.is_none() {
                        bc_table.insert(bucket_id.as_slice(), cid_val)?;
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

        if let Some(notify) = self.index_notifier.get() {
            for (scope, label) in &meta.tags {
                notify(scope, label, cid_bytes);
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod bind_tests {
    use crate::MemvaultStore;
    use tempfile::TempDir;

    fn decl_block(bucket_id: [u8; 32], cluster_id: Option<&[u8]>) -> Vec<u8> {
        let mut v = serde_json::json!({
            "payload": { "BucketCreate": { "bucket_id": bucket_id.to_vec() } },
            "name": "test-bucket",
        });
        if let Some(c) = cluster_id {
            v["cluster_id"] = serde_json::json!(c.to_vec());
        }
        serde_json::to_vec(&v).unwrap()
    }

    /// A synced Signed<T> BucketDecl carries no cluster_id; it must bind to
    /// the local fallback cluster live (not arrive unbound).
    #[test]
    fn synced_decl_without_cluster_binds_to_local_fallback() {
        let dir = TempDir::new().unwrap();
        let s = MemvaultStore::open(dir.path().join("db.redb")).unwrap();
        let bid = [9u8; 32];
        let local = [7u8; 32];
        assert!(
            s.reindex_bucket_decl(b"cid1", &decl_block(bid, None), Some(&local))
                .unwrap()
        );
        assert_eq!(s.get_bucket_cluster(&bid).unwrap(), Some(local.to_vec()));
    }

    /// A legacy decl that carries its own cluster_id keeps it — the local
    /// fallback only applies when the block has none.
    #[test]
    fn decl_with_cluster_keeps_block_cluster_over_fallback() {
        let dir = TempDir::new().unwrap();
        let s = MemvaultStore::open(dir.path().join("db.redb")).unwrap();
        let bid = [3u8; 32];
        let block_cluster = [1u8; 32];
        let local = [7u8; 32];
        assert!(
            s.reindex_bucket_decl(b"cid2", &decl_block(bid, Some(&block_cluster)), Some(&local))
                .unwrap()
        );
        assert_eq!(
            s.get_bucket_cluster(&bid).unwrap(),
            Some(block_cluster.to_vec())
        );
    }

    /// An already-bound bucket is never rebound by a later decl reindex.
    #[test]
    fn existing_binding_is_not_overwritten() {
        let dir = TempDir::new().unwrap();
        let s = MemvaultStore::open(dir.path().join("db.redb")).unwrap();
        let bid = [5u8; 32];
        s.bind_bucket(&bid, &[2u8; 32]).unwrap();
        assert!(
            s.reindex_bucket_decl(b"cid3", &decl_block(bid, None), Some(&[7u8; 32]))
                .unwrap()
        );
        assert_eq!(s.get_bucket_cluster(&bid).unwrap(), Some([2u8; 32].to_vec()));
    }
}

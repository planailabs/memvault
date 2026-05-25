//! Query by tag, author, time range, causal/provenance links, and buckets.

use redb::ReadableTable;

use crate::error::StoreError;
use crate::keys;
use crate::tables::*;
use crate::MemvaultStore;

impl MemvaultStore {
    /// Query CIDs by tag (scope + label), starting after `after_ns`, up to `limit` results.
    pub fn query_by_tag(
        &self,
        scope: &str,
        label: &str,
        after_ns: u64,
        limit: usize,
    ) -> Result<Vec<Vec<u8>>, StoreError> {
        let txn = self.db.begin_read()?;
        let table = txn.open_table(BY_TAG)?;

        let start = keys::pack_tag_prefix(scope, label, after_ns);
        let end = keys::pack_tag_prefix_end(scope, label);

        let mut results = Vec::new();
        let range = table.range(start.as_slice()..end.as_slice())?;
        for entry in range {
            let (key, _) = entry?;
            let cid = keys::unpack_tag_cid(key.value())?;
            results.push(cid.to_vec());
            if results.len() >= limit {
                break;
            }
        }
        Ok(results)
    }

    /// List unique labels under a tag scope, up to `limit` results.
    ///
    /// Scans the BY_TAG index for all entries with the given scope and
    /// collects distinct labels.  Useful for listing all entity IDs
    /// (scope = "entity") without going through the audit log.
    pub fn query_unique_labels(
        &self,
        scope: &str,
        limit: usize,
    ) -> Result<Vec<String>, StoreError> {
        let txn = self.db.begin_read()?;
        let table = txn.open_table(BY_TAG)?;

        let start = keys::pack_scope_prefix(scope);
        let end = keys::pack_scope_prefix_end(scope);

        let mut labels = Vec::new();
        let mut last_label = Vec::new();
        let range = table.range(start.as_slice()..end.as_slice())?;
        for entry in range {
            let (key, _) = entry?;
            let label = keys::unpack_tag_label(key.value())?;
            if label != last_label {
                last_label = label.to_vec();
                if let Ok(s) = std::str::from_utf8(label) {
                    labels.push(s.to_string());
                }
                if labels.len() >= limit {
                    break;
                }
            }
        }
        Ok(labels)
    }

    /// Query CIDs by author, starting after `after_ns`, up to `limit` results.
    pub fn query_by_author(
        &self,
        author: &[u8],
        after_ns: u64,
        limit: usize,
    ) -> Result<Vec<Vec<u8>>, StoreError> {
        let txn = self.db.begin_read()?;
        let table = txn.open_table(BY_AUTHOR)?;

        let start = keys::pack_author_prefix(author, after_ns);
        let end = keys::pack_author_prefix_end(author);

        let mut results = Vec::new();
        let range = table.range(start.as_slice()..end.as_slice())?;
        for entry in range {
            let (key, _) = entry?;
            let cid = keys::unpack_author_cid(key.value())?;
            results.push(cid.to_vec());
            if results.len() >= limit {
                break;
            }
        }
        Ok(results)
    }

    /// Query CIDs by time range [after_ns, before_ns), up to `limit` results.
    pub fn query_by_time(
        &self,
        after_ns: u64,
        before_ns: u64,
        limit: usize,
    ) -> Result<Vec<Vec<u8>>, StoreError> {
        let txn = self.db.begin_read()?;
        let table = txn.open_table(BY_TIME)?;

        let start = keys::pack_time_key(after_ns, &[]);
        let end = keys::pack_time_key(before_ns, &[]);

        let mut results = Vec::new();
        let range = table.range(start.as_slice()..end.as_slice())?;
        for entry in range {
            let (key, _) = entry?;
            let cid = keys::unpack_time_cid(key.value())?;
            results.push(cid.to_vec());
            if results.len() >= limit {
                break;
            }
        }
        Ok(results)
    }

    /// Query CIDs by time range, newest first (descending), up to `limit` results.
    pub fn query_by_time_desc(
        &self,
        after_ns: u64,
        before_ns: u64,
        limit: usize,
    ) -> Result<Vec<Vec<u8>>, StoreError> {
        let txn = self.db.begin_read()?;
        let table = txn.open_table(BY_TIME)?;

        let start = keys::pack_time_key(after_ns, &[]);
        let end = keys::pack_time_key(before_ns, &[]);

        let mut results = Vec::new();
        let range = table.range(start.as_slice()..end.as_slice())?;
        // Collect then reverse — redb ranges are always ascending.
        // For bounded limits this is fine; for very large tables we'd
        // want a proper reverse iterator but redb doesn't support that
        // on ranges easily.
        let entries: Vec<_> = range.collect();
        for entry in entries.into_iter().rev() {
            let (key, _) = entry?;
            let cid = keys::unpack_time_cid(key.value())?;
            results.push(cid.to_vec());
            if results.len() >= limit {
                break;
            }
        }
        Ok(results)
    }

    // ── Bucket queries (added B1) ───────────────────────────────────

    /// Query CIDs by bucket, starting after `after_ns`, up to `limit` results.
    pub fn query_by_bucket(
        &self,
        bucket_id: &[u8],
        after_ns: u64,
        limit: usize,
    ) -> Result<Vec<Vec<u8>>, StoreError> {
        let txn = self.db.begin_read()?;
        let table = txn.open_table(BY_BUCKET)?;

        let start = keys::pack_bucket_prefix(bucket_id, after_ns);
        let end = keys::pack_bucket_prefix_end(bucket_id);

        let mut results = Vec::new();
        let range = table.range(start.as_slice()..end.as_slice())?;
        for entry in range {
            let (key, _) = entry?;
            let cid = keys::unpack_bucket_cid(key.value())?;
            results.push(cid.to_vec());
            if results.len() >= limit {
                break;
            }
        }
        Ok(results)
    }

    /// List all buckets (returns bucket_id → decl_cid pairs from the BUCKETS table).
    pub fn list_buckets(&self) -> Result<Vec<(Vec<u8>, Vec<u8>)>, StoreError> {
        let txn = self.db.begin_read()?;
        let table = txn.open_table(BUCKETS)?;
        let mut results = Vec::new();
        for entry in table.iter()? {
            let (key, value) = entry?;
            results.push((key.value().to_vec(), value.value().to_vec()));
        }
        Ok(results)
    }

    /// Get the BucketDecl CID for a bucket.
    pub fn get_bucket(&self, bucket_id: &[u8]) -> Result<Option<Vec<u8>>, StoreError> {
        let txn = self.db.begin_read()?;
        let table = txn.open_table(BUCKETS)?;
        Ok(table.get(bucket_id)?.map(|v| v.value().to_vec()))
    }

    /// Get the cluster a bucket is bound to.
    pub fn get_bucket_cluster(&self, bucket_id: &[u8]) -> Result<Option<Vec<u8>>, StoreError> {
        let txn = self.db.begin_read()?;
        let table = txn.open_table(BUCKET_CLUSTER)?;
        Ok(table.get(bucket_id)?.map(|v| v.value().to_vec()))
    }

    /// Get the default bucket for a cluster.
    pub fn get_default_bucket(&self, cluster_id: &[u8]) -> Result<Option<Vec<u8>>, StoreError> {
        let txn = self.db.begin_read()?;
        let table = txn.open_table(CLUSTER_DEFAULT_BUCKET)?;
        Ok(table.get(cluster_id)?.map(|v| v.value().to_vec()))
    }

    /// Store a bucket declaration CID in the BUCKETS table.
    pub fn put_bucket(&self, bucket_id: &[u8], decl_cid: &[u8]) -> Result<(), StoreError> {
        let txn = self.db.begin_write()?;
        {
            let mut table = txn.open_table(BUCKETS)?;
            table.insert(bucket_id, decl_cid)?;
        }
        txn.commit()?;
        Ok(())
    }

    // ── Share queries (added B5) ──────────────────────────────────

    /// Record a share proposal in the inbox.
    pub fn record_share_inbox(
        &self,
        proposal_cid: &[u8],
        to_cluster: &[u8],
        wall_ns: u64,
        status: u8,
    ) -> Result<(), StoreError> {
        let txn = self.db.begin_write()?;
        {
            let mut table = txn.open_table(SHARE_INBOX)?;
            let mut key = Vec::with_capacity(to_cluster.len() + 8 + proposal_cid.len());
            key.extend_from_slice(to_cluster);
            key.extend_from_slice(&wall_ns.to_be_bytes());
            key.extend_from_slice(proposal_cid);
            table.insert(key.as_slice(), &[status] as &[u8])?;
        }
        txn.commit()?;
        Ok(())
    }

    /// Record a share proposal in the outbox.
    pub fn record_share_outbox(
        &self,
        proposal_cid: &[u8],
        from_cluster: &[u8],
        wall_ns: u64,
        status: u8,
    ) -> Result<(), StoreError> {
        let txn = self.db.begin_write()?;
        {
            let mut table = txn.open_table(SHARE_OUTBOX)?;
            let mut key = Vec::with_capacity(from_cluster.len() + 8 + proposal_cid.len());
            key.extend_from_slice(from_cluster);
            key.extend_from_slice(&wall_ns.to_be_bytes());
            key.extend_from_slice(proposal_cid);
            table.insert(key.as_slice(), &[status] as &[u8])?;
        }
        txn.commit()?;
        Ok(())
    }

    /// List pending share proposals from the inbox.
    pub fn list_share_inbox(&self, to_cluster: &[u8]) -> Result<Vec<Vec<u8>>, StoreError> {
        let txn = self.db.begin_read()?;
        let table = txn.open_table(SHARE_INBOX)?;
        let prefix = to_cluster.to_vec();
        let mut end = prefix.clone();
        end.push(0xFF);

        let mut results = Vec::new();
        let range = table.range(prefix.as_slice()..end.as_slice())?;
        for entry in range {
            let (key, _) = entry?;
            let k = key.value();
            if k.len() > to_cluster.len() + 8 {
                let proposal_cid = k[to_cluster.len() + 8..].to_vec();
                results.push(proposal_cid);
            }
        }
        Ok(results)
    }

    /// Record a cross-cluster bucket trust.
    pub fn record_bucket_trust(
        &self,
        bucket_id: &[u8],
        from_cluster: &[u8],
        to_cluster: &[u8],
        trust_cid: &[u8],
    ) -> Result<(), StoreError> {
        let txn = self.db.begin_write()?;
        {
            let mut table = txn.open_table(BUCKET_TRUST)?;
            let mut key = Vec::with_capacity(bucket_id.len() + from_cluster.len() + to_cluster.len());
            key.extend_from_slice(bucket_id);
            key.extend_from_slice(from_cluster);
            key.extend_from_slice(to_cluster);
            table.insert(key.as_slice(), trust_cid)?;
        }
        txn.commit()?;
        Ok(())
    }

    /// Bind a bucket to a cluster. If `is_default`, also set it as the cluster's default.
    pub fn bind_bucket(
        &self,
        bucket_id: &[u8],
        cluster_id: &[u8],
        is_default: bool,
    ) -> Result<(), StoreError> {
        let txn = self.db.begin_write()?;
        {
            let mut bc = txn.open_table(BUCKET_CLUSTER)?;
            bc.insert(bucket_id, cluster_id)?;

            if is_default {
                let mut cdb = txn.open_table(CLUSTER_DEFAULT_BUCKET)?;
                cdb.insert(cluster_id, bucket_id)?;
            }
        }
        txn.commit()?;
        Ok(())
    }
}

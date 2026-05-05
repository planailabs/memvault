//! Query by tag, author, time range, causal/provenance links.

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
}

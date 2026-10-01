//! Bounded-memory walks over the blockstore: a block count from the table
//! length, and an iterator that holds one block at a time.
//!
//! See `standards/bounded-memory.md`: a full-store walk must not collect
//! every block (a vault of books is gigabytes).

use redb::ReadableTableMetadata;

use crate::MemvaultStore;
use crate::error::StoreError;
use crate::tables::BLOCKS;

/// CIDs read per index page by [`Blocks`]; blocks themselves are read one at
/// a time.
const CID_PAGE: usize = 256;

impl MemvaultStore {
    /// The number of stored blocks (the table length; nothing is read).
    pub fn block_count(&self) -> Result<u64, StoreError> {
        let txn = self.begin_read()?;
        let table = txn.open_table(BLOCKS)?;
        Ok(table.len()?)
    }

    /// Up to `limit` block CIDs in key order, strictly after `after` (from
    /// the first when `None`). Keys only: no block is read.
    pub fn block_cids_after(
        &self,
        after: Option<&[u8]>,
        limit: usize,
    ) -> Result<Vec<Vec<u8>>, StoreError> {
        use std::ops::Bound;
        let txn = self.begin_read()?;
        let table = txn.open_table(BLOCKS)?;
        let lower = match after {
            Some(cid) => Bound::Excluded(cid),
            None => Bound::Unbounded,
        };
        let mut out = Vec::new();
        for entry in table.range::<&[u8]>((lower, Bound::Unbounded))? {
            if out.len() >= limit {
                break;
            }
            let (k, _) = entry?;
            out.push(k.value().to_vec());
        }
        Ok(out)
    }

    /// Every block as `(cid, data)`, one at a time, in CID order. CIDs are
    /// paged from the index and each block is read when it is reached, so
    /// memory stays at one block plus one page of CIDs. No transaction is
    /// held between items: the caller may write to the store (or `.await`)
    /// while walking. Blocks written during the walk may or may not be seen;
    /// a block deleted before it is reached is skipped.
    pub fn blocks(&self) -> Blocks<'_> {
        Blocks {
            store: self,
            page: std::collections::VecDeque::new(),
            last: None,
            done: false,
        }
    }
}

/// Iterator returned by [`MemvaultStore::blocks`].
pub struct Blocks<'a> {
    store: &'a MemvaultStore,
    page: std::collections::VecDeque<Vec<u8>>,
    last: Option<Vec<u8>>,
    done: bool,
}

impl Iterator for Blocks<'_> {
    type Item = Result<(Vec<u8>, Vec<u8>), StoreError>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if self.page.is_empty() {
                if self.done {
                    return None;
                }
                match self.store.block_cids_after(self.last.as_deref(), CID_PAGE) {
                    Ok(cids) => {
                        self.done = cids.len() < CID_PAGE;
                        self.last = cids.last().cloned();
                        self.page.extend(cids);
                    }
                    Err(e) => {
                        self.done = true;
                        return Some(Err(e));
                    }
                }
                if self.page.is_empty() {
                    return None;
                }
            }
            let cid = self.page.pop_front()?;
            match self.store.get_block(&cid) {
                Ok(Some(data)) => return Some(Ok((cid, data))),
                Ok(None) => continue,
                Err(e) => return Some(Err(e)),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::MemvaultStore;

    #[test]
    fn blocks_walks_every_block_across_pages() {
        let dir = tempfile::TempDir::new().unwrap();
        let store = MemvaultStore::open(dir.path().join("db")).unwrap();
        let mut want = Vec::new();
        for i in 0..(super::CID_PAGE * 2 + 7) {
            let data = format!("block {i}").into_bytes();
            let cid = memvault_core::cid_from_bytes(&data).to_bytes();
            store.put_block(&cid, &data).unwrap();
            want.push((cid, data));
        }
        want.sort();
        let got: Vec<_> = store.blocks().map(|r| r.unwrap()).collect();
        assert_eq!(got, want);
        assert_eq!(store.block_count().unwrap(), want.len() as u64);
        assert!(
            store
                .block_cids_after(want.last().map(|(c, _)| c.as_slice()), 10)
                .unwrap()
                .is_empty()
        );
    }
}

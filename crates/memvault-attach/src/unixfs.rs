//! UnixFS DAG construction (write) and traversal (read/range).

use prost::Message;

use crate::cid;
use crate::error::AttachError;
use crate::proto::{DataType, PbLink, PbNode, UnixFsData};

/// Maximum fan-out for interior DAG nodes.
const MAX_LINKS: usize = 174;

/// Build a UnixFS file DAG from bytes.
///
/// Returns (root_cid_bytes, all_blocks) where each block is (cid_bytes, data).
pub fn build_unixfs_dag(
    data: &[u8],
    chunk_size: usize,
) -> Result<(Vec<u8>, Vec<(Vec<u8>, Vec<u8>)>), AttachError> {
    if data.is_empty() {
        return Err(AttachError::EmptyInput);
    }

    let mut all_blocks: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();

    // Create leaf nodes.
    let chunks: Vec<&[u8]> = data.chunks(chunk_size).collect();
    let mut leaf_cids: Vec<(Vec<u8>, u64)> = Vec::with_capacity(chunks.len());

    for chunk in &chunks {
        let unixfs_data = UnixFsData {
            r#type: DataType::File as i32,
            data: Some(chunk.to_vec()),
            filesize: Some(chunk.len() as u64),
            blocksizes: Vec::new(),
        };
        let node = PbNode {
            data: Some(unixfs_data.encode_to_vec()),
            links: Vec::new(),
        };
        let block = node.encode_to_vec();
        let block_cid = cid::dag_pb_cid(&block);
        let cid_bytes = block_cid.to_bytes();
        leaf_cids.push((cid_bytes.clone(), chunk.len() as u64));
        all_blocks.push((cid_bytes, block));
    }

    // If only one leaf, it is the root.
    if leaf_cids.len() == 1 {
        let root_cid = leaf_cids[0].0.clone();
        return Ok((root_cid, all_blocks));
    }

    // Build balanced tree bottom-up.
    let mut current_level = leaf_cids;

    loop {
        let mut next_level: Vec<(Vec<u8>, u64)> = Vec::new();

        for group in current_level.chunks(MAX_LINKS) {
            let links: Vec<PbLink> = group
                .iter()
                .map(|(child_cid, child_size)| PbLink {
                    hash: Some(child_cid.clone()),
                    name: Some(String::new()),
                    tsize: Some(*child_size),
                })
                .collect();

            let total_size: u64 = group.iter().map(|(_, s)| s).sum();
            let blocksizes: Vec<u64> = group.iter().map(|(_, s)| *s).collect();

            let unixfs_data = UnixFsData {
                r#type: DataType::File as i32,
                data: None,
                filesize: Some(total_size),
                blocksizes,
            };

            let node = PbNode {
                data: Some(unixfs_data.encode_to_vec()),
                links,
            };
            let block = node.encode_to_vec();
            let block_cid = cid::dag_pb_cid(&block);
            let cid_bytes = block_cid.to_bytes();
            next_level.push((cid_bytes.clone(), total_size));
            all_blocks.push((cid_bytes, block));
        }

        if next_level.len() == 1 {
            let root_cid = next_level[0].0.clone();
            return Ok((root_cid, all_blocks));
        }

        current_level = next_level;
    }
}

/// Walk a UnixFS DAG to extract file bytes.
pub fn read_unixfs(
    root_cid: &[u8],
    get_block: &dyn Fn(&[u8]) -> Option<Vec<u8>>,
) -> Result<Vec<u8>, AttachError> {
    let block = get_block(root_cid)
        .ok_or_else(|| AttachError::BlockNotFound(hex::encode_upper(root_cid)))?;

    let node = PbNode::decode(block.as_slice())?;
    let ufs_data = parse_unixfs_data(&node)?;

    if node.links.is_empty() {
        // Leaf node — return the data directly.
        Ok(ufs_data.data.unwrap_or_default())
    } else {
        // Interior node — recurse into children.
        let mut result = Vec::with_capacity(ufs_data.filesize.unwrap_or(0) as usize);
        for link in &node.links {
            let child_cid = link
                .hash
                .as_ref()
                .ok_or_else(|| AttachError::InvalidDagPb("link missing hash".into()))?;
            let child_bytes = read_unixfs(child_cid, get_block)?;
            result.extend_from_slice(&child_bytes);
        }
        Ok(result)
    }
}

/// Range read from a UnixFS DAG (only fetches needed chunks).
pub fn read_unixfs_range(
    root_cid: &[u8],
    start: u64,
    end: u64,
    get_block: &dyn Fn(&[u8]) -> Option<Vec<u8>>,
) -> Result<Vec<u8>, AttachError> {
    if start >= end {
        return Ok(Vec::new());
    }

    let block = get_block(root_cid)
        .ok_or_else(|| AttachError::BlockNotFound(hex::encode_upper(root_cid)))?;

    let node = PbNode::decode(block.as_slice())?;
    let ufs_data = parse_unixfs_data(&node)?;

    let file_size = ufs_data.filesize.unwrap_or(0);
    if start >= file_size {
        return Err(AttachError::RangeOutOfBounds {
            start,
            end,
            size: file_size,
        });
    }

    let actual_end = end.min(file_size);

    if node.links.is_empty() {
        // Leaf node.
        let data = ufs_data.data.unwrap_or_default();
        let s = start as usize;
        let e = actual_end as usize;
        Ok(data[s..e].to_vec())
    } else {
        // Interior node — only fetch children that overlap [start, actual_end).
        let mut result = Vec::with_capacity((actual_end - start) as usize);
        let mut offset: u64 = 0;

        for (i, link) in node.links.iter().enumerate() {
            let child_size = if i < ufs_data.blocksizes.len() {
                ufs_data.blocksizes[i]
            } else {
                link.tsize.unwrap_or(0)
            };

            let child_start = offset;
            let child_end = offset + child_size;

            if child_end <= start {
                offset = child_end;
                continue;
            }
            if child_start >= actual_end {
                break;
            }

            let child_cid = link
                .hash
                .as_ref()
                .ok_or_else(|| AttachError::InvalidDagPb("link missing hash".into()))?;

            // Compute the local range within this child.
            let local_start = start.saturating_sub(child_start);
            let local_end = (actual_end - child_start).min(child_size);

            let child_bytes = read_unixfs_range(child_cid, local_start, local_end, get_block)?;
            result.extend_from_slice(&child_bytes);

            offset = child_end;
        }

        Ok(result)
    }
}

fn parse_unixfs_data(node: &PbNode) -> Result<UnixFsData, AttachError> {
    let raw = node
        .data
        .as_ref()
        .ok_or_else(|| AttachError::InvalidUnixFs("node missing data field".into()))?;
    let ufs = UnixFsData::decode(raw.as_slice())?;
    Ok(ufs)
}

/// Simple hex encoding for error messages (avoids a dep on the `hex` crate).
mod hex {
    pub fn encode_upper(data: &[u8]) -> String {
        data.iter().map(|b| format!("{:02X}", b)).collect()
    }
}

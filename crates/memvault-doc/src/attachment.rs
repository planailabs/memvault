use memvault_core::cid::cid_from_bytes;
use serde::{Deserialize, Serialize};

use crate::error::{DocError, Result};

/// Maximum chunk size: 256 KiB.
pub const MAX_CHUNK_SIZE: usize = 256 * 1024;

/// Reference to an attachment stored in the blockstore.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttachmentRef {
    pub name: String,
    pub content_type: String,
    pub size: u64,
    pub cid: Vec<u8>,
}

/// An attachment manifest — describes a stored file and its chunks.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Attachment {
    pub name: String,
    pub content_type: String,
    pub size: u64,
    pub blake3_hash: [u8; 32],
    pub chunks: Vec<ChunkRef>,
}

/// A reference to a single chunk of a file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChunkRef {
    pub cid: Vec<u8>,
    pub offset: u64,
    pub length: u32,
}

/// Split file data into chunks, returning the attachment manifest and chunk data pairs.
pub fn chunk_file(
    name: &str,
    content_type: &str,
    data: &[u8],
) -> (Attachment, Vec<(Vec<u8>, Vec<u8>)>) {
    let blake3_hash: [u8; 32] = blake3::hash(data).into();
    let mut chunks = Vec::new();
    let mut chunk_refs = Vec::new();
    let mut offset: u64 = 0;

    if data.is_empty() {
        // Zero-length file: no chunks
    } else {
        for chunk_data in data.chunks(MAX_CHUNK_SIZE) {
            let cid = cid_from_bytes(chunk_data);
            let cid_bytes = cid.to_bytes();
            chunk_refs.push(ChunkRef {
                cid: cid_bytes.clone(),
                offset,
                length: chunk_data.len() as u32,
            });
            chunks.push((cid_bytes, chunk_data.to_vec()));
            offset += chunk_data.len() as u64;
        }
    }

    let attachment = Attachment {
        name: name.to_string(),
        content_type: content_type.to_string(),
        size: data.len() as u64,
        blake3_hash,
        chunks: chunk_refs,
    };

    (attachment, chunks)
}

/// Reassemble a file from its chunks, verifying integrity.
pub fn reassemble_file(
    attachment: &Attachment,
    get_chunk: impl Fn(&[u8]) -> Option<Vec<u8>>,
) -> Result<Vec<u8>> {
    let mut result = Vec::with_capacity(attachment.size as usize);

    for chunk_ref in &attachment.chunks {
        let chunk_data = get_chunk(&chunk_ref.cid).ok_or_else(|| {
            DocError::ChunkNotFound(hex::encode(&chunk_ref.cid))
        })?;
        result.extend_from_slice(&chunk_data);
    }

    let hash: [u8; 32] = blake3::hash(&result).into();
    if hash != attachment.blake3_hash {
        return Err(DocError::Integrity(
            "blake3 hash mismatch after reassembly".to_string(),
        ));
    }

    Ok(result)
}

// We use a simple hex encode for error messages; inline it to avoid extra dep.
mod hex {
    pub fn encode(data: &[u8]) -> String {
        data.iter().map(|b| format!("{b:02x}")).collect()
    }
}

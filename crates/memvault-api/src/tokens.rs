//! Token lifecycle helpers (issue, redeem, revoke, list).

use ed25519_dalek::{Signer, SigningKey};
use memvault_auth::{JoinToken, Role, encode_token_string};
use memvault_core::{ClusterId, PeerId};
use memvault_store::MemvaultStore;

use crate::error::{ApiError, Result};
use crate::types::TokenStatus;

/// Issue a new join token signed by the cluster admin key.
///
/// Returns the encoded token string (`mvjoin1:...`).
pub fn issue_token(
    admin_peer_id: &PeerId,
    cluster_id: &ClusterId,
    admin_key: &SigningKey,
    role: Role,
    ttl_secs: u64,
    max_uses: u32,
    label: Option<String>,
    admin_genesis: Option<memvault_auth::AdminGenesis>,
    store: &MemvaultStore,
) -> Result<String> {
    let now_ns = memvault_core::time::wall_ns();
    let ttl_ns = ttl_secs * 1_000_000_000;
    let mut nonce = [0u8; 16];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut nonce);

    let token = JoinToken {
        issuer: admin_peer_id.clone(),
        cluster_id: cluster_id.clone(),
        role,
        initial_grants: vec![],
        not_before_ns: now_ns,
        not_after_ns: now_ns + ttl_ns,
        max_uses,
        nonce,
        label: label.clone(),
        admin_genesis,
        signature: [0u8; 64],
    };

    let signing_bytes = token
        .signing_bytes()
        .map_err(|e| ApiError::Other(format!("token signing bytes: {e}")))?;
    let sig = admin_key.sign(&signing_bytes);

    let token = JoinToken {
        signature: sig.to_bytes(),
        ..token
    };

    // Store the token as a block so it appears in list_tokens.
    let token_cbor = serde_ipld_dagcbor::to_vec(&token)
        .map_err(|e| ApiError::Other(format!("token cbor encode: {e}")))?;
    let cid = memvault_core::cid::cid_from_bytes(&token_cbor);
    let cid_bytes = cid.to_bytes();

    // Store in blockstore with metadata for discovery.
    let meta = memvault_store::insert::EnvelopeMeta {
        author: admin_peer_id.0.clone(),
        tags: vec![
            ("kind".to_string(), "join-token".to_string()),
            ("role".to_string(), format!("{:?}", role).to_lowercase()),
        ],
        wall_ns: now_ns,
        causal: vec![],
        provenance: vec![],
        cluster_id: Some(cluster_id.0.to_vec()),
        bucket_id: None,
            ..Default::default()
    };
    store.insert_envelope(&cid_bytes, &token_cbor, &meta)?;

    let encoded =
        encode_token_string(&token).map_err(|e| ApiError::Other(format!("token encode: {e}")))?;

    Ok(encoded)
}

/// List all tokens stored in the system.
///
/// Scans blocks tagged with `kind:join-token` and cross-references
/// consumed tokens to build status.
pub fn list_tokens(store: &MemvaultStore) -> Result<Vec<TokenStatus>> {
    let token_cids = store.query_by_tag("kind", "join-token", 0, 1000)?;
    let mut statuses = Vec::new();

    for cid_bytes in token_cids {
        let block = match store.get_block(&cid_bytes)? {
            Some(b) => b,
            None => continue,
        };

        let token: JoinToken = match serde_ipld_dagcbor::from_slice(&block) {
            Ok(t) => t,
            Err(_) => continue,
        };

        let is_revoked = store.is_revoked(&cid_bytes).unwrap_or(false);
        let consumed_count = store.get_token_consumption_count(&cid_bytes).unwrap_or(0);

        statuses.push(TokenStatus {
            cid: cid_bytes,
            label: token.label,
            role: token.role,
            max_uses: token.max_uses,
            consumed_count,
            not_after_ns: token.not_after_ns,
            revoked: is_revoked,
        });
    }

    Ok(statuses)
}

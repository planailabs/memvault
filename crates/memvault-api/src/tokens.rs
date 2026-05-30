//! Token lifecycle helpers (issue, redeem, revoke, list).

use ed25519_dalek::{Signer, SigningKey};
use memvault_auth::{JoinToken, Role, encode_token_string};
use memvault_core::{ClusterId, PeerId};
use memvault_keystore::KeyStore;
use memvault_store::MemvaultStore;

use crate::error::{ApiError, Result};
use crate::types::TokenStatus;

// Keystore key scheme for tokens (kept off redb so a second process —
// memctl — can issue/list/revoke while the daemon holds the blockstore):
//   token:<cid-hex>      → token CBOR bytes
//   tokused:<cid-hex>    → u32 LE consumption count
//   tokrevoked:<cid-hex> → revocation reason (presence ⇒ revoked)
fn token_key(cid: &[u8]) -> Vec<u8> {
    format!("token:{}", hex::encode(cid)).into_bytes()
}
pub(crate) fn token_used_key(cid: &[u8]) -> Vec<u8> {
    format!("tokused:{}", hex::encode(cid)).into_bytes()
}
pub(crate) fn token_revoked_key(cid: &[u8]) -> Vec<u8> {
    format!("tokrevoked:{}", hex::encode(cid)).into_bytes()
}

/// Keystore marker recording that the one-off redb→keystore token
/// migration has run, so it never runs (or re-reads redb) again.
const TOKENS_MIGRATED_MARKER: &[u8] = b"migrated:tokens";

/// One-off migration of legacy redb token state into the keystore: every
/// `kind:join-token` block, plus its consumption count and revocation
/// status, is copied across once. Guarded by a marker key so it runs a
/// single time; afterwards the keystore is authoritative and redb is never
/// consulted for tokens again. Returns the number of tokens migrated.
pub fn migrate_redb_tokens(store: &MemvaultStore, keystore: &KeyStore) -> Result<usize> {
    if keystore.contains(TOKENS_MIGRATED_MARKER) {
        return Ok(0);
    }
    let mut migrated = 0usize;
    for cid_bytes in store.query_by_tag("kind", "join-token", 0, 100_000)? {
        // Don't clobber a token already issued straight into the keystore.
        if keystore.contains(&token_key(&cid_bytes)) {
            continue;
        }
        let Some(block) = store.get_block(&cid_bytes)? else {
            continue;
        };
        // Validate it decodes as a token before copying.
        if serde_ipld_dagcbor::from_slice::<JoinToken>(&block).is_err() {
            continue;
        }
        keystore
            .put(&token_key(&cid_bytes), &block)
            .map_err(|e| ApiError::Other(format!("migrate token: {e}")))?;
        let used = store.get_token_consumption_count(&cid_bytes).unwrap_or(0);
        if used > 0 {
            keystore
                .put(&token_used_key(&cid_bytes), &used.to_le_bytes())
                .map_err(|e| ApiError::Other(format!("migrate token count: {e}")))?;
        }
        if store.is_revoked(&cid_bytes).unwrap_or(false) {
            keystore
                .put(&token_revoked_key(&cid_bytes), b"migrated")
                .map_err(|e| ApiError::Other(format!("migrate token revocation: {e}")))?;
        }
        migrated += 1;
    }
    keystore
        .put(TOKENS_MIGRATED_MARKER, b"1")
        .map_err(|e| ApiError::Other(format!("set token migration marker: {e}")))?;
    Ok(migrated)
}

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
    admit_as_admin: bool,
    issuer_addrs: Vec<String>,
    keystore: &KeyStore,
) -> Result<String> {
    // Admin and node membership tokens admit a peer into the cluster's trust
    // (a co-admin or a replicating node). They must only be minted once the
    // cluster is set up — i.e. the AdminGenesis exists — both so the cluster
    // has an established trust root and so the joiner can pin it from the
    // token. Agent roles (AgentHost/Auditor/Service) may predate genesis.
    if matches!(role, Role::Admin | Role::Node) && admin_genesis.is_none() {
        return Err(ApiError::Other(format!(
            "{role:?} tokens require a set-up cluster (run genesis first)"
        )));
    }

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
        admit_as_admin,
        issuer_addrs,
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

    // Persist the token into the keystore — the source of truth, off redb,
    // so a separate process can issue tokens while the daemon holds the
    // blockstore.
    let token_cbor = serde_ipld_dagcbor::to_vec(&token)
        .map_err(|e| ApiError::Other(format!("token cbor encode: {e}")))?;
    let cid = memvault_core::cid::cid_from_bytes(&token_cbor);
    let cid_bytes = cid.to_bytes();

    keystore
        .put(&token_key(&cid_bytes), &token_cbor)
        .map_err(|e| ApiError::Other(format!("keystore put token: {e}")))?;

    let encoded =
        encode_token_string(&token).map_err(|e| ApiError::Other(format!("token encode: {e}")))?;

    Ok(encoded)
}

/// Whether a token CID is revoked. The keystore is authoritative (redb
/// data is considered migrated).
pub(crate) fn token_revoked(keystore: &KeyStore, cid: &[u8]) -> bool {
    keystore.contains(&token_revoked_key(cid))
}

/// Consumption count for a token (keystore authoritative).
pub(crate) fn token_consumed(keystore: &KeyStore, cid: &[u8]) -> u32 {
    keystore.get_u32(&token_used_key(cid))
}

fn status_for(keystore: &KeyStore, cid_bytes: Vec<u8>, token: JoinToken) -> TokenStatus {
    TokenStatus {
        consumed_count: token_consumed(keystore, &cid_bytes),
        revoked: token_revoked(keystore, &cid_bytes),
        label: token.label,
        role: token.role,
        max_uses: token.max_uses,
        not_after_ns: token.not_after_ns,
        cid: cid_bytes,
    }
}

/// Revoke a token by CID in the keystore (works with no redb open).
pub fn revoke_token(keystore: &KeyStore, cid: &[u8], reason: &str) -> Result<()> {
    keystore
        .put(&token_revoked_key(cid), reason.as_bytes())
        .map_err(|e| ApiError::Other(format!("keystore revoke token: {e}")))
}

/// List all tokens from the keystore (the source of truth; redb token
/// blocks are considered migrated). Works with no redb open at all.
pub fn list_tokens(keystore: &KeyStore) -> Result<Vec<TokenStatus>> {
    let mut statuses = Vec::new();
    for k in keystore.keys_with_prefix(b"token:") {
        let Some(hex_cid) = k.strip_prefix(b"token:") else {
            continue;
        };
        let Ok(cid_bytes) = hex::decode(hex_cid) else {
            continue;
        };
        let Some(cbor) = keystore.get(&k) else { continue };
        let token: JoinToken = match serde_ipld_dagcbor::from_slice(&cbor) {
            Ok(t) => t,
            Err(_) => continue,
        };
        statuses.push(status_for(keystore, cid_bytes, token));
    }
    Ok(statuses)
}

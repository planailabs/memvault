//! Agent identity: key storage, loading, enrollment, and signing.
//!
//! Each agent's identity directory contains exactly one file:
//! - `private_key.pem` — Ed25519 private key (signs JWTs + per-write
//!   `Signed<T>` agent co-signatures).
//!
//! Everything else is derived or looked up:
//! - `agent_id` comes from the directory's basename.
//! - `verifying_key` is derived from the private key.
//! - The full `AgentAttestation` lives on the sigchain (the JWT
//!   verifier already resolves it by agent pubkey — cd0bd54b dropped
//!   JWT attestation embed). Envelope attribution falls back to the
//!   same chain lookup by author pubkey, so the per-write inline
//!   attestation CID was unnecessary local state and is gone.

use std::path::Path;

use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use memvault_auth::{JoinToken, Role, encode_token_string};
use memvault_core::{AgentId, ClusterId, PeerId};

use crate::error::{ApiError, Result};

/// A loaded agent identity: the signing key + the agent_id derived from
/// the identity directory's basename. The attestation and its CID are
/// not held in process — readers and writers resolve them from the
/// sigchain via the agent's pubkey.
#[derive(Debug, Clone)]
pub struct AgentIdentity {
    pub agent_id: AgentId,
    pub signing_key: SigningKey,
    pub verifying_key: VerifyingKey,
}


impl AgentIdentity {
    /// Load an existing agent identity from an identity directory.
    ///
    /// The directory must contain `private_key.pem`. `agent_id` is
    /// derived from the directory's basename (e.g.
    /// `…/agents/openclaw/` → `"openclaw"`).
    pub fn load(identity_dir: &Path) -> Result<Self> {
        let key_path = identity_dir.join("private_key.pem");

        let pem_bytes = std::fs::read(&key_path)
            .map_err(|e| ApiError::Other(format!("failed to read {}: {e}", key_path.display())))?;
        let signing_key = parse_ed25519_pem(&pem_bytes)?;
        let verifying_key = signing_key.verifying_key();

        let agent_id_str = identity_dir
            .file_name()
            .and_then(|s| s.to_str())
            .ok_or_else(|| {
                ApiError::Other(format!(
                    "could not derive agent_id from identity dir basename: {}",
                    identity_dir.display()
                ))
            })?
            .to_string();

        Ok(Self {
            agent_id: AgentId(agent_id_str),
            signing_key,
            verifying_key,
        })
    }

    /// Generate a new agent identity, signed by the given node's private key.
    ///
    /// The node's own [`NodeAttestation`](memvault_auth::NodeAttestation)
    /// must already be in the cluster's sig-chain; verifiers will look it up
    /// at JWT-verify time. The signed `AgentAttestation` is returned for
    /// the caller to publish via `sigchain::publish_agent_attestation`;
    /// nothing about it is persisted locally — `private_key.pem` is the
    /// only file written.
    ///
    /// `cluster_id` is accepted for API stability with older call sites
    /// but is no longer used: the on-chain node attestation is the
    /// source of truth for cluster membership.
    pub fn generate_local(
        identity_dir: &Path,
        agent_id: &str,
        _cluster_id: &ClusterId,
        node_signing_key: &SigningKey,
        role: Role,
        ttl_ns: u64,
    ) -> Result<(Self, memvault_auth::AgentAttestation)> {
        std::fs::create_dir_all(identity_dir)
            .map_err(|e| ApiError::Other(format!("failed to create identity dir: {e}")))?;

        let mut secret = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut secret);
        let signing_key = SigningKey::from_bytes(&secret);
        let verifying_key = signing_key.verifying_key();

        let now_ns = memvault_core::time::wall_ns();
        // `saturating_add` so callers can pass `u64::MAX` for "never expires"
        // without wrapping.
        let not_after_ns = now_ns.saturating_add(ttl_ns);

        let attestation = memvault_auth::sign_agent_attestation(
            node_signing_key,
            AgentId(agent_id.to_string()),
            verifying_key.to_bytes(),
            role,
            not_after_ns,
        )
        .map_err(|e| ApiError::Other(format!("sign agent attestation: {e}")))?;

        write_identity_dir(identity_dir, &signing_key)?;

        Ok((
            Self {
                agent_id: AgentId(agent_id.to_string()),
                signing_key,
                verifying_key,
            },
            attestation,
        ))
    }

    /// Check if an identity directory already has a valid identity.
    pub fn exists(identity_dir: &Path) -> bool {
        identity_dir.join("private_key.pem").exists()
    }

    /// Load if exists, otherwise generate locally. When generating, the
    /// freshly-signed attestation is published by the caller (see
    /// `enroll_local_agent` for the canonical path); `ensure` only
    /// touches local files.
    pub fn ensure(
        identity_dir: &Path,
        agent_id: &str,
        cluster_id: &ClusterId,
        node_signing_key: &SigningKey,
        role: Role,
        ttl_ns: u64,
    ) -> Result<Self> {
        if Self::exists(identity_dir) {
            Self::load(identity_dir)
        } else {
            Self::generate_local(
                identity_dir,
                agent_id,
                cluster_id,
                node_signing_key,
                role,
                ttl_ns,
            )
            .map(|(identity, _attestation)| identity)
        }
    }

    /// The peer ID derived from this agent's public key.
    pub fn peer_id(&self) -> PeerId {
        PeerId(self.verifying_key.as_bytes().to_vec())
    }

    /// Issue a JWT-format bearer token signed by this agent's key.
    /// The token embeds the attestation inline so the daemon can verify it
    /// without a state lookup.
    ///
    /// `scope`: space-separated OAuth-style scopes ("read write" / "admin" / etc.).
    /// `ttl_secs`: lifetime in seconds; typical values 300 (short-lived) — 3600.
    pub fn issue_jwt(&self, scope: &str, ttl_secs: u64) -> Result<String> {
        memvault_auth::jwt::issue(&self.signing_key, &self.agent_id.0, scope, ttl_secs)
            .map_err(|e| ApiError::Other(format!("issue_jwt: {e}")))
    }
}

/// Enroll (or re-use) a per-agent identity backed by the local node, then
/// publish its attestation to the sigchain so peers can verify writes from
/// that agent. This is the LocalClient-side analogue of
/// `enroll_remote_agent` (which exchanges a join token over HTTP): the
/// daemon is its own attestor and uses its in-memory node signing key to
/// sign the `AgentAttestation` directly.
///
/// On every call:
///   1. Pulls `node_signing_key` and `cluster_id` from the live
///      `LocalClient` (no need for callers to thread them through).
///   2. Loads an existing identity from `identity_dir` iff it was signed by
///      the **current** node key and hasn't expired. If the key rotated
///      or the attestation expired, the directory is removed and a fresh
///      identity is minted — same self-healing behavior the web UI's
///      `init_ui_agent` already implements.
///   3. Generates a new keypair + attestation when no valid cache exists.
///   4. Publishes the (new or reused) attestation via
///      `sigchain::publish_agent_attestation`. Idempotent at the redb
///      layer (keyed by attestation CID), so re-runs are safe.
///
/// Returns the resulting `AgentIdentity`. Caller is responsible for any
/// process-local state binding (e.g. setting `MEMVAULT_IDENTITY_DIR` in a
/// subprocess env, or installing the identity in a global cache).
///
/// **Prerequisites on the client:** a node signing key must already be
/// installed via `LocalClient::set_node_signing_key`. Pre-genesis cluster
/// state (all-zero cluster_id) is tolerated — the attestation gets
/// recorded with that cluster_id and is replaced if the node later joins
/// a real cluster and key-rotates.
pub fn enroll_local_agent(
    client: &crate::LocalClient,
    agent_id: &str,
    identity_dir: &Path,
    role: Role,
    ttl_ns: u64,
) -> Result<AgentIdentity> {
    let node_signing_key = client
        .node_signing_key()
        .ok_or_else(|| ApiError::Other(
            "enroll_local_agent: node signing key not set on LocalClient; \
             call set_node_signing_key first".into(),
        ))?
        .clone();
    let node_pubkey_bytes = node_signing_key.verifying_key().to_bytes();

    let cluster_bytes = client.cluster_id();
    let mut cluster_arr = [0u8; 32];
    if cluster_bytes.len() == 32 {
        cluster_arr.copy_from_slice(cluster_bytes);
    }
    let cluster_id = memvault_core::ClusterId(cluster_arr);

    let now_ns = memvault_core::time::wall_ns();

    // Reuse an existing on-disk identity iff the sigchain still carries
    // an attestation for its pubkey that's signed by the current node
    // key and not expired. The freshness check used to consult the
    // local attestation.cbor file; now it goes straight to the chain so
    // both `init_ui_agent` and `enroll_local_agent` see the same
    // truth-of-record.
    let existing = if AgentIdentity::exists(identity_dir) {
        match AgentIdentity::load(identity_dir) {
            Ok(id) => match crate::sigchain::find_agent_attestation(
                client,
                &id.verifying_key.to_bytes(),
            ) {
                Ok(Some(att))
                    if att.node_pubkey == node_pubkey_bytes
                        && att.not_after_ns > now_ns =>
                {
                    Some((id, att))
                }
                _ => {
                    tracing::info!(
                        agent_id,
                        "agent attestation on-chain is missing, expired, or signed by a \
                         rotated node key; regenerating"
                    );
                    let _ = std::fs::remove_dir_all(identity_dir);
                    None
                }
            },
            Err(e) => {
                tracing::warn!(agent_id, error = %e, "agent identity unreadable; regenerating");
                let _ = std::fs::remove_dir_all(identity_dir);
                None
            }
        }
    } else {
        None
    };

    let (identity, attestation) = match existing {
        Some((id, att)) => (id, att),
        None => AgentIdentity::generate_local(
            identity_dir,
            agent_id,
            &cluster_id,
            &node_signing_key,
            role,
            ttl_ns,
        )?,
    };

    let attestation_cid = crate::sigchain::publish_agent_attestation(client, &attestation)
        .map_err(|e| ApiError::Other(format!("publish agent attestation: {e}")))?;
    // Hand the CID to the LocalClient so subsequent writes can embed
    // it as inline attribution without re-scanning the sigchain.
    client.set_agent_attestation_cid(attestation_cid);

    Ok(identity)
}

/// Persist the agent's private key. That's the entire on-disk identity
/// now — `agent_id` derives from the parent directory's basename and
/// the attestation lives on the sigchain.
pub fn write_identity_dir(dir: &Path, signing_key: &SigningKey) -> Result<()> {
    let pem = encode_ed25519_pem(signing_key);
    std::fs::write(dir.join("private_key.pem"), pem.as_bytes())
        .map_err(|e| ApiError::Other(format!("failed to write private_key.pem: {e}")))?;

    // Set restrictive permissions on the key file (Unix only)
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o600);
        let _ = std::fs::set_permissions(dir.join("private_key.pem"), perms);
    }

    Ok(())
}

/// Encode an Ed25519 signing key as a simplified PEM (just the raw seed).
/// Format: `-----BEGIN ED25519 PRIVATE KEY-----\n<base64(seed)>\n-----END ED25519 PRIVATE KEY-----`
fn encode_ed25519_pem(key: &SigningKey) -> String {
    use data_encoding::BASE64;
    let seed = key.to_bytes();
    let b64 = BASE64.encode(&seed);
    format!("-----BEGIN ED25519 PRIVATE KEY-----\n{b64}\n-----END ED25519 PRIVATE KEY-----\n")
}

/// Parse an Ed25519 signing key from our simplified PEM format.
fn parse_ed25519_pem(pem_bytes: &[u8]) -> Result<SigningKey> {
    let pem_str = std::str::from_utf8(pem_bytes)
        .map_err(|e| ApiError::Other(format!("PEM is not valid UTF-8: {e}")))?;

    let b64_line = pem_str
        .lines()
        .find(|line| !line.starts_with("-----") && !line.is_empty())
        .ok_or_else(|| ApiError::Other("PEM file has no data line".into()))?;

    use data_encoding::BASE64;
    let seed_bytes = BASE64
        .decode(b64_line.as_bytes())
        .map_err(|e| ApiError::Other(format!("PEM base64 decode failed: {e}")))?;

    let seed: [u8; 32] = seed_bytes
        .try_into()
        .map_err(|_| ApiError::Other("PEM seed must be exactly 32 bytes".into()))?;

    Ok(SigningKey::from_bytes(&seed))
}

/// Outcome of [`enroll_remote_agent`].
#[derive(Debug, Clone)]
pub struct EnrollResult {
    /// Freshly-minted (or reused) agent attestation.
    pub attestation: memvault_auth::AgentAttestation,
    /// CID of the attestation block in the sigchain.
    pub attestation_cid: Vec<u8>,
}

/// Server-side agent enrollment for an HTTP / network caller.
///
/// The caller (typically the `POST /api/v1/auth/enroll-agent` handler)
/// passes the encoded join token + the agent's chosen pubkey. This
/// function:
///   1. Decodes the token, verifies signature against the admin key
///      held on `client`, checks time bounds, cluster_id, revocation,
///      and `max_uses`.
///   2. Reuses an existing `AgentAttestation` for the same
///      `agent_pubkey` if one is on the chain (idempotent retries).
///   3. Otherwise mints a fresh attestation with the node's signing
///      key, publishes it to the sigchain, and records token
///      consumption.
///
/// The agent never touches its private key on the server — only the
/// pubkey crosses the wire.
pub fn enroll_remote_agent(
    client: &crate::LocalClient,
    token_str: &str,
    agent_id: &str,
    agent_pubkey: [u8; 32],
) -> Result<EnrollResult> {
    // Decode + verify the token.
    let token = memvault_auth::decode_token_string(token_str)
        .map_err(|e| ApiError::Other(format!("decode token: {e}")))?;
    let admin_vk = client
        .admin_verifying_key()
        .ok_or_else(|| ApiError::Other("no admin pubkey on this node".into()))?;
    token
        .verify_signature(&admin_vk)
        .map_err(|_| ApiError::Other("token signature does not verify".into()))?;
    let now_ns = memvault_core::wall_ns();
    token
        .verify_time_bounds(now_ns)
        .map_err(|e| ApiError::Other(format!("token time bounds: {e}")))?;
    if token.cluster_id.0.as_slice() != client.cluster_id() {
        return Err(ApiError::Other("token cluster_id mismatch".into()));
    }

    // CID of the token, for consumption tracking + revocation lookup.
    let token_cbor = serde_ipld_dagcbor::to_vec(&token)
        .map_err(|e| ApiError::Serialization(e.to_string()))?;
    let token_cid = memvault_core::cid_from_bytes(&token_cbor).to_bytes();

    if client.store().is_revoked(&token_cid).unwrap_or(false) {
        return Err(ApiError::Other("token revoked".into()));
    }

    // Idempotent re-enrollment: if we already minted for this pubkey,
    // return the existing attestation without re-consuming.
    if let Some(existing) = crate::sigchain::find_agent_attestation(client, &agent_pubkey)? {
        let existing_bytes = serde_ipld_dagcbor::to_vec(&existing)
            .map_err(|e| ApiError::Serialization(e.to_string()))?;
        let existing_cid = memvault_core::cid_from_bytes(&existing_bytes).to_bytes();
        return Ok(EnrollResult {
            attestation: existing,
            attestation_cid: existing_cid,
        });
    }

    // Enforce max_uses BEFORE minting.
    let used = client
        .store()
        .get_token_consumption_count(&token_cid)
        .unwrap_or(0);
    if used >= token.max_uses {
        return Err(ApiError::Other(
            "token already consumed (max_uses hit)".into(),
        ));
    }

    // Mint + publish.
    let node_sk = client
        .node_signing_key()
        .ok_or_else(|| ApiError::Other("no node signing key configured".into()))?;
    let attestation = memvault_auth::sign_agent_attestation(
        node_sk,
        AgentId(agent_id.to_string()),
        agent_pubkey,
        token.role,
        token.not_after_ns,
    )
    .map_err(|e| ApiError::Other(format!("sign attestation: {e}")))?;
    let attestation_cid = crate::sigchain::publish_agent_attestation(client, &attestation)?;

    // Record consumption.
    let _ = client
        .store()
        .record_token_consumption(&token_cid, &agent_pubkey, now_ns);

    Ok(EnrollResult {
        attestation,
        attestation_cid,
    })
}

/// Issue a join token for an agent, signed by the admin key.
/// This is the "local enrollment" path — no network round-trip.
pub fn issue_join_token(
    admin_peer_id: &PeerId,
    cluster_id: &ClusterId,
    admin_key: &SigningKey,
    role: Role,
    ttl_ns: u64,
    max_uses: u32,
    label: Option<String>,
    admin_genesis: Option<memvault_auth::AdminGenesis>,
) -> Result<(JoinToken, String)> {
    let now_ns = memvault_core::time::wall_ns();
    let mut nonce = [0u8; 16];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut nonce);

    let token = JoinToken {
        issuer: admin_peer_id.clone(),
        cluster_id: cluster_id.clone(),
        role,
        initial_grants: vec![],
        not_before_ns: now_ns,
        not_after_ns: now_ns.saturating_add(ttl_ns),
        max_uses,
        nonce,
        label,
        admin_genesis,
        signature: [0u8; 64], // placeholder
    };

    let signing_bytes = token
        .signing_bytes()
        .map_err(|e| ApiError::Other(format!("token signing bytes: {e}")))?;
    let sig = admin_key.sign(&signing_bytes);

    let token = JoinToken {
        signature: sig.to_bytes(),
        ..token
    };

    let encoded =
        encode_token_string(&token).map_err(|e| ApiError::Other(format!("token encode: {e}")))?;

    Ok((token, encoded))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_admin_key() -> (SigningKey, VerifyingKey) {
        let mut secret = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut secret);
        let sk = SigningKey::from_bytes(&secret);
        let vk = sk.verifying_key();
        (sk, vk)
    }

    #[test]
    fn test_pem_roundtrip() {
        let (sk, _) = make_admin_key();
        let pem = encode_ed25519_pem(&sk);
        let sk2 = parse_ed25519_pem(pem.as_bytes()).unwrap();
        assert_eq!(sk.to_bytes(), sk2.to_bytes());
    }

    #[test]
    fn test_generate_and_load_identity() {
        let (admin_sk, admin_vk) = make_admin_key();
        let admin_peer_id = PeerId(admin_vk.as_bytes().to_vec());
        let cluster_id = ClusterId::random();

        let dir = tempfile::tempdir().unwrap();
        let identity_dir = dir.path().join("agent-test");

        // Generate — node signs the agent attestation directly (no admin chain in this test).
        let (identity, attestation) = AgentIdentity::generate_local(
            &identity_dir,
            "test-agent",
            &cluster_id,
            &admin_sk, // re-using the same key as the "node" signing key for this test
            Role::AgentHost,
            86400_000_000_000, // 1 day in ns
        )
        .unwrap();

        assert_eq!(identity.agent_id.0, "test-agent");

        // The signed attestation is returned but not persisted —
        // verify it here, then confirm no other files leak onto disk.
        attestation.verify_signature().unwrap();
        assert_eq!(
            attestation.node_pubkey,
            admin_vk.to_bytes(),
            "attestation's node_pubkey matches the signer"
        );
        let _ = admin_peer_id;

        // Load from disk: agent_id derives from the directory basename.
        let loaded = AgentIdentity::load(&identity_dir).unwrap();
        assert_eq!(loaded.agent_id.0, "agent-test");
        assert_eq!(
            loaded.signing_key.to_bytes(),
            identity.signing_key.to_bytes()
        );
        // private_key.pem is the only file the dir should contain now.
        assert!(!identity_dir.join("attestation.cbor").exists());
        assert!(!identity_dir.join("agent.json").exists());
    }

    #[test]
    fn test_ensure_idempotent() {
        let (admin_sk, admin_vk) = make_admin_key();
        let _admin_peer_id = PeerId(admin_vk.as_bytes().to_vec());
        let cluster_id = ClusterId::random();

        let dir = tempfile::tempdir().unwrap();
        let identity_dir = dir.path().join("agent-ensure");

        // First call: generates
        let id1 = AgentIdentity::ensure(
            &identity_dir,
            "ensure-agent",
            &cluster_id,
            &admin_sk,
            Role::AgentHost,
            86400_000_000_000,
        )
        .unwrap();

        // Second call: loads (same key)
        let id2 = AgentIdentity::ensure(
            &identity_dir,
            "ensure-agent",
            &cluster_id,
            &admin_sk,
            Role::AgentHost,
            86400_000_000_000,
        )
        .unwrap();

        assert_eq!(id1.signing_key.to_bytes(), id2.signing_key.to_bytes());
    }

    #[test]
    fn test_issue_join_token() {
        let (admin_sk, admin_vk) = make_admin_key();
        let admin_peer_id = PeerId(admin_vk.as_bytes().to_vec());
        let cluster_id = ClusterId::random();

        let (token, encoded) = issue_join_token(
            &admin_peer_id,
            &cluster_id,
            &admin_sk,
            Role::AgentHost,
            3600_000_000_000, // 1 hour
            1,
            Some("test-token".to_string()),
            None,
        )
        .unwrap();

        // Verify signature
        token.verify_signature(&admin_vk).unwrap();

        // Verify encoded roundtrip
        assert!(encoded.starts_with("mvjoin1:"));
        let decoded = memvault_auth::decode_token_string(&encoded).unwrap();
        decoded.verify_signature(&admin_vk).unwrap();
        assert_eq!(decoded.label, Some("test-token".to_string()));
    }
}

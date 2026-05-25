//! Agent identity: key storage, loading, enrollment, and signing.
//!
//! Each agent gets an identity directory containing:
//! - `private_key.pem` — Ed25519 private key (PKCS8 PEM)
//! - `attestation.cbor` — Signed MembershipAttestation from the cluster admin
//! - `enrollment.cbor` — Signed AgentEnrollment record
//! - `agent.json` — metadata (agent_id, cluster_id, enrolled_at_ns)

use std::path::Path;

use ed25519_dalek::{SigningKey, VerifyingKey, Signer};
use memvault_auth::{
    AgentEnrollment, AttestationOrigin, MembershipAttestation, Role,
    JoinToken,
    encode_token_string,
};
use memvault_core::{AgentId, ClusterId, PeerId};
use serde::{Deserialize, Serialize};

use crate::error::{ApiError, Result};

/// Metadata written to `agent.json` alongside the cryptographic material.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentMeta {
    pub agent_id: String,
    pub cluster_id: String, // hex
    pub enrolled_at_ns: u64,
}

/// A loaded agent identity: signing key + attestation + enrollment.
#[derive(Debug, Clone)]
pub struct AgentIdentity {
    pub agent_id: AgentId,
    pub signing_key: SigningKey,
    pub verifying_key: VerifyingKey,
    pub attestation: MembershipAttestation,
    pub enrollment: AgentEnrollment,
    pub cluster_id: ClusterId,
}

impl AgentIdentity {
    /// Load an existing agent identity from an identity directory.
    ///
    /// The directory must contain `private_key.pem`, `attestation.cbor`,
    /// `enrollment.cbor`, and `agent.json`.
    pub fn load(identity_dir: &Path) -> Result<Self> {
        let key_path = identity_dir.join("private_key.pem");
        let attestation_path = identity_dir.join("attestation.cbor");
        let enrollment_path = identity_dir.join("enrollment.cbor");
        let meta_path = identity_dir.join("agent.json");

        // Load private key
        let pem_bytes = std::fs::read(&key_path)
            .map_err(|e| ApiError::Other(format!("failed to read {}: {e}", key_path.display())))?;
        let signing_key = parse_ed25519_pem(&pem_bytes)?;
        let verifying_key = signing_key.verifying_key();

        // Load attestation
        let att_bytes = std::fs::read(&attestation_path)
            .map_err(|e| ApiError::Other(format!("failed to read {}: {e}", attestation_path.display())))?;
        let attestation: MembershipAttestation = serde_ipld_dagcbor::from_slice(&att_bytes)
            .map_err(|e| ApiError::Other(format!("failed to decode attestation: {e}")))?;

        // Load enrollment
        let enr_bytes = std::fs::read(&enrollment_path)
            .map_err(|e| ApiError::Other(format!("failed to read {}: {e}", enrollment_path.display())))?;
        let enrollment: AgentEnrollment = serde_ipld_dagcbor::from_slice(&enr_bytes)
            .map_err(|e| ApiError::Other(format!("failed to decode enrollment: {e}")))?;

        // Load metadata
        let meta_bytes = std::fs::read(&meta_path)
            .map_err(|e| ApiError::Other(format!("failed to read {}: {e}", meta_path.display())))?;
        let meta: AgentMeta = serde_json::from_slice(&meta_bytes)
            .map_err(|e| ApiError::Other(format!("failed to decode agent.json: {e}")))?;

        let cluster_id_bytes = hex::decode(&meta.cluster_id)
            .map_err(|e| ApiError::Other(format!("invalid cluster_id hex: {e}")))?;
        let cluster_id = ClusterId(cluster_id_bytes.try_into()
            .map_err(|_| ApiError::Other("cluster_id must be 32 bytes".into()))?);

        Ok(Self {
            agent_id: AgentId(meta.agent_id),
            signing_key,
            verifying_key,
            attestation,
            enrollment,
            cluster_id,
        })
    }

    /// Generate a new agent identity via local enrollment (daemon-side).
    ///
    /// This creates the keypair, enrollment, and attestation without needing
    /// a network round-trip — the caller holds the admin signing key and can
    /// issue everything locally.
    pub fn generate_local(
        identity_dir: &Path,
        agent_id: &str,
        cluster_id: &ClusterId,
        admin_peer_id: &PeerId,
        admin_signing_key: &SigningKey,
        role: Role,
        ttl_ns: u64,
    ) -> Result<Self> {
        std::fs::create_dir_all(identity_dir)
            .map_err(|e| ApiError::Other(format!("failed to create identity dir: {e}")))?;

        // Generate agent keypair
        let mut secret = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut secret);
        let signing_key = SigningKey::from_bytes(&secret);
        let verifying_key = signing_key.verifying_key();

        let now_ns = memvault_core::time::wall_ns();
        let not_after_ns = now_ns + ttl_ns;

        let agent_peer_id = PeerId(verifying_key.as_bytes().to_vec());

        // Create AgentEnrollment signed by admin
        let enrollment = sign_enrollment(
            agent_id,
            &verifying_key,
            cluster_id,
            admin_peer_id,
            admin_signing_key,
            not_after_ns,
        )?;

        // Create MembershipAttestation signed by admin
        let attestation = sign_attestation(
            cluster_id,
            &agent_peer_id,
            role,
            not_after_ns,
            AttestationOrigin::Direct,
            admin_signing_key,
        )?;

        // Write to disk
        write_identity_dir(identity_dir, &signing_key, &attestation, &enrollment, &AgentMeta {
            agent_id: agent_id.to_string(),
            cluster_id: hex::encode(cluster_id.0),
            enrolled_at_ns: now_ns,
        })?;

        Ok(Self {
            agent_id: AgentId(agent_id.to_string()),
            signing_key,
            verifying_key,
            attestation,
            enrollment,
            cluster_id: cluster_id.clone(),
        })
    }

    /// Check if an identity directory already has a valid identity.
    pub fn exists(identity_dir: &Path) -> bool {
        identity_dir.join("private_key.pem").exists()
            && identity_dir.join("attestation.cbor").exists()
            && identity_dir.join("enrollment.cbor").exists()
            && identity_dir.join("agent.json").exists()
    }

    /// Load if exists, otherwise generate locally.
    pub fn ensure(
        identity_dir: &Path,
        agent_id: &str,
        cluster_id: &ClusterId,
        admin_peer_id: &PeerId,
        admin_signing_key: &SigningKey,
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
                admin_peer_id,
                admin_signing_key,
                role,
                ttl_ns,
            )
        }
    }

    /// The peer ID derived from this agent's public key.
    pub fn peer_id(&self) -> PeerId {
        PeerId(self.verifying_key.as_bytes().to_vec())
    }
}

/// Sign an AgentEnrollment with the admin key.
fn sign_enrollment(
    agent_id: &str,
    agent_public_key: &VerifyingKey,
    cluster_id: &ClusterId,
    enrolled_by: &PeerId,
    admin_key: &SigningKey,
    not_after_ns: u64,
) -> Result<AgentEnrollment> {
    let enrollment = AgentEnrollment {
        agent_id: AgentId(agent_id.to_string()),
        public_key: *agent_public_key.as_bytes(),
        cluster_id: cluster_id.clone(),
        enrolled_by: enrolled_by.clone(),
        initial_grants: vec![],
        not_after_ns,
        signature: [0u8; 64], // placeholder, filled below
    };

    let signing_bytes = enrollment.signing_bytes()
        .map_err(|e| ApiError::Other(format!("enrollment signing bytes: {e}")))?;
    let sig = admin_key.sign(&signing_bytes);

    Ok(AgentEnrollment {
        signature: sig.to_bytes(),
        ..enrollment
    })
}

/// Sign a MembershipAttestation with the admin key.
fn sign_attestation(
    cluster_id: &ClusterId,
    member: &PeerId,
    role: Role,
    not_after_ns: u64,
    issued_via: AttestationOrigin,
    admin_key: &SigningKey,
) -> Result<MembershipAttestation> {
    let attestation = MembershipAttestation {
        cluster_id: cluster_id.clone(),
        member: member.clone(),
        role,
        not_after_ns,
        issued_via,
        signature: [0u8; 64], // placeholder, filled below
    };

    let signing_bytes = attestation.signing_bytes()
        .map_err(|e| ApiError::Other(format!("attestation signing bytes: {e}")))?;
    let sig = admin_key.sign(&signing_bytes);

    Ok(MembershipAttestation {
        signature: sig.to_bytes(),
        ..attestation
    })
}

/// Write all identity files to disk.
fn write_identity_dir(
    dir: &Path,
    signing_key: &SigningKey,
    attestation: &MembershipAttestation,
    enrollment: &AgentEnrollment,
    meta: &AgentMeta,
) -> Result<()> {
    // Write private key as PEM
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

    // Write attestation
    let att_bytes = serde_ipld_dagcbor::to_vec(attestation)
        .map_err(|e| ApiError::Other(format!("failed to encode attestation: {e}")))?;
    std::fs::write(dir.join("attestation.cbor"), &att_bytes)
        .map_err(|e| ApiError::Other(format!("failed to write attestation.cbor: {e}")))?;

    // Write enrollment
    let enr_bytes = serde_ipld_dagcbor::to_vec(enrollment)
        .map_err(|e| ApiError::Other(format!("failed to encode enrollment: {e}")))?;
    std::fs::write(dir.join("enrollment.cbor"), &enr_bytes)
        .map_err(|e| ApiError::Other(format!("failed to write enrollment.cbor: {e}")))?;

    // Write metadata
    let meta_json = serde_json::to_string_pretty(meta)
        .map_err(|e| ApiError::Other(format!("failed to serialize agent.json: {e}")))?;
    std::fs::write(dir.join("agent.json"), meta_json.as_bytes())
        .map_err(|e| ApiError::Other(format!("failed to write agent.json: {e}")))?;

    Ok(())
}

/// Encode an Ed25519 signing key as a simplified PEM (just the raw seed).
/// Format: `-----BEGIN ED25519 PRIVATE KEY-----\n<base64(seed)>\n-----END ED25519 PRIVATE KEY-----`
fn encode_ed25519_pem(key: &SigningKey) -> String {
    use data_encoding::BASE64;
    let seed = key.to_bytes();
    let b64 = BASE64.encode(&seed);
    format!(
        "-----BEGIN ED25519 PRIVATE KEY-----\n{b64}\n-----END ED25519 PRIVATE KEY-----\n"
    )
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
    let seed_bytes = BASE64.decode(b64_line.as_bytes())
        .map_err(|e| ApiError::Other(format!("PEM base64 decode failed: {e}")))?;

    let seed: [u8; 32] = seed_bytes.try_into()
        .map_err(|_| ApiError::Other("PEM seed must be exactly 32 bytes".into()))?;

    Ok(SigningKey::from_bytes(&seed))
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
        not_after_ns: now_ns + ttl_ns,
        max_uses,
        nonce,
        label,
        signature: [0u8; 64], // placeholder
    };

    let signing_bytes = token.signing_bytes()
        .map_err(|e| ApiError::Other(format!("token signing bytes: {e}")))?;
    let sig = admin_key.sign(&signing_bytes);

    let token = JoinToken {
        signature: sig.to_bytes(),
        ..token
    };

    let encoded = encode_token_string(&token)
        .map_err(|e| ApiError::Other(format!("token encode: {e}")))?;

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

        // Generate
        let identity = AgentIdentity::generate_local(
            &identity_dir,
            "test-agent",
            &cluster_id,
            &admin_peer_id,
            &admin_sk,
            Role::AgentHost,
            86400_000_000_000, // 1 day in ns
        ).unwrap();

        assert_eq!(identity.agent_id.0, "test-agent");
        assert_eq!(identity.cluster_id, cluster_id);

        // Verify attestation signature
        identity.attestation.verify_signature(&admin_vk).unwrap();

        // Verify enrollment signature
        identity.enrollment.verify_signature(&admin_vk).unwrap();

        // Load from disk
        let loaded = AgentIdentity::load(&identity_dir).unwrap();
        assert_eq!(loaded.agent_id.0, "test-agent");
        assert_eq!(loaded.signing_key.to_bytes(), identity.signing_key.to_bytes());
    }

    #[test]
    fn test_ensure_idempotent() {
        let (admin_sk, admin_vk) = make_admin_key();
        let admin_peer_id = PeerId(admin_vk.as_bytes().to_vec());
        let cluster_id = ClusterId::random();

        let dir = tempfile::tempdir().unwrap();
        let identity_dir = dir.path().join("agent-ensure");

        // First call: generates
        let id1 = AgentIdentity::ensure(
            &identity_dir, "ensure-agent", &cluster_id,
            &admin_peer_id, &admin_sk, Role::AgentHost,
            86400_000_000_000,
        ).unwrap();

        // Second call: loads (same key)
        let id2 = AgentIdentity::ensure(
            &identity_dir, "ensure-agent", &cluster_id,
            &admin_peer_id, &admin_sk, Role::AgentHost,
            86400_000_000_000,
        ).unwrap();

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
        ).unwrap();

        // Verify signature
        token.verify_signature(&admin_vk).unwrap();

        // Verify encoded roundtrip
        assert!(encoded.starts_with("mvjoin1:"));
        let decoded = memvault_auth::decode_token_string(&encoded).unwrap();
        decoded.verify_signature(&admin_vk).unwrap();
        assert_eq!(decoded.label, Some("test-token".to_string()));
    }
}

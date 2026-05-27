//! Agent JWT — ed25519-signed bearer token issued by an agent for itself.
//!
//! The token carries the agent's [`AgentAttestation`] inline (in the `att`
//! claim). The agent attestation is signed by a *node*, and the node's own
//! [`NodeAttestation`] (admin-signed) lives in the cluster's sig-chain.
//! Verification flow:
//!
//! 1. Decode JWT header + payload.
//! 2. Pull `att` from payload, deserialize the [`AgentAttestation`].
//! 3. Verify the agent attestation's signature against its embedded `node_pubkey`.
//! 4. Look up the node's [`NodeAttestation`] via the caller-supplied
//!    closure (the sig-chain table).
//! 5. Verify that node attestation against the cluster admin's pubkey.
//! 6. Verify the JWT signature against `att.agent_pubkey`.
//! 7. Check `exp` is not in the past.
//!
//! Scopes use OAuth-style space-separated strings ("read write admin").
//!
//! `iss` carries the human-readable `agent_id` for display / audit only —
//! the security-relevant identity is `att.agent_pubkey`.

use base64::Engine;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};

use crate::agent_attestation::AgentAttestation;
use crate::node_attestation::NodeAttestation;
use crate::error::{AuthError, Result};

const ALG: &str = "EdDSA";
const TYP: &str = "JWT";

/// Standard scope strings.
pub mod scope {
    pub const READ: &str = "read";
    pub const WRITE: &str = "write";
    pub const ADMIN: &str = "admin";
}

/// Claims carried inside an agent JWT.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentTokenClaims {
    /// Issuer — agent_id string for display / audit (not authoritative;
    /// authoritative identity is `attestation.member`).
    pub iss: String,
    /// Subject — peer-id hex (= attestation.member, agent's ed25519 pubkey).
    pub sub: String,
    /// Expiration time, seconds since the unix epoch.
    pub exp: u64,
    /// Issued-at time, seconds since the unix epoch.
    pub iat: u64,
    /// Space-separated scopes (OAuth-style).
    pub scope: String,
    /// Base64-encoded CBOR of the agent's [`NodeAttestation`].
    pub att: String,
}

impl AgentTokenClaims {
    /// True if `scope` is present in the space-separated scope list.
    pub fn has_scope(&self, scope: &str) -> bool {
        self.scope.split_whitespace().any(|s| s == scope)
    }

    /// Decode the embedded agent attestation.
    pub fn agent_attestation(&self) -> Result<AgentAttestation> {
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(&self.att)
            .map_err(|e| AuthError::InvalidToken(format!("invalid att base64: {e}")))?;
        serde_ipld_dagcbor::from_slice(&bytes)
            .map_err(|e| AuthError::InvalidToken(format!("invalid attestation CBOR: {e}")))
    }
}

fn b64_url() -> base64::engine::general_purpose::GeneralPurpose {
    base64::engine::general_purpose::URL_SAFE_NO_PAD
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Issue a JWT signed by `signing_key` (the agent's private key), embedding
/// the agent's node-issued [`AgentAttestation`].
///
/// `attestation.agent_pubkey` MUST match `signing_key.verifying_key()`.
/// Caller chooses scopes and `ttl_secs`.
pub fn issue(
    signing_key: &SigningKey,
    attestation: &AgentAttestation,
    scope: &str,
    ttl_secs: u64,
) -> Result<String> {
    let now = now_secs();
    let att_bytes = serde_ipld_dagcbor::to_vec(attestation)
        .map_err(|e| AuthError::InvalidToken(format!("encode attestation: {e}")))?;
    let claims = AgentTokenClaims {
        iss: attestation.agent_id.0.clone(),
        sub: hex::encode(attestation.agent_pubkey),
        iat: now,
        exp: now + ttl_secs,
        scope: scope.to_string(),
        att: base64::engine::general_purpose::STANDARD.encode(att_bytes),
    };

    let header = serde_json::to_vec(&serde_json::json!({ "alg": ALG, "typ": TYP }))
        .map_err(|e| AuthError::InvalidToken(format!("header encode: {e}")))?;
    let payload = serde_json::to_vec(&claims)
        .map_err(|e| AuthError::InvalidToken(format!("claims encode: {e}")))?;

    let b64 = b64_url();
    let header_b64 = b64.encode(&header);
    let payload_b64 = b64.encode(&payload);
    let signing_input = format!("{header_b64}.{payload_b64}");
    let signature = signing_key.sign(signing_input.as_bytes());
    let sig_b64 = b64.encode(signature.to_bytes());

    Ok(format!("{signing_input}.{sig_b64}"))
}

/// What the lookup callback returns for a given node pubkey.
///
/// `PreGenesis` covers the local-node trust seed before cluster genesis:
/// no admin key exists yet, so the node attestation can't chain to admin.
/// In that mode `admin_pubkey` must also be `None`; the verifier skips the
/// admin chain check but still validates the agent attestation + JWT
/// signature.
#[derive(Debug, Clone)]
pub enum NodeTrust {
    /// Admin-signed attestation. Verifier confirms against `admin_pubkey`.
    Attested(NodeAttestation),
    /// Pre-genesis trust seed. The node is trusted because it's local
    /// (or otherwise pre-configured); no admin chain check.
    PreGenesis,
}

/// Verify a JWT.
///
/// `admin_pubkey`:
/// - `Some` post-genesis — the cluster's admin verifying key. Must be present
///   if the lookup returns [`NodeTrust::Attested`].
/// - `None` pre-genesis — only [`NodeTrust::PreGenesis`] entries verify.
///
/// `lookup_node` returns the node's trust record from the in-memory table.
/// Returning `None` rejects the token.
///
/// Trust chain checked (when `Attested`):
/// agent JWT sig → agent pubkey → AgentAttestation sig → node pubkey →
/// NodeAttestation sig → admin pubkey.
///
/// Pre-genesis: agent JWT sig → agent pubkey → AgentAttestation sig → node
/// pubkey (trusted because the lookup said so). No admin step.
///
/// `exp` is always enforced.
pub fn verify<F>(
    token: &str,
    admin_pubkey: Option<&VerifyingKey>,
    lookup_node: F,
) -> Result<AgentTokenClaims>
where
    F: FnOnce(&[u8; 32]) -> Option<NodeTrust>,
{
    let b64 = b64_url();

    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return Err(AuthError::InvalidToken(
            "expected 3 dot-separated parts".into(),
        ));
    }
    let header_bytes = b64
        .decode(parts[0])
        .map_err(|e| AuthError::InvalidToken(format!("header b64: {e}")))?;
    let payload_bytes = b64
        .decode(parts[1])
        .map_err(|e| AuthError::InvalidToken(format!("payload b64: {e}")))?;
    let sig_bytes = b64
        .decode(parts[2])
        .map_err(|e| AuthError::InvalidToken(format!("signature b64: {e}")))?;

    // Header alg check.
    let header: serde_json::Value = serde_json::from_slice(&header_bytes)
        .map_err(|e| AuthError::InvalidToken(format!("header json: {e}")))?;
    if header.get("alg").and_then(|v| v.as_str()) != Some(ALG) {
        return Err(AuthError::InvalidToken(format!("unsupported alg: {header}")));
    }

    let claims: AgentTokenClaims = serde_json::from_slice(&payload_bytes)
        .map_err(|e| AuthError::InvalidToken(format!("claims json: {e}")))?;

    // Decode the agent attestation embedded in the JWT.
    let agent_att = claims.agent_attestation()?;

    // Bind: sub must match the agent pubkey claimed by the attestation.
    if claims.sub != hex::encode(agent_att.agent_pubkey) {
        return Err(AuthError::InvalidToken(
            "sub does not match agent_attestation.agent_pubkey".into(),
        ));
    }
    if claims.iss != agent_att.agent_id.0 {
        return Err(AuthError::InvalidToken(
            "iss does not match agent_attestation.agent_id".into(),
        ));
    }

    // Look up the node's trust record. The lookup table is the source of truth
    // for which node_pubkeys are trusted in this cluster (or in pre-genesis,
    // which nodes are trusted as local seeds).
    let trust = lookup_node(&agent_att.node_pubkey).ok_or_else(|| {
        AuthError::InvalidToken(format!(
            "unknown issuing node: {}",
            hex::encode(agent_att.node_pubkey)
        ))
    })?;
    match trust {
        NodeTrust::Attested(node_att) => {
            let admin_pk = admin_pubkey.ok_or_else(|| {
                AuthError::InvalidToken(
                    "no admin pubkey configured but node has an admin-signed attestation".into(),
                )
            })?;
            node_att
                .verify_signature(admin_pk)
                .map_err(|e| AuthError::InvalidToken(format!("node attestation: {e}")))?;
            if node_att.member.0 != agent_att.node_pubkey.as_slice() {
                return Err(AuthError::InvalidToken(
                    "node_pubkey mismatch between agent attestation and looked-up node attestation"
                        .into(),
                ));
            }
        }
        NodeTrust::PreGenesis => {
            // Pre-genesis: no admin chain check. The agent attestation
            // verification below still confirms the agent was issued by the
            // claimed node, and the node was deemed trustworthy by the lookup.
            if admin_pubkey.is_some() {
                return Err(AuthError::InvalidToken(
                    "PreGenesis trust returned but admin_pubkey is configured — \
                     lookup table is stale; re-issue node attestation post-genesis"
                        .into(),
                ));
            }
        }
    }

    // Verify the agent attestation against the (now-trusted) node pubkey.
    agent_att
        .verify_signature()
        .map_err(|e| AuthError::InvalidToken(format!("agent attestation: {e}")))?;

    // Finally: verify the JWT signature against the agent pubkey.
    let agent_pubkey = VerifyingKey::from_bytes(&agent_att.agent_pubkey)
        .map_err(|e| AuthError::InvalidToken(format!("agent pubkey: {e}")))?;
    let signing_input = format!("{}.{}", parts[0], parts[1]);
    let sig_arr: [u8; 64] = sig_bytes
        .as_slice()
        .try_into()
        .map_err(|_| AuthError::InvalidToken("signature must be 64 bytes".into()))?;
    let signature = Signature::from_bytes(&sig_arr);
    agent_pubkey
        .verify(signing_input.as_bytes(), &signature)
        .map_err(|e| AuthError::InvalidToken(format!("signature: {e}")))?;

    // Expiry.
    if claims.exp < now_secs() {
        return Err(AuthError::InvalidToken("token expired".into()));
    }

    Ok(claims)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent_attestation::sign_agent_attestation;
    use crate::node_attestation::AttestationOrigin;
    use crate::role::Role;
    use ed25519_dalek::SigningKey;
    use memvault_core::{AgentId, ClusterId, PeerId};
    use rand::RngCore;

    fn make_key() -> SigningKey {
        let mut seed = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut seed);
        SigningKey::from_bytes(&seed)
    }

    fn node_att(admin: &SigningKey, node: &SigningKey) -> NodeAttestation {
        let mut a = NodeAttestation {
            cluster_id: ClusterId([7u8; 32]),
            member: PeerId(node.verifying_key().to_bytes().to_vec()),
            role: Role::AgentHost,
            not_after_ns: u64::MAX,
            issued_via: AttestationOrigin::Direct,
            signature: [0u8; 64],
        };
        a.signature = admin.sign(&a.signing_bytes().unwrap()).to_bytes();
        a
    }

    fn build_token(scope: &str, ttl: u64) -> (String, VerifyingKey, NodeAttestation) {
        let admin = make_key();
        let node = make_key();
        let agent = make_key();
        let n_att = node_att(&admin, &node);
        let a_att = sign_agent_attestation(
            &node,
            AgentId("alice".into()),
            agent.verifying_key().to_bytes(),
            Role::AgentHost,
            u64::MAX,
        )
        .unwrap();
        let tok = issue(&agent, &a_att, scope, ttl).unwrap();
        (tok, admin.verifying_key(), n_att)
    }

    #[test]
    fn roundtrip_valid_token() {
        let (tok, admin_pk, n_att) = build_token("read write", 300);
        let claims = verify(&tok, Some(&admin_pk), |_| {
            Some(NodeTrust::Attested(n_att.clone()))
        })
        .unwrap();
        assert_eq!(claims.iss, "alice");
        assert!(claims.has_scope("read"));
        assert!(claims.has_scope("write"));
        assert!(!claims.has_scope("admin"));
    }

    #[test]
    fn pre_genesis_token_works_without_admin() {
        // Pre-genesis: same key acts as both "admin" and "node"; admin_pubkey is None.
        let key = make_key();
        let agent = make_key();
        let a_att = sign_agent_attestation(
            &key,
            AgentId("alice".into()),
            agent.verifying_key().to_bytes(),
            Role::AgentHost,
            u64::MAX,
        )
        .unwrap();
        let tok = issue(&agent, &a_att, "read", 300).unwrap();
        let claims = verify(&tok, None, |_| Some(NodeTrust::PreGenesis)).unwrap();
        assert_eq!(claims.iss, "alice");
    }

    #[test]
    fn rejects_pre_genesis_with_admin_configured() {
        // Stale lookup: returns PreGenesis but admin_pubkey is Some.
        let (tok, admin_pk, _) = build_token("read", 300);
        assert!(verify(&tok, Some(&admin_pk), |_| Some(NodeTrust::PreGenesis)).is_err());
    }

    #[test]
    fn rejects_attested_without_admin_pubkey() {
        let (tok, _, n_att) = build_token("read", 300);
        // No admin_pubkey but lookup returns Attested → reject.
        assert!(verify(&tok, None, |_| Some(NodeTrust::Attested(n_att.clone()))).is_err());
    }

    #[test]
    fn rejects_unknown_node() {
        let (tok, admin_pk, _) = build_token("read", 300);
        assert!(verify(&tok, Some(&admin_pk), |_| None).is_err());
    }

    #[test]
    fn rejects_wrong_admin_key() {
        let (tok, _, n_att) = build_token("read", 300);
        let other_admin = make_key();
        assert!(
            verify(&tok, Some(&other_admin.verifying_key()), |_| Some(
                NodeTrust::Attested(n_att.clone())
            ))
            .is_err()
        );
    }

    #[test]
    fn rejects_tampered_payload() {
        let (tok, admin_pk, n_att) = build_token("read", 300);
        let parts: Vec<&str> = tok.split('.').collect();
        let new_payload = b64_url().encode(
            br#"{"iss":"alice","sub":"00","exp":99999999999,"iat":0,"scope":"admin","att":""}"#,
        );
        let tampered = format!("{}.{}.{}", parts[0], new_payload, parts[2]);
        assert!(
            verify(&tampered, Some(&admin_pk), |_| Some(NodeTrust::Attested(
                n_att.clone()
            )))
            .is_err()
        );
    }

    #[test]
    fn rejects_expired() {
        let (tok, admin_pk, n_att) = build_token("read", 0);
        std::thread::sleep(std::time::Duration::from_secs(2));
        let err = verify(&tok, Some(&admin_pk), |_| {
            Some(NodeTrust::Attested(n_att.clone()))
        })
        .unwrap_err();
        assert!(format!("{err}").contains("expired"), "got: {err}");
    }

}

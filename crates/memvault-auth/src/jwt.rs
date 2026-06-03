//! Agent JWT — ed25519-signed bearer token issued by an agent for itself.
//!
//! The token carries only its claims (`iss`, `sub`, `exp`, `iat`, `scope`)
//! plus the agent's signature. The agent's [`AgentAttestation`] is NOT
//! embedded — the verifier looks it up by `sub` (agent pubkey) in its
//! local sigchain. Same security guarantees, ~200 bytes smaller per
//! token, no duplication between identity-dir state and chain state.
//!
//! Verification flow:
//!
//! 1. Decode JWT header + payload.
//! 2. Parse `sub` as the agent's 32-byte ed25519 pubkey.
//! 3. Verify the JWT signature against `sub`. Fast reject on tampering.
//! 4. Look up the [`AgentAttestation`] for that pubkey via the
//!    caller-supplied closure (typically backed by
//!    `sigchain::find_agent_attestation`).
//! 5. Verify the agent attestation's signature against its embedded
//!    `node_pubkey`.
//! 6. Look up the node's [`NodeAttestation`] via the second closure.
//! 7. Verify that node attestation against the cluster admin's pubkey
//!    (or accept `PreGenesis` when no admin is configured).
//! 8. Check `exp` is not in the past.
//!
//! Scopes use OAuth-style space-separated strings ("read write admin").
//!
//! `iss` carries the human-readable `agent_id` for display / audit only —
//! the security-relevant identity is `sub`.

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
    /// authoritative identity is `sub`).
    pub iss: String,
    /// Subject — agent's ed25519 pubkey, hex-encoded. This IS the
    /// authoritative identity. Verifier looks up the matching
    /// `AgentAttestation` from its local sigchain.
    pub sub: String,
    /// Expiration time, seconds since the unix epoch.
    pub exp: u64,
    /// Issued-at time, seconds since the unix epoch.
    pub iat: u64,
    /// Space-separated scopes (OAuth-style).
    pub scope: String,
}

impl AgentTokenClaims {
    /// True if `scope` is present in the space-separated scope list.
    pub fn has_scope(&self, scope: &str) -> bool {
        self.scope.split_whitespace().any(|s| s == scope)
    }

    /// Parse `sub` as a 32-byte ed25519 pubkey.
    pub fn agent_pubkey(&self) -> Result<[u8; 32]> {
        let bytes = hex::decode(&self.sub)
            .map_err(|e| AuthError::InvalidToken(format!("sub hex: {e}")))?;
        bytes
            .try_into()
            .map_err(|_| AuthError::InvalidToken("sub must decode to 32 bytes".into()))
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

fn now_ns() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0)
}

/// Issue a JWT signed by `signing_key` (the agent's private key).
///
/// The verifier will look up the agent's [`AgentAttestation`] from its
/// local sigchain by `sub` — no attestation embed needed in the token.
/// `agent_id` is a human-readable label carried in `iss` (display /
/// audit only; not authoritative).
pub fn issue(
    signing_key: &SigningKey,
    agent_id: &str,
    scope: &str,
    ttl_secs: u64,
) -> Result<String> {
    let now = now_secs();
    let claims = AgentTokenClaims {
        iss: agent_id.to_string(),
        sub: hex::encode(signing_key.verifying_key().to_bytes()),
        iat: now,
        exp: now + ttl_secs,
        scope: scope.to_string(),
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
/// `lookup_agent` returns the `AgentAttestation` for the given agent
/// pubkey (parsed from `sub`). Typically backed by a sigchain index
/// scan; returning `None` rejects the token.
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
pub fn verify<FA, FN>(
    token: &str,
    admin_keys: &[VerifyingKey],
    lookup_agent: FA,
    lookup_node: FN,
) -> Result<AgentTokenClaims>
where
    FA: FnOnce(&[u8; 32]) -> Option<AgentAttestation>,
    FN: FnOnce(&[u8; 32]) -> Option<NodeTrust>,
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

    let mut claims: AgentTokenClaims = serde_json::from_slice(&payload_bytes)
        .map_err(|e| AuthError::InvalidToken(format!("claims json: {e}")))?;

    // Parse the agent pubkey from `sub`.
    let agent_pubkey_bytes = claims.agent_pubkey()?;

    // Verify the JWT signature first — cheap fast-reject on tampering,
    // and we want to authenticate the agent before any sigchain lookup.
    let agent_pubkey = VerifyingKey::from_bytes(&agent_pubkey_bytes)
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

    // Look up the AgentAttestation by pubkey in the local sigchain.
    let agent_att = lookup_agent(&agent_pubkey_bytes).ok_or_else(|| {
        AuthError::InvalidToken(format!(
            "unknown agent: {} — attestation not yet synced",
            claims.sub
        ))
    })?;

    // Bind: agent pubkey must match (defensive; lookup contract should
    // already guarantee this).
    if agent_att.agent_pubkey != agent_pubkey_bytes {
        return Err(AuthError::InvalidToken(
            "lookup returned attestation for a different pubkey".into(),
        ));
    }
    // `iss` is a display LABEL, not an identity. The authoritative identity
    // is `sub` (the agent pubkey), verified above against the token
    // signature, and the attestation — looked up by that pubkey — carries
    // the canonical `agent_id`. A forger cannot fake the token without the
    // agent's private key regardless of `iss`, so enforcing `iss ==
    // agent_id` added no security; it only 401'd a legitimate key-holder
    // whose client-side `iss` was stale (e.g. a renamed/copied identity
    // dir, whose basename drives `AgentIdentity`'s agent_id). Instead of
    // rejecting, adopt the on-chain agent_id as the authoritative `iss` so
    // downstream display/audit always shows the canonical name.
    claims.iss = agent_att.agent_id.0.clone();

    // Verify the agent attestation's signature against its embedded
    // `node_pubkey` (a node-signed promise to admit this agent).
    agent_att
        .verify_signature()
        .map_err(|e| AuthError::InvalidToken(format!("agent attestation: {e}")))?;

    // Enforce attestation expiry at request time. A time-boxed agent
    // attestation must stop authorizing once it lapses (daemon-managed
    // identities use not_after_ns = u64::MAX, so they are unaffected).
    let now = now_ns();
    agent_att
        .verify_not_expired(now)
        .map_err(|e| AuthError::InvalidToken(format!("agent attestation: {e}")))?;

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
            if admin_keys.is_empty() {
                return Err(AuthError::InvalidToken(
                    "no admin pubkey configured but node has an admin-signed attestation".into(),
                ));
            }
            // Multi-admin: the attestation is valid if ANY currently-known
            // cluster admin key verifies it. Node attestations carry no
            // issue timestamp, so we accept against the full admin set
            // (availability over time-windowing — a retired admin's prior
            // attestations stay valid, matching the grant model; compromise
            // response is node revocation, not key retirement alone).
            let ok = admin_keys
                .iter()
                .any(|k| node_att.verify_signature(k).is_ok());
            if !ok {
                return Err(AuthError::InvalidToken(
                    "node attestation: no configured admin key verifies the signature".into(),
                ));
            }
            if node_att.member.0 != agent_att.node_pubkey.as_slice() {
                return Err(AuthError::InvalidToken(
                    "node_pubkey mismatch between agent attestation and looked-up node attestation"
                        .into(),
                ));
            }
            // Enforce node attestation expiry at request time.
            node_att
                .verify_not_expired(now)
                .map_err(|e| AuthError::InvalidToken(format!("node attestation: {e}")))?;
        }
        NodeTrust::PreGenesis => {
            if !admin_keys.is_empty() {
                return Err(AuthError::InvalidToken(
                    "PreGenesis trust returned but admin keys are configured — \
                     lookup table is stale; re-issue node attestation post-genesis"
                        .into(),
                ));
            }
        }
    }

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
    use crate::role::AgentRole;
    use ed25519_dalek::SigningKey;
    use memvault_core::{AgentName, ClusterId, PeerId};
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
            not_after_ns: u64::MAX,
            issued_via: AttestationOrigin::Direct,
            signature: [0u8; 64],
        };
        a.signature = admin.sign(&a.signing_bytes().unwrap()).to_bytes();
        a
    }

    fn build_token(
        scope: &str,
        ttl: u64,
    ) -> (String, VerifyingKey, NodeAttestation, AgentAttestation) {
        let admin = make_key();
        let node = make_key();
        let agent = make_key();
        let n_att = node_att(&admin, &node);
        let a_att = sign_agent_attestation(
            &node,
            AgentName("alice".into()),
            agent.verifying_key().to_bytes(),
            AgentRole::AgentHost,
            u64::MAX,
        )
        .unwrap();
        let tok = issue(&agent, "alice", scope, ttl).unwrap();
        (tok, admin.verifying_key(), n_att, a_att)
    }

    #[test]
    fn rejects_expired_agent_attestation() {
        let admin = make_key();
        let node = make_key();
        let agent = make_key();
        let n_att = node_att(&admin, &node);
        // Agent attestation that expired long ago (not_after_ns = 1).
        let a_att = sign_agent_attestation(
            &node,
            AgentName("alice".into()),
            agent.verifying_key().to_bytes(),
            AgentRole::AgentHost,
            1,
        )
        .unwrap();
        let tok = issue(&agent, "alice", "read", 300).unwrap();
        let err = verify(
            &tok,
            &[admin.verifying_key()],
            |_| Some(a_att.clone()),
            |_| Some(NodeTrust::Attested(n_att.clone())),
        );
        assert!(err.is_err(), "expired agent attestation must be rejected");
    }

    #[test]
    fn rejects_expired_node_attestation() {
        let admin = make_key();
        let node = make_key();
        let agent = make_key();
        // Node attestation expired (not_after_ns = 1).
        let mut n_att = NodeAttestation {
            cluster_id: ClusterId([7u8; 32]),
            member: PeerId(node.verifying_key().to_bytes().to_vec()),
            not_after_ns: 1,
            issued_via: AttestationOrigin::Direct,
            signature: [0u8; 64],
        };
        n_att.signature = admin.sign(&n_att.signing_bytes().unwrap()).to_bytes();
        let a_att = sign_agent_attestation(
            &node,
            AgentName("alice".into()),
            agent.verifying_key().to_bytes(),
            AgentRole::AgentHost,
            u64::MAX,
        )
        .unwrap();
        let tok = issue(&agent, "alice", "read", 300).unwrap();
        let err = verify(
            &tok,
            &[admin.verifying_key()],
            |_| Some(a_att.clone()),
            |_| Some(NodeTrust::Attested(n_att.clone())),
        );
        assert!(err.is_err(), "expired node attestation must be rejected");
    }

    #[test]
    fn roundtrip_valid_token() {
        let (tok, admin_pk, n_att, a_att) = build_token("read write", 300);
        let claims = verify(
            &tok,
            &[admin_pk],
            |_| Some(a_att.clone()),
            |_| Some(NodeTrust::Attested(n_att.clone())),
        )
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
            AgentName("alice".into()),
            agent.verifying_key().to_bytes(),
            AgentRole::AgentHost,
            u64::MAX,
        )
        .unwrap();
        let tok = issue(&agent, "alice", "read", 300).unwrap();
        let claims = verify(
            &tok,
            &[],
            |_| Some(a_att.clone()),
            |_| Some(NodeTrust::PreGenesis),
        )
        .unwrap();
        assert_eq!(claims.iss, "alice");
    }

    /// A token whose `iss` differs from the attestation's `agent_id` (e.g.
    /// a renamed/copied identity dir) must still verify — `sub` (pubkey) is
    /// the identity — and the returned claims adopt the on-chain agent_id.
    #[test]
    fn iss_mismatch_is_tolerated_and_canonicalized() {
        let admin = make_key();
        let node = make_key();
        let agent = make_key();
        let n_att = node_att(&admin, &node);
        // On-chain attestation says the agent is "alice".
        let a_att = sign_agent_attestation(
            &node,
            AgentName("alice".into()),
            agent.verifying_key().to_bytes(),
            AgentRole::AgentHost,
            u64::MAX,
        )
        .unwrap();
        // But the client mints a token claiming iss="stale-dir-name".
        let tok = issue(&agent, "stale-dir-name", "read", 300).unwrap();
        let claims = verify(
            &tok,
            &[admin.verifying_key()],
            |_| Some(a_att.clone()),
            |_| Some(NodeTrust::Attested(n_att.clone())),
        )
        .expect("iss mismatch must not reject a signature-valid token");
        assert_eq!(claims.iss, "alice", "iss canonicalized to on-chain agent_id");
    }

    #[test]
    fn rejects_pre_genesis_with_admin_configured() {
        let (tok, admin_pk, _, a_att) = build_token("read", 300);
        assert!(
            verify(
                &tok,
                &[admin_pk],
                |_| Some(a_att.clone()),
                |_| Some(NodeTrust::PreGenesis),
            )
            .is_err()
        );
    }

    #[test]
    fn rejects_attested_without_admin_pubkey() {
        let (tok, _, n_att, a_att) = build_token("read", 300);
        assert!(
            verify(
                &tok,
                &[],
                |_| Some(a_att.clone()),
                |_| Some(NodeTrust::Attested(n_att.clone())),
            )
            .is_err()
        );
    }

    #[test]
    fn rejects_unknown_agent() {
        let (tok, admin_pk, _, _) = build_token("read", 300);
        assert!(
            verify(&tok, &[admin_pk], |_| None, |_| None).is_err()
        );
    }

    #[test]
    fn rejects_unknown_node() {
        let (tok, admin_pk, _, a_att) = build_token("read", 300);
        assert!(
            verify(&tok, &[admin_pk], |_| Some(a_att.clone()), |_| None)
                .is_err()
        );
    }

    #[test]
    fn rejects_wrong_admin_key() {
        let (tok, _, n_att, a_att) = build_token("read", 300);
        let other_admin = make_key();
        assert!(
            verify(
                &tok,
                &[other_admin.verifying_key()],
                |_| Some(a_att.clone()),
                |_| Some(NodeTrust::Attested(n_att.clone())),
            )
            .is_err()
        );
    }

    #[test]
    fn rejects_tampered_payload() {
        let (tok, admin_pk, n_att, a_att) = build_token("read", 300);
        let parts: Vec<&str> = tok.split('.').collect();
        let new_payload = b64_url().encode(
            br#"{"iss":"alice","sub":"00","exp":99999999999,"iat":0,"scope":"admin"}"#,
        );
        let tampered = format!("{}.{}.{}", parts[0], new_payload, parts[2]);
        assert!(
            verify(
                &tampered,
                &[admin_pk],
                |_| Some(a_att.clone()),
                |_| Some(NodeTrust::Attested(n_att.clone())),
            )
            .is_err()
        );
    }

    #[test]
    fn rejects_expired() {
        let (tok, admin_pk, n_att, a_att) = build_token("read", 0);
        std::thread::sleep(std::time::Duration::from_secs(2));
        let err = verify(
            &tok,
            &[admin_pk],
            |_| Some(a_att.clone()),
            |_| Some(NodeTrust::Attested(n_att.clone())),
        )
        .unwrap_err();
        assert!(format!("{err}").contains("expired"), "got: {err}");
    }
}

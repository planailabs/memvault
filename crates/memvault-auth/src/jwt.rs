//! Agent JWT — ed25519-signed bearer token issued by an agent for itself.
//!
//! The token carries the agent's [`MembershipAttestation`] inline (in the `att`
//! claim) so the server can validate the agent without any state lookup:
//!
//! 1. Decode JWT header + payload.
//! 2. Pull `att` from payload, deserialize the attestation.
//! 3. Verify the attestation's signature against the cluster admin's pubkey.
//! 4. Extract the agent's pubkey from the (now-trusted) attestation.member.
//! 5. Verify the JWT signature against the agent's pubkey.
//! 6. Check `exp` is not in the past.
//!
//! Scopes use OAuth-style space-separated strings ("read write admin").
//!
//! `iss` carries the human-readable `agent_id` for display / audit only —
//! the security-relevant identity is the attestation's `member` (peer-id).

use base64::Engine;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};

use crate::attestation::MembershipAttestation;
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
    /// Base64-encoded CBOR of the agent's [`MembershipAttestation`].
    pub att: String,
}

impl AgentTokenClaims {
    /// True if `scope` is present in the space-separated scope list.
    pub fn has_scope(&self, scope: &str) -> bool {
        self.scope.split_whitespace().any(|s| s == scope)
    }

    /// Decode the embedded attestation.
    pub fn attestation(&self) -> Result<MembershipAttestation> {
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

/// Issue a JWT signed by `signing_key`, embedding `attestation`.
///
/// `agent_id` is for display only; the security identity is in `attestation.member`.
/// Caller chooses scopes and `ttl_secs`.
pub fn issue(
    signing_key: &SigningKey,
    attestation: &MembershipAttestation,
    agent_id: &str,
    scope: &str,
    ttl_secs: u64,
) -> Result<String> {
    let now = now_secs();
    let att_bytes = serde_ipld_dagcbor::to_vec(attestation)
        .map_err(|e| AuthError::InvalidToken(format!("encode attestation: {e}")))?;
    let claims = AgentTokenClaims {
        iss: agent_id.to_string(),
        sub: hex::encode(&attestation.member.0),
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

/// Verify a JWT against the cluster admin's verifying key.
///
/// Performs the full chain: attestation-trust → agent-key-trust → JWT signature
/// → expiry. Returns the verified claims on success.
pub fn verify(token: &str, admin_pubkey: &VerifyingKey) -> Result<AgentTokenClaims> {
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

    // Trust chain: admin → attestation → agent pubkey → JWT signature.
    let attestation = claims.attestation()?;
    attestation
        .verify_signature(admin_pubkey)
        .map_err(|e| AuthError::InvalidToken(format!("attestation: {e}")))?;
    // `sub` must agree with attestation.member (claim displays bind correctly).
    let member_hex = hex::encode(&attestation.member.0);
    if claims.sub != member_hex {
        return Err(AuthError::InvalidToken(
            "sub does not match attestation.member".into(),
        ));
    }
    if attestation.member.0.len() != 32 {
        return Err(AuthError::InvalidToken(
            "attestation.member is not a 32-byte ed25519 key".into(),
        ));
    }
    let mut pub_arr = [0u8; 32];
    pub_arr.copy_from_slice(&attestation.member.0);
    let agent_pubkey = VerifyingKey::from_bytes(&pub_arr)
        .map_err(|e| AuthError::InvalidToken(format!("attestation pubkey: {e}")))?;

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
    use crate::attestation::AttestationOrigin;
    use crate::role::Role;
    use ed25519_dalek::SigningKey;
    use memvault_core::{ClusterId, PeerId};
    use rand::RngCore;

    fn make_keys() -> (SigningKey, SigningKey) {
        let mut admin_seed = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut admin_seed);
        let mut agent_seed = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut agent_seed);
        (
            SigningKey::from_bytes(&admin_seed),
            SigningKey::from_bytes(&agent_seed),
        )
    }

    fn make_attestation(admin: &SigningKey, agent: &SigningKey) -> MembershipAttestation {
        let agent_pub = agent.verifying_key();
        let mut att = MembershipAttestation {
            cluster_id: ClusterId([7u8; 32]),
            member: PeerId(agent_pub.as_bytes().to_vec()),
            role: Role::AgentHost,
            not_after_ns: u64::MAX,
            issued_via: AttestationOrigin::Direct,
            signature: [0u8; 64],
        };
        let signing_bytes = att.signing_bytes().unwrap();
        let sig = admin.sign(&signing_bytes);
        att.signature = sig.to_bytes();
        att
    }

    #[test]
    fn roundtrip_valid_token() {
        let (admin, agent) = make_keys();
        let att = make_attestation(&admin, &agent);
        let token = issue(&agent, &att, "alice", "read write", 300).unwrap();
        let claims = verify(&token, &admin.verifying_key()).unwrap();
        assert_eq!(claims.iss, "alice");
        assert!(claims.has_scope("read"));
        assert!(claims.has_scope("write"));
        assert!(!claims.has_scope("admin"));
    }

    #[test]
    fn rejects_wrong_admin_key() {
        let (admin, agent) = make_keys();
        let att = make_attestation(&admin, &agent);
        let token = issue(&agent, &att, "alice", "read", 300).unwrap();
        let (other_admin, _) = make_keys();
        assert!(verify(&token, &other_admin.verifying_key()).is_err());
    }

    #[test]
    fn rejects_tampered_payload() {
        let (admin, agent) = make_keys();
        let att = make_attestation(&admin, &agent);
        let token = issue(&agent, &att, "alice", "read", 300).unwrap();
        let parts: Vec<&str> = token.split('.').collect();
        // Swap in payload with elevated scope, keep original signature.
        let new_payload = b64_url().encode(
            br#"{"iss":"alice","sub":"00","exp":99999999999,"iat":0,"scope":"admin","att":""}"#,
        );
        let tampered = format!("{}.{}.{}", parts[0], new_payload, parts[2]);
        assert!(verify(&tampered, &admin.verifying_key()).is_err());
    }

    #[test]
    fn rejects_expired() {
        let (admin, agent) = make_keys();
        let att = make_attestation(&admin, &agent);
        // ttl=0 so the token's exp is "now", which is treated as expired.
        let token = issue(&agent, &att, "alice", "read", 0).unwrap();
        // sleep 1s to push past exp
        std::thread::sleep(std::time::Duration::from_secs(2));
        let err = verify(&token, &admin.verifying_key()).unwrap_err();
        assert!(format!("{err}").contains("expired"), "got: {err}");
    }
}

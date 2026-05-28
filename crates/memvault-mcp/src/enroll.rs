//! `plan-ai-memvault enroll` — exchange an agent token with a remote
//! memvault server for a full agent credential and persist it locally.
//!
//! Workflow (mirrors the in-tree `memctl agent-enroll`, except that
//! enrollment goes through an HTTP endpoint instead of touching the
//! local block store):
//!   1. Generate a fresh ed25519 keypair locally — the private key
//!      never crosses the wire.
//!   2. POST `{ token, agent_id, public_key }` to the remote server's
//!      `/api/v1/auth/enroll-agent` endpoint.
//!   3. Verify the returned attestation signature so a malicious
//!      endpoint can't poison the identity dir.
//!   4. Persist the signing key + attestation + metadata under the
//!      standard memvault identity directory layout via
//!      `memvault_api::agent_identity::write_identity_dir`. Subsequent
//!      MCP server runs pick up the credential by setting
//!      `MEMVAULT_AGENT_ID=<agent_id>`.

use std::path::PathBuf;

use anyhow::{Context, Result, anyhow};
use clap::Args;

#[derive(Args, Debug)]
pub struct EnrollArgs {
    /// Base URL of the remote memvault server, e.g. `https://node.example`.
    #[arg(long)]
    pub server: String,
    /// Agent / join token issued by the cluster (mvjoin1:…).
    #[arg(long)]
    pub token: String,
    /// Agent identifier (e.g. "openclaw", "hermes").
    #[arg(long)]
    pub agent_id: String,
    /// Identity directory (default: `<data-dir>/agents/<agent-id>/`).
    #[arg(long)]
    pub identity_dir: Option<PathBuf>,
    /// Base data directory (default: platform `data_local_dir/memvault`).
    #[arg(long, env = "MEMVAULT_DATA_DIR")]
    pub data_dir: Option<PathBuf>,
}

pub async fn run(args: EnrollArgs) -> Result<()> {
    let data_dir = args.data_dir.unwrap_or_else(|| {
        dirs::data_local_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("memvault")
    });
    let identity_dir = args
        .identity_dir
        .unwrap_or_else(|| data_dir.join("agents").join(&args.agent_id));

    if memvault_api::agent_identity::AgentIdentity::exists(&identity_dir) {
        println!(
            "Agent identity already exists at {}",
            identity_dir.display()
        );
        println!("To re-enroll, remove the directory first.");
        return Ok(());
    }

    // Local keypair — private key never leaves this host.
    let mut agent_seed = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut agent_seed);
    let agent_sk = ed25519_dalek::SigningKey::from_bytes(&agent_seed);
    let agent_pubkey = agent_sk.verifying_key().to_bytes();

    let url = format!(
        "{}/api/v1/auth/enroll-agent",
        args.server.trim_end_matches('/')
    );
    let body = serde_json::json!({
        "token": args.token,
        "agent_id": args.agent_id,
        "public_key": hex::encode(agent_pubkey),
    });

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .context("build http client")?;
    let resp = client
        .post(&url)
        .json(&body)
        .send()
        .await
        .with_context(|| format!("POST {url}"))?;
    let status = resp.status();
    if !status.is_success() {
        let detail = resp.text().await.unwrap_or_default();
        return Err(anyhow!("enroll endpoint returned {status}: {detail}"));
    }
    let parsed: serde_json::Value = resp
        .json()
        .await
        .context("parse enroll response as JSON")?;

    let att_hex = parsed
        .get("attestation_cbor_hex")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            anyhow!(
                "server omitted attestation_cbor_hex — upgrade the server before remote \
                 enrollment can persist a local identity"
            )
        })?;
    let att_bytes =
        hex::decode(att_hex).context("decode attestation_cbor_hex from response")?;
    let attestation: memvault_auth::AgentAttestation =
        serde_ipld_dagcbor::from_slice(&att_bytes).context("decode attestation CBOR")?;

    // Defense in depth: verify the attestation locally so a hostile or
    // misconfigured endpoint can't poison the identity directory with
    // an unsigned (or differently-signed) credential.
    attestation
        .verify_signature()
        .map_err(|e| anyhow!("attestation signature did not verify: {e}"))?;
    if attestation.agent_pubkey != agent_pubkey {
        return Err(anyhow!(
            "attestation agent_pubkey does not match locally generated key"
        ));
    }
    if attestation.agent_id.0 != args.agent_id {
        return Err(anyhow!(
            "attestation agent_id ({:?}) does not match requested agent_id ({:?})",
            attestation.agent_id.0,
            args.agent_id
        ));
    }

    let att_cid = parsed
        .get("attestation_cid")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    std::fs::create_dir_all(&identity_dir)?;
    memvault_api::agent_identity::write_identity_dir(&identity_dir, &agent_sk)
        .map_err(|e| anyhow!("write identity dir: {e}"))?;
    let _ = attestation; // attestation lives on the sigchain, not the disk
    println!("Agent enrolled.");
    println!("  Agent ID:     {}", args.agent_id);
    println!("  Server:       {}", args.server);
    println!("  Identity dir: {}", identity_dir.display());
    println!("  Public key:   {}", hex::encode(agent_pubkey));
    println!("  Attestation:  {att_cid}");

    Ok(())
}

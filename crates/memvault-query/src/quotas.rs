//! Quota management for memvault agents.

use std::collections::HashMap;

use memvault_core::AgentId;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Quota exceeded error.
#[derive(Debug, Error)]
#[error("quota exceeded for agent {agent_id}: {detail}")]
pub struct QuotaExceeded {
    pub agent_id: String,
    pub detail: String,
}

/// Per-agent quota configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentQuota {
    pub max_docs: u64,
    pub max_bytes: u64,
    pub max_entities: u64,
}

impl Default for AgentQuota {
    fn default() -> Self {
        Self {
            max_docs: 10_000,
            max_bytes: 1_073_741_824, // 1 GiB
            max_entities: 100_000,
        }
    }
}

/// Tracks per-agent and per-bucket usage against configured quotas.
pub struct QuotaManager {
    quotas: HashMap<String, AgentQuota>,
    usage: HashMap<String, AgentUsage>,
    default_quota: AgentQuota,
    /// Per-bucket quotas (added B8). Keyed by hex-encoded bucket_id.
    bucket_quotas: HashMap<String, BucketQuota>,
    /// Per-bucket usage tracking (added B8). Keyed by hex-encoded bucket_id.
    bucket_usage: HashMap<String, BucketUsage>,
}

#[derive(Debug, Clone, Default)]
struct AgentUsage {
    doc_count: u64,
    byte_count: u64,
    entity_count: u64,
}

impl QuotaManager {
    pub fn new(default_quota: AgentQuota) -> Self {
        Self {
            quotas: HashMap::new(),
            usage: HashMap::new(),
            default_quota,
            bucket_quotas: HashMap::new(),
            bucket_usage: HashMap::new(),
        }
    }

    /// Set a specific quota for an agent.
    pub fn set_quota(&mut self, agent_id: &AgentId, quota: AgentQuota) {
        self.quotas.insert(agent_id.0.clone(), quota);
    }

    /// Check if a write of `bytes` size is allowed for the agent.
    pub fn check_write(&self, agent_id: &AgentId, bytes: u64) -> Result<(), QuotaExceeded> {
        let quota = self.quotas.get(&agent_id.0).unwrap_or(&self.default_quota);
        let usage = self.usage.get(&agent_id.0);
        let current_bytes = usage.map(|u| u.byte_count).unwrap_or(0);

        if current_bytes + bytes > quota.max_bytes {
            return Err(QuotaExceeded {
                agent_id: agent_id.0.clone(),
                detail: format!(
                    "byte limit exceeded: {} + {} > {}",
                    current_bytes, bytes, quota.max_bytes
                ),
            });
        }
        Ok(())
    }

    /// Check if creating a new doc is allowed for the agent.
    pub fn check_doc_create(&self, agent_id: &AgentId) -> Result<(), QuotaExceeded> {
        let quota = self.quotas.get(&agent_id.0).unwrap_or(&self.default_quota);
        let usage = self.usage.get(&agent_id.0);
        let current_docs = usage.map(|u| u.doc_count).unwrap_or(0);

        if current_docs >= quota.max_docs {
            return Err(QuotaExceeded {
                agent_id: agent_id.0.clone(),
                detail: format!("doc limit reached: {} >= {}", current_docs, quota.max_docs),
            });
        }
        Ok(())
    }

    /// Check if creating a new entity is allowed for the agent.
    pub fn check_entity_create(&self, agent_id: &AgentId) -> Result<(), QuotaExceeded> {
        let quota = self.quotas.get(&agent_id.0).unwrap_or(&self.default_quota);
        let usage = self.usage.get(&agent_id.0);
        let current = usage.map(|u| u.entity_count).unwrap_or(0);

        if current >= quota.max_entities {
            return Err(QuotaExceeded {
                agent_id: agent_id.0.clone(),
                detail: format!(
                    "entity limit reached: {} >= {}",
                    current, quota.max_entities
                ),
            });
        }
        Ok(())
    }

    /// Record that a doc was created by an agent.
    pub fn record_doc_create(&mut self, agent_id: &AgentId, bytes: u64) {
        let usage = self.usage.entry(agent_id.0.clone()).or_default();
        usage.doc_count += 1;
        usage.byte_count += bytes;
    }

    /// Record that bytes were written by an agent.
    pub fn record_write(&mut self, agent_id: &AgentId, bytes: u64) {
        let usage = self.usage.entry(agent_id.0.clone()).or_default();
        usage.byte_count += bytes;
    }

    /// Record that an entity was created by an agent.
    pub fn record_entity_create(&mut self, agent_id: &AgentId) {
        let usage = self.usage.entry(agent_id.0.clone()).or_default();
        usage.entity_count += 1;
    }
}

impl Default for QuotaManager {
    fn default() -> Self {
        Self::new(AgentQuota::default())
    }
}

// ── Per-bucket quotas (added B8) ─────────────────────────────────

/// Per-bucket quota configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BucketQuota {
    /// Maximum total bytes stored in this bucket.
    pub max_bytes: u64,
    /// Maximum number of envelopes in this bucket.
    pub max_envelopes: u64,
}

impl Default for BucketQuota {
    fn default() -> Self {
        Self {
            max_bytes: 10_737_418_240, // 10 GiB
            max_envelopes: 1_000_000,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct BucketUsage {
    pub byte_count: u64,
    pub envelope_count: u64,
}

impl QuotaManager {
    /// Set a quota for a specific bucket.
    pub fn set_bucket_quota(&mut self, bucket_id: &str, quota: BucketQuota) {
        self.bucket_quotas.insert(bucket_id.to_string(), quota);
    }

    /// Check if a write to a bucket is allowed.
    pub fn check_bucket_write(&self, bucket_id: &str, bytes: u64) -> Result<(), QuotaExceeded> {
        let quota = match self.bucket_quotas.get(bucket_id) {
            Some(q) => q,
            None => return Ok(()), // no quota set = unlimited
        };
        let usage = self.bucket_usage.get(bucket_id);
        let current_bytes = usage.map(|u| u.byte_count).unwrap_or(0);

        if current_bytes + bytes > quota.max_bytes {
            return Err(QuotaExceeded {
                agent_id: format!("bucket:{bucket_id}"),
                detail: format!(
                    "bucket byte limit exceeded: {} + {} > {}",
                    current_bytes, bytes, quota.max_bytes
                ),
            });
        }

        let current_envelopes = usage.map(|u| u.envelope_count).unwrap_or(0);
        if current_envelopes >= quota.max_envelopes {
            return Err(QuotaExceeded {
                agent_id: format!("bucket:{bucket_id}"),
                detail: format!(
                    "bucket envelope limit reached: {} >= {}",
                    current_envelopes, quota.max_envelopes
                ),
            });
        }

        Ok(())
    }

    /// Record a write to a bucket.
    pub fn record_bucket_write(&mut self, bucket_id: &str, bytes: u64) {
        let usage = self.bucket_usage.entry(bucket_id.to_string()).or_default();
        usage.byte_count += bytes;
        usage.envelope_count += 1;
    }

    /// Get the current usage for a bucket.
    pub fn get_bucket_usage(&self, bucket_id: &str) -> BucketUsage {
        self.bucket_usage
            .get(bucket_id)
            .cloned()
            .unwrap_or_default()
    }
}

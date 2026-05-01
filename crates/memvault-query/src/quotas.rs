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

/// Tracks per-agent usage against configured quotas.
pub struct QuotaManager {
    quotas: HashMap<String, AgentQuota>,
    usage: HashMap<String, AgentUsage>,
    default_quota: AgentQuota,
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
        }
    }

    /// Set a specific quota for an agent.
    pub fn set_quota(&mut self, agent_id: &AgentId, quota: AgentQuota) {
        self.quotas.insert(agent_id.0.clone(), quota);
    }

    /// Check if a write of `bytes` size is allowed for the agent.
    pub fn check_write(&self, agent_id: &AgentId, bytes: u64) -> Result<(), QuotaExceeded> {
        let quota = self
            .quotas
            .get(&agent_id.0)
            .unwrap_or(&self.default_quota);
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
        let quota = self
            .quotas
            .get(&agent_id.0)
            .unwrap_or(&self.default_quota);
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
        let quota = self
            .quotas
            .get(&agent_id.0)
            .unwrap_or(&self.default_quota);
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

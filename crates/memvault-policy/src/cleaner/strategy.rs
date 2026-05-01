use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use crate::pii::findings::PiiKind;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum RedactionStrategy {
    /// Replace with [REDACTED]
    Mask,
    /// Remove entirely
    Drop,
    /// Replace with blake3 hash of the original
    Hash,
    /// Replace with a stable token (same PII -> same token within a session)
    Tokenize,
    /// Replace with a specific string
    Replace(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RedactionPolicy {
    pub by_kind: BTreeMap<PiiKind, RedactionStrategy>,
    pub default: RedactionStrategy,
}

impl RedactionPolicy {
    /// Default policy: Mask for all PII kinds.
    pub fn default_policy() -> Self {
        Self {
            by_kind: BTreeMap::new(),
            default: RedactionStrategy::Mask,
        }
    }

    /// Strict policy: Drop for high-risk (SSN, credit card), Mask for others.
    pub fn strict() -> Self {
        let mut by_kind = BTreeMap::new();
        by_kind.insert(PiiKind::Ssn, RedactionStrategy::Drop);
        by_kind.insert(PiiKind::CreditCard, RedactionStrategy::Drop);
        Self {
            by_kind,
            default: RedactionStrategy::Mask,
        }
    }

    /// Get the strategy for a specific PII kind.
    pub fn strategy_for(&self, kind: &PiiKind) -> &RedactionStrategy {
        self.by_kind.get(kind).unwrap_or(&self.default)
    }
}

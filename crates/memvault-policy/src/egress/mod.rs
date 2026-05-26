pub mod decision;
pub mod destination;

use std::collections::BTreeMap;

use decision::EgressDecision;
use destination::{EgressDestination, EgressKind};

use crate::classification::{CLASSIFICATION_LEVELS, classification_allows};
use crate::cleaner::strategy::RedactionPolicy;
use crate::pii::PiiDetector;

/// Egress policy definition.
#[derive(Debug, Clone)]
pub struct EgressPolicy {
    /// Destinations that are always allowed regardless of classification.
    pub allowed_destinations: Vec<EgressKind>,
    /// Classification levels that can be sent to any destination.
    pub unrestricted_classifications: Vec<String>,
    /// Maximum classification level for each destination kind.
    pub max_classification: BTreeMap<EgressKind, String>,
    /// Whether PII detected in content blocks egress to cloud LLMs.
    pub block_pii_to_cloud_llm: bool,
    /// Whether PII detected blocks egress to third parties.
    pub block_pii_to_third_party: bool,
}

impl EgressPolicy {
    pub fn default_policy() -> Self {
        let mut max_classification = BTreeMap::new();
        max_classification.insert(EgressKind::CloudLlm, "internal".to_string());
        max_classification.insert(EgressKind::Backup, "confidential".to_string());
        max_classification.insert(EgressKind::AgentHost, "internal".to_string());
        max_classification.insert(EgressKind::ThirdParty, "public".to_string());
        max_classification.insert(EgressKind::PublicShare, "public".to_string());

        Self {
            allowed_destinations: vec![EgressKind::Backup],
            unrestricted_classifications: vec!["public".to_string()],
            max_classification,
            block_pii_to_cloud_llm: true,
            block_pii_to_third_party: true,
        }
    }

    /// Check whether a piece of content can be sent to a destination.
    pub fn check_egress(
        &self,
        text: &str,
        classification: &str,
        destination: &EgressDestination,
        detector: &dyn PiiDetector,
    ) -> EgressDecision {
        // If classification is unrestricted, allow to anything
        if self
            .unrestricted_classifications
            .iter()
            .any(|c| c == classification)
        {
            return EgressDecision::Allow;
        }

        // If destination kind is always allowed
        if self.allowed_destinations.contains(&destination.kind) {
            return EgressDecision::Allow;
        }

        // Check classification level against max allowed
        if let Some(max_allowed) = self.max_classification.get(&destination.kind) {
            if !classification_allows(classification, max_allowed) {
                return EgressDecision::Deny {
                    reasons: vec![format!(
                        "classification '{}' exceeds maximum '{}' for destination kind {:?}",
                        classification, max_allowed, destination.kind
                    )],
                };
            }
        } else {
            // No entry means unknown destination kind, check if it's in CLASSIFICATION_LEVELS
            if !CLASSIFICATION_LEVELS.contains(&classification) {
                return EgressDecision::Deny {
                    reasons: vec![format!("unknown classification level: {}", classification)],
                };
            }
        }

        // Check PII
        let should_check_pii = (self.block_pii_to_cloud_llm
            && destination.kind == EgressKind::CloudLlm)
            || (self.block_pii_to_third_party && destination.kind == EgressKind::ThirdParty);

        if should_check_pii {
            let findings = detector.detect(text);
            if !findings.is_empty() {
                return EgressDecision::AllowWithRedaction {
                    suggested_policy: RedactionPolicy::default_policy(),
                    blocking_findings: findings,
                };
            }
        }

        EgressDecision::Allow
    }
}

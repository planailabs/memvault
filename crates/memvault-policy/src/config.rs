//! TOML-based policy configuration loader.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::egress::EgressPolicy;
use crate::egress::destination::EgressKind;
use crate::error::PolicyError;

/// Top-level policy configuration loaded from TOML.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyConfig {
    pub egress: EgressPolicyConfig,
    pub classification: ClassificationConfig,
    pub pii: PiiConfig,
}

/// Egress policy configuration section.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EgressPolicyConfig {
    pub block_pii_to_cloud_llm: bool,
    pub block_pii_to_third_party: bool,
    pub allowed_destinations: Vec<String>,
    pub max_classification: BTreeMap<String, String>,
}

/// Classification configuration section.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClassificationConfig {
    /// Levels ordered from least to most sensitive.
    pub levels: Vec<String>,
    pub default_level: String,
}

/// PII detection configuration section.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PiiConfig {
    pub enabled: bool,
    pub custom_patterns: Vec<CustomPatternConfig>,
    /// Default redaction strategy: "mask", "drop", "hash", "tokenize".
    pub default_strategy: String,
}

/// A custom PII pattern definition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustomPatternConfig {
    pub name: String,
    pub pattern: String,
    pub kind: String,
    pub confidence: f32,
}

impl PolicyConfig {
    /// Parse a TOML string into a PolicyConfig.
    pub fn from_toml(toml_str: &str) -> Result<Self, PolicyError> {
        toml::from_str(toml_str).map_err(|e| PolicyError::Config(format!("TOML parse error: {e}")))
    }

    /// Return a default configuration.
    pub fn default_config() -> Self {
        Self {
            egress: EgressPolicyConfig {
                block_pii_to_cloud_llm: true,
                block_pii_to_third_party: true,
                allowed_destinations: vec!["backup".to_string()],
                max_classification: {
                    let mut m = BTreeMap::new();
                    m.insert("cloud_llm".to_string(), "internal".to_string());
                    m.insert("backup".to_string(), "confidential".to_string());
                    m.insert("agent_host".to_string(), "internal".to_string());
                    m.insert("third_party".to_string(), "public".to_string());
                    m.insert("public_share".to_string(), "public".to_string());
                    m
                },
            },
            classification: ClassificationConfig {
                levels: vec![
                    "public".to_string(),
                    "internal".to_string(),
                    "confidential".to_string(),
                ],
                default_level: "internal".to_string(),
            },
            pii: PiiConfig {
                enabled: true,
                custom_patterns: vec![],
                default_strategy: "mask".to_string(),
            },
        }
    }

    /// Build an EgressPolicy from this configuration.
    pub fn to_egress_policy(&self) -> Result<EgressPolicy, PolicyError> {
        let allowed_destinations = self
            .egress
            .allowed_destinations
            .iter()
            .map(|s| parse_egress_kind(s))
            .collect::<Result<Vec<_>, _>>()?;

        let max_classification = self
            .egress
            .max_classification
            .iter()
            .map(|(k, v)| Ok((parse_egress_kind(k)?, v.clone())))
            .collect::<Result<BTreeMap<EgressKind, String>, PolicyError>>()?;

        Ok(EgressPolicy {
            allowed_destinations,
            unrestricted_classifications: vec!["public".to_string()],
            max_classification,
            block_pii_to_cloud_llm: self.egress.block_pii_to_cloud_llm,
            block_pii_to_third_party: self.egress.block_pii_to_third_party,
        })
    }
}

fn parse_egress_kind(s: &str) -> Result<EgressKind, PolicyError> {
    match s {
        "cloud_llm" => Ok(EgressKind::CloudLlm),
        "backup" => Ok(EgressKind::Backup),
        "agent_host" => Ok(EgressKind::AgentHost),
        "third_party" => Ok(EgressKind::ThirdParty),
        "public_share" => Ok(EgressKind::PublicShare),
        other => Err(PolicyError::Config(format!("unknown egress kind: {other}"))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_TOML: &str = r#"
[egress]
block_pii_to_cloud_llm = true
block_pii_to_third_party = false
allowed_destinations = ["backup"]

[egress.max_classification]
cloud_llm = "internal"
backup = "confidential"
third_party = "public"

[classification]
levels = ["public", "internal", "confidential"]
default_level = "internal"

[pii]
enabled = true
default_strategy = "mask"
custom_patterns = []
"#;

    #[test]
    fn from_toml_roundtrip() {
        let config = PolicyConfig::from_toml(SAMPLE_TOML).unwrap();
        assert!(config.egress.block_pii_to_cloud_llm);
        assert!(!config.egress.block_pii_to_third_party);
        assert_eq!(config.classification.default_level, "internal");
        assert_eq!(config.pii.default_strategy, "mask");
    }

    #[test]
    fn default_config_is_valid() {
        let config = PolicyConfig::default_config();
        assert!(config.egress.block_pii_to_cloud_llm);
        assert_eq!(config.classification.levels.len(), 3);
        assert!(config.pii.enabled);
    }

    #[test]
    fn to_egress_policy_builds_correctly() {
        let config = PolicyConfig::from_toml(SAMPLE_TOML).unwrap();
        let policy = config.to_egress_policy().unwrap();
        assert!(policy.block_pii_to_cloud_llm);
        assert!(!policy.block_pii_to_third_party);
        assert_eq!(policy.allowed_destinations, vec![EgressKind::Backup]);
    }

    #[test]
    fn invalid_toml_returns_error() {
        let result = PolicyConfig::from_toml("not valid { toml");
        assert!(result.is_err());
    }

    #[test]
    fn unknown_egress_kind_returns_error() {
        let bad_toml = r#"
[egress]
block_pii_to_cloud_llm = true
block_pii_to_third_party = true
allowed_destinations = ["unknown_kind"]

[egress.max_classification]

[classification]
levels = ["public"]
default_level = "public"

[pii]
enabled = true
default_strategy = "mask"
custom_patterns = []
"#;
        let config = PolicyConfig::from_toml(bad_toml).unwrap();
        let result = config.to_egress_policy();
        assert!(result.is_err());
    }

    #[test]
    fn custom_patterns_parse() {
        let toml_str = r#"
[egress]
block_pii_to_cloud_llm = true
block_pii_to_third_party = true
allowed_destinations = []

[egress.max_classification]

[classification]
levels = ["public", "internal"]
default_level = "public"

[pii]
enabled = true
default_strategy = "hash"

[[pii.custom_patterns]]
name = "employee_id"
pattern = "EMP-\\d{6}"
kind = "employee_id"
confidence = 0.9
"#;
        let config = PolicyConfig::from_toml(toml_str).unwrap();
        assert_eq!(config.pii.custom_patterns.len(), 1);
        assert_eq!(config.pii.custom_patterns[0].name, "employee_id");
        assert_eq!(config.pii.custom_patterns[0].confidence, 0.9);
    }
}

pub mod classification;
pub mod cleaner;
pub mod config;
pub mod egress;
pub mod error;
pub mod pii;

pub use classification::{
    CLASSIFICATION_LEVELS, classification_allows, extract_classification, validate_classification,
};
pub use cleaner::report::{RedactionApplied, RedactionResult};
pub use cleaner::strategy::{RedactionPolicy, RedactionStrategy};
pub use cleaner::{DefaultCleaner, PiiCleaner};
pub use egress::EgressPolicy;
pub use egress::decision::EgressDecision;
pub use egress::destination::{EgressDestination, EgressKind};
pub use error::PolicyError;
pub use pii::findings::{Location, PiiFinding, PiiKind};
pub use pii::{PiiDetector, RegexDetector};

#[cfg(test)]
mod tests {
    use super::*;

    // === PII Detection Tests ===

    #[test]
    fn test_detect_email() {
        let detector = RegexDetector::new();
        let findings = detector.detect("Contact us at hello@example.com for info.");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].kind, PiiKind::Email);
        assert_eq!(findings[0].text, "hello@example.com");
    }

    #[test]
    fn test_detect_phone() {
        let detector = RegexDetector::new();
        let findings = detector.detect("Call me at (555) 123-4567 please.");
        assert!(findings.iter().any(|f| f.kind == PiiKind::Phone));
    }

    #[test]
    fn test_detect_ssn() {
        let detector = RegexDetector::new();
        let findings = detector.detect("SSN: 123-45-6789 is on file.");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].kind, PiiKind::Ssn);
        assert_eq!(findings[0].text, "123-45-6789");
    }

    #[test]
    fn test_detect_credit_card() {
        let detector = RegexDetector::new();
        let findings = detector.detect("Card number: 4111 1111 1111 1111 on file.");
        assert!(findings.iter().any(|f| f.kind == PiiKind::CreditCard));
    }

    #[test]
    fn test_detect_ip_address() {
        let detector = RegexDetector::new();
        let findings = detector.detect("Server at 192.168.1.100 is down.");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].kind, PiiKind::IpAddress);
        assert_eq!(findings[0].text, "192.168.1.100");
    }

    #[test]
    fn test_detect_iban() {
        let detector = RegexDetector::new();
        let findings = detector.detect("Wire to DE89370400440532013000 please.");
        assert!(findings.iter().any(|f| f.kind == PiiKind::Iban));
    }

    #[test]
    fn test_detect_dob() {
        let detector = RegexDetector::new();
        let findings = detector.detect("DOB: 1990-05-15 is recorded.");
        assert!(findings.iter().any(|f| f.kind == PiiKind::DateOfBirth));
    }

    #[test]
    fn test_no_false_positives() {
        let detector = RegexDetector::new();
        let findings = detector.detect(
            "The quick brown fox jumps over the lazy dog. This is normal text without any PII.",
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn test_no_false_positive_short_numbers() {
        let detector = RegexDetector::new();
        // Numbers that are too short for credit cards, not formatted as SSN/phone
        let findings = detector.detect("Order #12345 was shipped on day 7.");
        // Should not match as credit card (too short)
        assert!(!findings.iter().any(|f| f.kind == PiiKind::CreditCard));
    }

    // === Redaction Tests ===

    #[test]
    fn test_redact_mask() {
        let cleaner = DefaultCleaner::new();
        let policy = RedactionPolicy::default_policy();
        let result = cleaner.redact("Email: hello@example.com here.", &policy);
        assert_eq!(result.redacted_text, "Email: [REDACTED] here.");
        assert_eq!(result.applied.len(), 1);
        assert_eq!(result.applied[0].strategy, RedactionStrategy::Mask);
    }

    #[test]
    fn test_redact_drop() {
        let cleaner = DefaultCleaner::new();
        let policy = RedactionPolicy::strict();
        let result = cleaner.redact("SSN: 123-45-6789 end.", &policy);
        assert_eq!(result.redacted_text, "SSN:  end.");
        assert_eq!(result.applied[0].strategy, RedactionStrategy::Drop);
    }

    #[test]
    fn test_redact_hash() {
        let cleaner = DefaultCleaner::new();
        let mut policy = RedactionPolicy::default_policy();
        policy.default = RedactionStrategy::Hash;
        let result = cleaner.redact("Email: test@test.com done.", &policy);
        assert!(result.redacted_text.contains("[HASH:"));
        assert!(result.redacted_text.contains("]"));
        assert!(!result.redacted_text.contains("test@test.com"));
    }

    #[test]
    fn test_redact_tokenize_stability() {
        let cleaner = DefaultCleaner::new();
        let mut policy = RedactionPolicy::default_policy();
        policy.default = RedactionStrategy::Tokenize;

        let result1 = cleaner.redact("Email: same@email.com text.", &policy);
        let result2 = cleaner.redact("Another same@email.com mention.", &policy);

        // Same PII should get same token
        assert_eq!(
            result1.applied[0].replacement,
            result2.applied[0].replacement
        );
        assert!(result1.applied[0].replacement.starts_with("[TOKEN-"));
    }

    #[test]
    fn test_redact_replace() {
        let cleaner = DefaultCleaner::new();
        let mut policy = RedactionPolicy::default_policy();
        policy.default = RedactionStrategy::Replace("***".to_string());
        let result = cleaner.redact("IP: 10.0.0.1 seen.", &policy);
        assert_eq!(result.redacted_text, "IP: *** seen.");
    }

    #[test]
    fn test_redact_overlapping_findings() {
        // Test that overlapping findings are handled (longer match wins)
        let detector = RegexDetector::new();
        // This text has an SSN which also contains digit patterns
        let findings = detector.detect("123-45-6789");
        // Should detect as SSN
        assert!(findings.iter().any(|f| f.kind == PiiKind::Ssn));

        let cleaner = DefaultCleaner::new();
        let policy = RedactionPolicy::default_policy();
        let result = cleaner.redact("Data: 123-45-6789 end.", &policy);
        // Should not have double-redaction artifacts
        assert!(!result.redacted_text.contains("123-45-6789"));
    }

    // === Egress Tests ===

    #[test]
    fn test_egress_public_allows_anything() {
        let policy = EgressPolicy::default_policy();
        let detector = RegexDetector::new();
        let dest = EgressDestination {
            name: "cloud".into(),
            kind: EgressKind::CloudLlm,
            url: Some("https://api.openai.com".into()),
        };
        let decision = policy.check_egress("public content", "public", &dest, &detector);
        assert!(matches!(decision, EgressDecision::Allow));
    }

    #[test]
    fn test_egress_confidential_to_cloud_denied() {
        let policy = EgressPolicy::default_policy();
        let detector = RegexDetector::new();
        let dest = EgressDestination {
            name: "cloud".into(),
            kind: EgressKind::CloudLlm,
            url: Some("https://api.openai.com".into()),
        };
        let decision = policy.check_egress("secret stuff", "confidential", &dest, &detector);
        assert!(matches!(decision, EgressDecision::Deny { .. }));
    }

    #[test]
    fn test_egress_pii_to_cloud_requires_redaction() {
        let policy = EgressPolicy::default_policy();
        let detector = RegexDetector::new();
        let dest = EgressDestination {
            name: "cloud".into(),
            kind: EgressKind::CloudLlm,
            url: Some("https://api.openai.com".into()),
        };
        let decision = policy.check_egress(
            "User email is test@example.com",
            "internal",
            &dest,
            &detector,
        );
        assert!(matches!(
            decision,
            EgressDecision::AllowWithRedaction { .. }
        ));
    }

    #[test]
    fn test_egress_backup_always_allowed() {
        let policy = EgressPolicy::default_policy();
        let detector = RegexDetector::new();
        let dest = EgressDestination {
            name: "backup".into(),
            kind: EgressKind::Backup,
            url: None,
        };
        let decision = policy.check_egress(
            "SSN: 123-45-6789 confidential",
            "confidential",
            &dest,
            &detector,
        );
        assert!(matches!(decision, EgressDecision::Allow));
    }

    #[test]
    fn test_egress_internal_to_cloud_no_pii_allows() {
        let policy = EgressPolicy::default_policy();
        let detector = RegexDetector::new();
        let dest = EgressDestination {
            name: "cloud".into(),
            kind: EgressKind::CloudLlm,
            url: None,
        };
        let decision =
            policy.check_egress("just some internal notes", "internal", &dest, &detector);
        assert!(matches!(decision, EgressDecision::Allow));
    }

    // === Classification Tests ===

    #[test]
    fn test_classification_allows_same_level() {
        assert!(classification_allows("public", "public"));
        assert!(classification_allows("internal", "internal"));
        assert!(classification_allows("confidential", "confidential"));
    }

    #[test]
    fn test_classification_allows_lower_to_higher() {
        assert!(classification_allows("public", "internal"));
        assert!(classification_allows("public", "confidential"));
        assert!(classification_allows("internal", "confidential"));
    }

    #[test]
    fn test_classification_denies_higher_to_lower() {
        assert!(!classification_allows("confidential", "public"));
        assert!(!classification_allows("confidential", "internal"));
        assert!(!classification_allows("internal", "public"));
    }

    #[test]
    fn test_classification_unknown_levels() {
        assert!(!classification_allows("secret", "public"));
        assert!(!classification_allows("public", "unknown"));
    }

    #[test]
    fn test_extract_classification() {
        let tags = vec![
            ("author".to_string(), "alice".to_string()),
            ("classification".to_string(), "confidential".to_string()),
        ];
        assert_eq!(
            extract_classification(&tags),
            Some("confidential".to_string())
        );
    }

    #[test]
    fn test_extract_classification_missing() {
        let tags = vec![("author".to_string(), "alice".to_string())];
        assert_eq!(extract_classification(&tags), None);
    }

    #[test]
    fn test_validate_classification_public_with_pii() {
        let detector = RegexDetector::new();
        let warnings =
            validate_classification("Contact john@example.com for details", "public", &detector);
        assert!(!warnings.is_empty());
        assert!(warnings[0].contains("PII"));
    }

    #[test]
    fn test_validate_classification_public_no_pii() {
        let detector = RegexDetector::new();
        let warnings =
            validate_classification("This is just normal public text.", "public", &detector);
        assert!(warnings.is_empty());
    }

    #[test]
    fn test_validate_classification_confidential_no_warning() {
        let detector = RegexDetector::new();
        let warnings = validate_classification("SSN: 123-45-6789", "confidential", &detector);
        // Confidential classification is appropriate for PII, no warning
        assert!(warnings.is_empty());
    }
}

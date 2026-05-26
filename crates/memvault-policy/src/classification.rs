use crate::pii::PiiDetector;

/// Classification levels ordered by sensitivity (least to most).
pub const CLASSIFICATION_LEVELS: &[&str] = &["public", "internal", "confidential"];

/// Check if a classification level allows egress to a destination.
/// Returns true if content_level's sensitivity is <= max_allowed's sensitivity.
pub fn classification_allows(content_level: &str, max_allowed: &str) -> bool {
    let content_idx = CLASSIFICATION_LEVELS
        .iter()
        .position(|&l| l == content_level);
    let max_idx = CLASSIFICATION_LEVELS.iter().position(|&l| l == max_allowed);

    match (content_idx, max_idx) {
        (Some(c), Some(m)) => c <= m,
        _ => false, // unknown levels are not allowed
    }
}

/// Get classification from a set of tags.
pub fn extract_classification(tags: &[(String, String)]) -> Option<String> {
    tags.iter()
        .find(|(key, _)| key == "classification")
        .map(|(_, value)| value.clone())
}

/// Validate that content matches its claimed classification (heuristic).
/// Returns warnings if the content appears to be misclassified.
pub fn validate_classification(
    text: &str,
    claimed: &str,
    detector: &dyn PiiDetector,
) -> Vec<String> {
    let mut warnings = Vec::new();

    if claimed == "public" {
        let findings = detector.detect(text);
        if !findings.is_empty() {
            warnings.push(format!(
                "content classified as 'public' contains {} PII finding(s): consider upgrading to 'internal' or 'confidential'",
                findings.len()
            ));
            // List the kinds found
            let kinds: Vec<String> = findings
                .iter()
                .map(|f| format!("{:?}", f.kind))
                .collect::<std::collections::HashSet<_>>()
                .into_iter()
                .collect();
            warnings.push(format!("PII kinds detected: {}", kinds.join(", ")));
        }
    }

    warnings
}

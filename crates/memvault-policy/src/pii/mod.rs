pub mod findings;
pub mod patterns;

use findings::{Location, PiiFinding, PiiKind};
use patterns::PatternEntry;

use crate::error::PolicyError;

/// PII detector trait.
pub trait PiiDetector: Send + Sync {
    fn detect(&self, text: &str) -> Vec<PiiFinding>;
}

/// Default regex-based PII detector.
pub struct RegexDetector {
    patterns: Vec<PatternEntry>,
}

impl RegexDetector {
    /// Create a new detector with default patterns.
    pub fn new() -> Self {
        Self {
            patterns: patterns::default_patterns(),
        }
    }

    /// Create a detector with custom patterns.
    pub fn with_custom_patterns(
        custom: Vec<(PiiKind, &str, f32)>,
    ) -> Result<Self, PolicyError> {
        let mut patterns = Vec::new();
        for (kind, pattern, confidence) in custom {
            let regex = regex::Regex::new(pattern)?;
            patterns.push(PatternEntry {
                kind,
                regex,
                confidence,
                detector_name: "regex:custom".into(),
            });
        }
        Ok(Self { patterns })
    }
}

impl Default for RegexDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl PiiDetector for RegexDetector {
    fn detect(&self, text: &str) -> Vec<PiiFinding> {
        let mut findings = Vec::new();
        for entry in &self.patterns {
            for m in entry.regex.find_iter(text) {
                findings.push(PiiFinding {
                    kind: entry.kind.clone(),
                    location: Location {
                        byte_offset: m.start(),
                        byte_length: m.len(),
                    },
                    text: m.as_str().to_string(),
                    confidence: entry.confidence,
                    detector: entry.detector_name.clone(),
                });
            }
        }
        findings
    }
}

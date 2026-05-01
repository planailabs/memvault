pub mod report;
pub mod strategy;

use std::collections::BTreeMap;
use std::sync::Mutex;

use report::{RedactionApplied, RedactionResult};
use strategy::{RedactionPolicy, RedactionStrategy};

use crate::pii::findings::PiiFinding;
use crate::pii::{PiiDetector, RegexDetector};

/// PII cleaner trait.
pub trait PiiCleaner: Send + Sync {
    fn redact(&self, text: &str, policy: &RedactionPolicy) -> RedactionResult;
}

/// Default cleaner using RegexDetector.
pub struct DefaultCleaner {
    detector: RegexDetector,
    /// Token map for Tokenize strategy (PII text -> stable token).
    token_map: Mutex<BTreeMap<String, String>>,
    /// Session salt for tokenization.
    session_salt: [u8; 32],
}

impl DefaultCleaner {
    pub fn new() -> Self {
        let mut salt = [0u8; 32];
        use rand::RngCore;
        rand::thread_rng().fill_bytes(&mut salt);
        Self {
            detector: RegexDetector::new(),
            token_map: Mutex::new(BTreeMap::new()),
            session_salt: salt,
        }
    }

    fn apply_strategy(&self, text: &str, strategy: &RedactionStrategy) -> String {
        match strategy {
            RedactionStrategy::Mask => "[REDACTED]".to_string(),
            RedactionStrategy::Drop => String::new(),
            RedactionStrategy::Hash => {
                let hash = blake3::hash(text.as_bytes());
                let hex = hash.to_hex();
                format!("[HASH:{}]", &hex[..8])
            }
            RedactionStrategy::Tokenize => {
                let mut map = self.token_map.lock().unwrap();
                if let Some(token) = map.get(text) {
                    return token.clone();
                }
                // Generate stable token from PII text + session salt
                let mut hasher = blake3::Hasher::new();
                hasher.update(&self.session_salt);
                hasher.update(text.as_bytes());
                let hash = hasher.finalize();
                let hex = hash.to_hex();
                let token = format!("[TOKEN-{}]", &hex[..8]);
                map.insert(text.to_string(), token.clone());
                token
            }
            RedactionStrategy::Replace(replacement) => replacement.clone(),
        }
    }
}

impl Default for DefaultCleaner {
    fn default() -> Self {
        Self::new()
    }
}

impl PiiCleaner for DefaultCleaner {
    fn redact(&self, text: &str, policy: &RedactionPolicy) -> RedactionResult {
        let findings = self.detector.detect(text);

        if findings.is_empty() {
            return RedactionResult {
                redacted_text: text.to_string(),
                findings: Vec::new(),
                applied: Vec::new(),
            };
        }

        // Sort findings by byte_offset, longest first for overlaps
        let mut sorted_findings = findings.clone();
        sorted_findings.sort_by(|a, b| {
            a.location
                .byte_offset
                .cmp(&b.location.byte_offset)
                .then_with(|| b.location.byte_length.cmp(&a.location.byte_length))
        });

        // Remove overlapping findings (keep longest/first)
        let mut non_overlapping: Vec<PiiFinding> = Vec::new();
        for finding in sorted_findings {
            let dominated = non_overlapping.iter().any(|existing| {
                let e_start = existing.location.byte_offset;
                let e_end = e_start + existing.location.byte_length;
                let f_start = finding.location.byte_offset;
                let f_end = f_start + finding.location.byte_length;
                // finding is contained within existing
                f_start >= e_start && f_end <= e_end
            });
            if !dominated {
                // Also check if this finding overlaps and starts within an existing one
                let overlaps = non_overlapping.iter().any(|existing| {
                    let e_start = existing.location.byte_offset;
                    let e_end = e_start + existing.location.byte_length;
                    let f_start = finding.location.byte_offset;
                    f_start >= e_start && f_start < e_end
                });
                if !overlaps {
                    non_overlapping.push(finding);
                }
            }
        }

        // Apply redactions from end to start to preserve offsets
        let mut result = text.to_string();
        let mut applied = Vec::new();

        // Sort in reverse order by offset
        non_overlapping.sort_by(|a, b| b.location.byte_offset.cmp(&a.location.byte_offset));

        for finding in non_overlapping {
            let strategy = policy.strategy_for(&finding.kind);
            let replacement = self.apply_strategy(&finding.text, strategy);

            let start = finding.location.byte_offset;
            let end = start + finding.location.byte_length;
            result.replace_range(start..end, &replacement);

            applied.push(RedactionApplied {
                finding: finding.clone(),
                strategy: strategy.clone(),
                replacement,
            });
        }

        // Reverse applied to be in document order
        applied.reverse();

        RedactionResult {
            redacted_text: result,
            findings,
            applied,
        }
    }
}

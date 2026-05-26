use regex::Regex;

use super::findings::PiiKind;

pub struct PatternEntry {
    pub kind: PiiKind,
    pub regex: Regex,
    pub confidence: f32,
    pub detector_name: String,
}

/// Build the default set of PII detection patterns.
pub fn default_patterns() -> Vec<PatternEntry> {
    vec![
        PatternEntry {
            kind: PiiKind::Email,
            regex: Regex::new(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}").unwrap(),
            confidence: 0.95,
            detector_name: "regex:email".into(),
        },
        PatternEntry {
            kind: PiiKind::Phone,
            regex: Regex::new(r"(?:\+1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}").unwrap(),
            confidence: 0.80,
            detector_name: "regex:phone_us".into(),
        },
        PatternEntry {
            kind: PiiKind::Ssn,
            regex: Regex::new(r"\b\d{3}-\d{2}-\d{4}\b").unwrap(),
            confidence: 0.90,
            detector_name: "regex:ssn".into(),
        },
        PatternEntry {
            kind: PiiKind::CreditCard,
            regex: Regex::new(r"\b(?:\d[ \-]?){13,19}\b").unwrap(),
            confidence: 0.75,
            detector_name: "regex:credit_card".into(),
        },
        PatternEntry {
            kind: PiiKind::IpAddress,
            regex: Regex::new(
                r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b",
            )
            .unwrap(),
            confidence: 0.85,
            detector_name: "regex:ipv4".into(),
        },
        PatternEntry {
            kind: PiiKind::Iban,
            regex: Regex::new(r"\b[A-Z]{2}\d{2}[A-Z0-9]{4,30}\b").unwrap(),
            confidence: 0.80,
            detector_name: "regex:iban".into(),
        },
        PatternEntry {
            kind: PiiKind::DateOfBirth,
            regex: Regex::new(r"(?i)(?:dob|born|date of birth)[:\s]+\d{1,4}[-/]\d{1,2}[-/]\d{1,4}")
                .unwrap(),
            confidence: 0.85,
            detector_name: "regex:dob".into(),
        },
    ]
}

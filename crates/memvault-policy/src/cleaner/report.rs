use serde::{Deserialize, Serialize};

use crate::cleaner::strategy::RedactionStrategy;
use crate::pii::findings::PiiFinding;

/// Result of applying redaction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RedactionResult {
    pub redacted_text: String,
    pub findings: Vec<PiiFinding>,
    pub applied: Vec<RedactionApplied>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RedactionApplied {
    pub finding: PiiFinding,
    pub strategy: RedactionStrategy,
    pub replacement: String,
}

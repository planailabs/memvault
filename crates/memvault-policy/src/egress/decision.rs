use serde::{Deserialize, Serialize};

use crate::cleaner::strategy::RedactionPolicy;
use crate::pii::findings::PiiFinding;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EgressDecision {
    Allow,
    Deny {
        reasons: Vec<String>,
    },
    AllowWithRedaction {
        suggested_policy: RedactionPolicy,
        blocking_findings: Vec<PiiFinding>,
    },
}

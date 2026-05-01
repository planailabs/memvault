use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EgressDestination {
    pub name: String,
    pub kind: EgressKind,
    pub url: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum EgressKind {
    CloudLlm,
    Backup,
    AgentHost,
    ThirdParty,
    PublicShare,
}

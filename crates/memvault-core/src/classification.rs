use serde::{Deserialize, Serialize};

/// Classification levels for memvault data.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Classification {
    Public,
    Internal,
    Confidential,
}

impl Classification {
    /// Parse from the label portion of a `classification:` tag.
    pub fn from_label(s: &str) -> Option<Self> {
        match s {
            "public" => Some(Self::Public),
            "internal" => Some(Self::Internal),
            "confidential" => Some(Self::Confidential),
            _ => None,
        }
    }

    pub fn as_label(&self) -> &'static str {
        match self {
            Self::Public => "public",
            Self::Internal => "internal",
            Self::Confidential => "confidential",
        }
    }
}

impl std::fmt::Display for Classification {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_label())
    }
}

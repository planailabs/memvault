use serde::{Deserialize, Serialize};

/// A tag with scope and label, formatted as `scope:label`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Tag {
    pub scope: String,
    pub label: String,
}

impl Tag {
    pub fn new(scope: impl Into<String>, label: impl Into<String>) -> Self {
        Self {
            scope: scope.into(),
            label: label.into(),
        }
    }

    /// Parse from `scope:label` format.
    pub fn parse(s: &str) -> Option<Self> {
        let (scope, label) = s.split_once(':')?;
        if scope.is_empty() || label.is_empty() {
            return None;
        }
        Some(Self::new(scope, label))
    }
}

impl std::fmt::Display for Tag {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}", self.scope, self.label)
    }
}

/// A pattern for matching tags. The label supports glob patterns (*, ?).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TagPattern {
    pub scope: String,
    pub label: String,
}

impl TagPattern {
    pub fn new(scope: impl Into<String>, label: impl Into<String>) -> Self {
        Self {
            scope: scope.into(),
            label: label.into(),
        }
    }

    /// Check if a tag matches this pattern.
    pub fn matches(&self, tag: &Tag) -> bool {
        if self.scope != tag.scope {
            return false;
        }
        let pattern = glob::Pattern::new(&self.label).unwrap_or_else(|_| {
            // If pattern is invalid, try literal match
            glob::Pattern::new(&glob::Pattern::escape(&self.label)).unwrap()
        });
        pattern.matches(&tag.label)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tag_parse_roundtrip() {
        let tag = Tag::parse("classification:public").unwrap();
        assert_eq!(tag.scope, "classification");
        assert_eq!(tag.label, "public");
        assert_eq!(tag.to_string(), "classification:public");
    }

    #[test]
    fn tag_parse_invalid() {
        assert!(Tag::parse("nocolon").is_none());
        assert!(Tag::parse(":noscope").is_none());
        assert!(Tag::parse("nolabel:").is_none());
    }

    #[test]
    fn pattern_glob_matching() {
        let pattern = TagPattern::new("project", "memvault-*");
        assert!(pattern.matches(&Tag::new("project", "memvault-core")));
        assert!(pattern.matches(&Tag::new("project", "memvault-net")));
        assert!(!pattern.matches(&Tag::new("project", "other")));
        assert!(!pattern.matches(&Tag::new("other", "memvault-core")));
    }

    #[test]
    fn pattern_exact_match() {
        let pattern = TagPattern::new("classification", "public");
        assert!(pattern.matches(&Tag::new("classification", "public")));
        assert!(!pattern.matches(&Tag::new("classification", "internal")));
    }
}

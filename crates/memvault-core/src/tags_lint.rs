use crate::classification::Classification;
use crate::error::{Error, Result};
use crate::tags::Tag;

/// Lint a tag set, enforcing rules:
/// - Exactly one `classification:` tag is required.
/// - The classification label must be a valid Classification variant.
pub fn lint_tags(tags: &[Tag]) -> Result<Classification> {
    let classification_tags: Vec<&Tag> = tags
        .iter()
        .filter(|t| t.scope == "classification")
        .collect();

    match classification_tags.len() {
        0 => Err(Error::TagLint(
            "missing required classification tag".into(),
        )),
        1 => {
            let tag = classification_tags[0];
            Classification::from_label(&tag.label).ok_or_else(|| {
                Error::TagLint(format!(
                    "invalid classification label '{}', expected one of: public, internal, confidential",
                    tag.label
                ))
            })
        }
        n => Err(Error::TagLint(format!(
            "expected exactly one classification tag, found {n}"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_single_classification() {
        let tags = vec![
            Tag::new("classification", "internal"),
            Tag::new("project", "memvault"),
        ];
        assert_eq!(lint_tags(&tags).unwrap(), Classification::Internal);
    }

    #[test]
    fn missing_classification() {
        let tags = vec![Tag::new("project", "memvault")];
        assert!(lint_tags(&tags).is_err());
    }

    #[test]
    fn duplicate_classification() {
        let tags = vec![
            Tag::new("classification", "public"),
            Tag::new("classification", "internal"),
        ];
        assert!(lint_tags(&tags).is_err());
    }

    #[test]
    fn invalid_classification_label() {
        let tags = vec![Tag::new("classification", "secret")];
        assert!(lint_tags(&tags).is_err());
    }
}

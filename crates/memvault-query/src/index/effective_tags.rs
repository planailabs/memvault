//! Compute effective tags for a block considering inheritance.

use memvault_core::Tag;

/// Compute the effective tags for a block, merging inherited tags from parents.
pub fn effective_tags(own_tags: &[Tag], parent_tags: &[Vec<Tag>]) -> Vec<Tag> {
    let mut result: Vec<Tag> = own_tags.to_vec();
    for parent in parent_tags {
        for tag in parent {
            if !result.iter().any(|t| t.scope == tag.scope && t.label == tag.label) {
                result.push(tag.clone());
            }
        }
    }
    result
}

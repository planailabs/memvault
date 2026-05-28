//! Bucket types — moved to `memvault-core`. This module remains as a
//! thin re-export so existing `memvault_doc::{BucketDecl, BucketBinding,
//! BucketRole}` imports keep working. New code should import directly
//! from `memvault_core`.

pub use memvault_core::{BucketBinding, BucketDecl, BucketRole};

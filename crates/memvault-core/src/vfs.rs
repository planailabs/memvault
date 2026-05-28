//! Shared Virtual Filesystem (VFS) wire constants.
//!
//! These constants are used by both the API/server-side VFS helpers and the
//! WASM web UI. Keep them in `memvault-core` so browser builds do not need to
//! link the server-only `memvault-api` crate.

pub const VFS_DIR_KIND: &str = "vfs:dir";
pub const VFS_CHILD_REL: &str = "vfs:child";

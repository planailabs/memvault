//! Runtime migrations for the memvault store.
//!
//! Each migration is idempotent and guarded by a monotonically increasing
//! schema version stored in `LOCAL_IDENTITY["schema_version"]`.  Migrations
//! run automatically on [`LocalClient::run_migrations`] (called at startup)
//! and can also be triggered manually via `memctl repair-index`.
//!
//! **ACID guarantee**: each migration performs its work, then bumps the
//! version in a separate store transaction.  If the process crashes
//! mid-migration the version stays at the old value and the migration
//! re-runs on next startup — safe because every migration is idempotent.
//!
//! **Rule**: never modify an existing migration.  Always append new ones.

use crate::error::Result;
use crate::local::LocalClient;

/// A single migration step.
struct Migration {
    version: u32,
    name: &'static str,
    run: fn(&LocalClient) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<()>> + '_>>,
}

/// The ordered list of all migrations.  **Append-only.**
static MIGRATIONS: &[Migration] = &[Migration {
    version: 1,
    name: "adopt unbucketed entities into legacy bucket",
    run: |client| Box::pin(m0001_adopt_unbucketed(client)),
}];

/// The latest schema version (highest migration version).
pub const LATEST_VERSION: u32 = 1;

/// Run all pending migrations.  Returns `(from_version, to_version)`.
///
/// Safe to call on every startup — already-applied migrations are skipped
/// via the stored schema version.
pub async fn run_pending(client: &LocalClient) -> Result<(u32, u32)> {
    let current = client.store().schema_version().map_err(|e| {
        crate::error::ApiError::Other(format!("failed to read schema version: {e}"))
    })?;

    for m in MIGRATIONS {
        if m.version <= current {
            continue;
        }
        tracing::info!(version = m.version, name = m.name, "running migration");
        (m.run)(client).await?;
        client
            .store()
            .set_schema_version(m.version)
            .map_err(|e| {
                crate::error::ApiError::Other(format!(
                    "failed to set schema version to {}: {e}",
                    m.version
                ))
            })?;
        tracing::info!(version = m.version, name = m.name, "migration complete");
    }

    let final_version = client.store().schema_version().map_err(|e| {
        crate::error::ApiError::Other(format!("failed to read schema version: {e}"))
    })?;
    Ok((current, final_version))
}

// ── Migration 0001 ─────────────────────────────────────────────────────
//
// Adopt locally-authored unbucketed entities into the legacy bucket.
// "Legacy bucket" = the cluster's default bucket, used here only as the
// adoption target for pre-bucket data.

async fn m0001_adopt_unbucketed(client: &LocalClient) -> Result<()> {
    let legacy_bucket = match client.legacy_bucket_id() {
        Some(b) => b,
        None => return Ok(()), // no cluster/bucket yet — nothing to adopt
    };

    let entities = client.list_entities_unscoped(50_000).await?;
    let mut adopted = 0usize;

    for entity in &entities {
        if client
            .adopt_entity_into_bucket(&entity.id, &legacy_bucket)
            .await?
        {
            adopted += 1;
        }
    }

    if adopted > 0 {
        tracing::info!(adopted, "adopted unbucketed entities into legacy bucket");
    }
    Ok(())
}

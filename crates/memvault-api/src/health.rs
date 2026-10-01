//! Health check module for memvault nodes.

use std::time::Instant;

use serde::{Deserialize, Serialize};

use memvault_store::MemvaultStore;

/// Health check result for the memvault node.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthCheck {
    pub status: HealthStatus,
    pub checks: Vec<CheckResult>,
}

/// Overall health status.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum HealthStatus {
    Healthy,
    Degraded,
    Unhealthy,
}

/// Result of a single health check.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckResult {
    pub name: String,
    pub status: HealthStatus,
    pub message: Option<String>,
    pub duration_ms: u64,
}

/// Run all health checks against the store.
pub fn check_health(store: &MemvaultStore) -> HealthCheck {
    let mut checks = Vec::new();

    // Check 1: Store accessible (can write and read a test block)
    checks.push(check_store_accessible(store));

    // Check 2: Rotations check (no stuck rotations)
    checks.push(check_rotations(store));

    // Overall status
    let status = if checks.iter().any(|c| c.status == HealthStatus::Unhealthy) {
        HealthStatus::Unhealthy
    } else if checks.iter().any(|c| c.status == HealthStatus::Degraded) {
        HealthStatus::Degraded
    } else {
        HealthStatus::Healthy
    };

    HealthCheck { status, checks }
}

fn check_store_accessible(store: &MemvaultStore) -> CheckResult {
    let start = Instant::now();
    // Probe a scratch table, never BLOCKS: a fake key there is a
    // non-content-addressed block, and deleting a real CID could remove
    // someone's data.
    let result = store
        .probe_roundtrip()
        .map_err(|e| format!("store probe failed: {e}"));

    let duration_ms = start.elapsed().as_millis() as u64;

    match result {
        Ok(()) => CheckResult {
            name: "store_accessible".to_string(),
            status: HealthStatus::Healthy,
            message: None,
            duration_ms,
        },
        Err(msg) => CheckResult {
            name: "store_accessible".to_string(),
            status: HealthStatus::Unhealthy,
            message: Some(msg),
            duration_ms,
        },
    }
}

fn check_rotations(store: &MemvaultStore) -> CheckResult {
    let start = Instant::now();

    let result = store.get_all_rotations();
    let duration_ms = start.elapsed().as_millis() as u64;

    match result {
        Ok(rotations) => {
            // If there are many rotations, that might indicate something is stuck,
            // but for now just confirm we can read the table.
            let msg = if rotations.is_empty() {
                None
            } else {
                Some(format!("{} rotation(s) recorded", rotations.len()))
            };
            CheckResult {
                name: "rotations".to_string(),
                status: HealthStatus::Healthy,
                message: msg,
                duration_ms,
            }
        }
        Err(e) => CheckResult {
            name: "rotations".to_string(),
            status: HealthStatus::Degraded,
            message: Some(format!("failed to read rotations: {e}")),
            duration_ms,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn check_health_on_fresh_store_is_healthy() {
        let dir = tempfile::tempdir().unwrap();
        let store = MemvaultStore::open(dir.path().join("test.redb")).unwrap();
        let health = check_health(&store);
        assert_eq!(health.status, HealthStatus::Healthy);
        assert!(!health.checks.is_empty());
        for check in &health.checks {
            assert_eq!(check.status, HealthStatus::Healthy);
        }
    }
}

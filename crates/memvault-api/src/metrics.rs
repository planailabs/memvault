//! Prometheus-compatible operational metrics for memvault.

use std::fmt::Write;
use std::sync::atomic::{AtomicU64, Ordering};

/// Memvault operational metrics.
pub struct Metrics {
    pub blocks_stored: AtomicU64,
    pub blocks_served: AtomicU64,
    pub envelopes_inserted: AtomicU64,
    pub queries_total: AtomicU64,
    pub auth_handshakes_total: AtomicU64,
    pub auth_handshakes_failed: AtomicU64,
    pub tokens_issued: AtomicU64,
    pub tokens_redeemed: AtomicU64,
    pub tokens_revoked: AtomicU64,
    pub rotations_total: AtomicU64,
    pub pii_findings_total: AtomicU64,
    pub egress_checks_total: AtomicU64,
    pub egress_denials_total: AtomicU64,
    pub summaries_generated: AtomicU64,
    pub retractions_total: AtomicU64,
    pub federation_announcements_sent: AtomicU64,
    pub federation_announcements_received: AtomicU64,
    pub connected_peers: AtomicU64,
    pub storage_bytes: AtomicU64,
}

impl Metrics {
    pub fn new() -> Self {
        Self {
            blocks_stored: AtomicU64::new(0),
            blocks_served: AtomicU64::new(0),
            envelopes_inserted: AtomicU64::new(0),
            queries_total: AtomicU64::new(0),
            auth_handshakes_total: AtomicU64::new(0),
            auth_handshakes_failed: AtomicU64::new(0),
            tokens_issued: AtomicU64::new(0),
            tokens_redeemed: AtomicU64::new(0),
            tokens_revoked: AtomicU64::new(0),
            rotations_total: AtomicU64::new(0),
            pii_findings_total: AtomicU64::new(0),
            egress_checks_total: AtomicU64::new(0),
            egress_denials_total: AtomicU64::new(0),
            summaries_generated: AtomicU64::new(0),
            retractions_total: AtomicU64::new(0),
            federation_announcements_sent: AtomicU64::new(0),
            federation_announcements_received: AtomicU64::new(0),
            connected_peers: AtomicU64::new(0),
            storage_bytes: AtomicU64::new(0),
        }
    }

    /// Render all metrics in Prometheus exposition format.
    pub fn render_prometheus(&self) -> String {
        let mut out = String::new();

        let fields: &[(&str, &str, &AtomicU64)] = &[
            (
                "memvault_blocks_stored_total",
                "Total blocks stored",
                &self.blocks_stored,
            ),
            (
                "memvault_blocks_served_total",
                "Total blocks served",
                &self.blocks_served,
            ),
            (
                "memvault_envelopes_inserted_total",
                "Total envelopes inserted",
                &self.envelopes_inserted,
            ),
            (
                "memvault_queries_total",
                "Total queries executed",
                &self.queries_total,
            ),
            (
                "memvault_auth_handshakes_total",
                "Total auth handshakes",
                &self.auth_handshakes_total,
            ),
            (
                "memvault_auth_handshakes_failed_total",
                "Total failed auth handshakes",
                &self.auth_handshakes_failed,
            ),
            (
                "memvault_tokens_issued_total",
                "Total tokens issued",
                &self.tokens_issued,
            ),
            (
                "memvault_tokens_redeemed_total",
                "Total tokens redeemed",
                &self.tokens_redeemed,
            ),
            (
                "memvault_tokens_revoked_total",
                "Total tokens revoked",
                &self.tokens_revoked,
            ),
            (
                "memvault_rotations_total",
                "Total key rotations",
                &self.rotations_total,
            ),
            (
                "memvault_pii_findings_total",
                "Total PII findings detected",
                &self.pii_findings_total,
            ),
            (
                "memvault_egress_checks_total",
                "Total egress checks",
                &self.egress_checks_total,
            ),
            (
                "memvault_egress_denials_total",
                "Total egress denials",
                &self.egress_denials_total,
            ),
            (
                "memvault_summaries_generated_total",
                "Total summaries generated",
                &self.summaries_generated,
            ),
            (
                "memvault_retractions_total",
                "Total retractions",
                &self.retractions_total,
            ),
            (
                "memvault_federation_announcements_sent_total",
                "Federation announcements sent",
                &self.federation_announcements_sent,
            ),
            (
                "memvault_federation_announcements_received_total",
                "Federation announcements received",
                &self.federation_announcements_received,
            ),
            (
                "memvault_connected_peers",
                "Currently connected peers",
                &self.connected_peers,
            ),
            (
                "memvault_storage_bytes",
                "Total storage bytes used",
                &self.storage_bytes,
            ),
        ];

        for (name, help, value) in fields {
            let _ = writeln!(out, "# HELP {name} {help}");
            let metric_type = if name.ends_with("_total") {
                "counter"
            } else {
                "gauge"
            };
            let _ = writeln!(out, "# TYPE {name} {metric_type}");
            let _ = writeln!(out, "{name} {}", value.load(Ordering::Relaxed));
        }

        out
    }

    /// Reset all counters (for testing).
    pub fn reset(&self) {
        self.blocks_stored.store(0, Ordering::Relaxed);
        self.blocks_served.store(0, Ordering::Relaxed);
        self.envelopes_inserted.store(0, Ordering::Relaxed);
        self.queries_total.store(0, Ordering::Relaxed);
        self.auth_handshakes_total.store(0, Ordering::Relaxed);
        self.auth_handshakes_failed.store(0, Ordering::Relaxed);
        self.tokens_issued.store(0, Ordering::Relaxed);
        self.tokens_redeemed.store(0, Ordering::Relaxed);
        self.tokens_revoked.store(0, Ordering::Relaxed);
        self.rotations_total.store(0, Ordering::Relaxed);
        self.pii_findings_total.store(0, Ordering::Relaxed);
        self.egress_checks_total.store(0, Ordering::Relaxed);
        self.egress_denials_total.store(0, Ordering::Relaxed);
        self.summaries_generated.store(0, Ordering::Relaxed);
        self.retractions_total.store(0, Ordering::Relaxed);
        self.federation_announcements_sent
            .store(0, Ordering::Relaxed);
        self.federation_announcements_received
            .store(0, Ordering::Relaxed);
        self.connected_peers.store(0, Ordering::Relaxed);
        self.storage_bytes.store(0, Ordering::Relaxed);
    }
}

impl Default for Metrics {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn increment_and_read() {
        let m = Metrics::new();
        m.blocks_stored.fetch_add(5, Ordering::Relaxed);
        m.queries_total.fetch_add(3, Ordering::Relaxed);
        assert_eq!(m.blocks_stored.load(Ordering::Relaxed), 5);
        assert_eq!(m.queries_total.load(Ordering::Relaxed), 3);
    }

    #[test]
    fn render_prometheus_format() {
        let m = Metrics::new();
        m.blocks_stored.fetch_add(10, Ordering::Relaxed);
        m.connected_peers.store(2, Ordering::Relaxed);

        let output = m.render_prometheus();
        assert!(output.contains("# HELP memvault_blocks_stored_total"));
        assert!(output.contains("# TYPE memvault_blocks_stored_total counter"));
        assert!(output.contains("memvault_blocks_stored_total 10"));
        assert!(output.contains("# TYPE memvault_connected_peers gauge"));
        assert!(output.contains("memvault_connected_peers 2"));
    }

    #[test]
    fn reset_clears_all() {
        let m = Metrics::new();
        m.blocks_stored.fetch_add(100, Ordering::Relaxed);
        m.egress_denials_total.fetch_add(50, Ordering::Relaxed);
        m.connected_peers.store(7, Ordering::Relaxed);

        m.reset();

        assert_eq!(m.blocks_stored.load(Ordering::Relaxed), 0);
        assert_eq!(m.egress_denials_total.load(Ordering::Relaxed), 0);
        assert_eq!(m.connected_peers.load(Ordering::Relaxed), 0);
    }
}

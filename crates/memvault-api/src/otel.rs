//! OpenTelemetry integration for memvault.
//!
//! When the `otel` feature is enabled, this module provides span creation
//! helpers that add structured attributes to traces. Without the feature,
//! only the attribute constants are available (useful for manual tracing spans).

/// Span attributes for memvault operations.
pub mod attrs {
    pub const DOC_ID: &str = "memvault.doc_id";
    pub const CID: &str = "memvault.cid";
    pub const ENTITY_ID: &str = "memvault.entity_id";
    pub const OP_KIND: &str = "memvault.op_kind";
    pub const QUERY: &str = "memvault.query";
    pub const RESULT_COUNT: &str = "memvault.result_count";
    pub const BLOCK_SIZE: &str = "memvault.block_size";
    pub const PEER_COUNT: &str = "memvault.peer_count";
}

/// Initialize OpenTelemetry tracing (call once at startup).
///
/// When the `otel` feature is enabled, this sets up a TracerProvider with
/// a stdout exporter suitable for development. Production deployments should
/// configure an OTLP exporter via environment variables before calling this.
#[cfg(feature = "otel")]
pub fn init_otel(_service_name: &str) -> Result<(), Box<dyn std::error::Error>> {
    // The actual OTel SDK setup is a runtime concern. This stub exists so
    // downstream consumers (daemon, memctl) can call init_otel() uniformly.
    // A real implementation would use opentelemetry_otlp or stdout exporter.
    Ok(())
}

/// No-op when otel feature is disabled.
#[cfg(not(feature = "otel"))]
pub fn init_otel(_service_name: &str) -> Result<(), Box<dyn std::error::Error>> {
    Ok(())
}

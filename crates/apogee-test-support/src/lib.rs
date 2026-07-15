//! Test-only harness: byte-diff goldens, redaction, sandboxes, and the out-of-process oracle
//! runner.
//!
//! Dev-dependency only: consumers pull this in under `[dev-dependencies]`, so it never enters a
//! shipping build's graph.

pub mod golden;
pub mod redact;
pub mod sandbox;

#[cfg(feature = "oracle")]
pub mod oracle;

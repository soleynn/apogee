//! Test-only harness: byte-diff goldens, redaction, sandboxes, and a fixture transport.
//!
//! Dev-dependency only: consumers pull this in under `[dev-dependencies]`, so it never enters a
//! shipping build's graph.

pub mod chaos;
pub mod golden;
pub mod redact;
pub mod rt;
pub mod sandbox;
pub mod transport;

#![forbid(unsafe_code)]
//! Test-only harness: byte-diff goldens, redaction, sandboxes, and a fixture transport.
//!
//! Dev-dependency only: consumers pull this in under `[dev-dependencies]`, so it never enters a
//! shipping build's graph.

#[cfg(target_os = "linux")]
pub mod capacity;
pub mod catalog_sign;
pub mod chaos;
// Always compiled: the readiness rule a corpus-backed gate consults is filesystem and environment
// only, and the gates that need it must not pull the download transport in to ask. Fetching itself
// stays behind the `corpus` feature, inside the module.
pub mod corpus;
pub mod golden;
pub mod login_fixtures;
pub mod redact;
pub mod rt;
pub mod sandbox;
pub mod transport;
pub mod tree_manifest;

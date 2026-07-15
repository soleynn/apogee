//! The protocol error taxonomy.
//!
//! Expected dispositions the UI narrates (no service, terms not yet accepted, a boot patch pending)
//! are *values* in the result types, not errors; the variants here are genuine protocol failures.
//! `#[non_exhaustive]`: the login and session-registration failures join as those surfaces land.

use crate::transport::TransportError;

/// The protocol step a failure occurred in, for triage. `#[non_exhaustive]`: grows with the surfaces.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Step {
    /// The unauthenticated boot-version check.
    BootVersion,
    /// The frontier gate-status fetch.
    GateStatus,
    /// The frontier login-status fetch.
    LoginStatus,
}

/// A protocol failure.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ProtoError {
    /// The transport could not complete the request.
    #[error("transport: {0}")]
    Transport(#[from] TransportError),

    /// SE returned a response the step could not accept: an unexpected status or an unparseable body.
    /// The excerpt is redacted and length-capped at the construction site.
    #[error("unexpected response at {step:?}: status {status}")]
    InvalidResponse {
        step: Step,
        status: u16,
        excerpt: String,
    },

    /// A patchlist line could not be parsed. `line` is 1-based; `reason` is a stable, static tag.
    #[error("patchlist parse error at line {line}: {reason}")]
    PatchListParse { line: u32, reason: &'static str },
}

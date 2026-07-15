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

/// A short, safe excerpt of a response body for an error message: lossy UTF-8, capped in length so a
/// large or binary body cannot bloat the error.
pub(crate) fn excerpt(body: &[u8]) -> String {
    const MAX_CHARS: usize = 200;
    String::from_utf8_lossy(body)
        .chars()
        .take(MAX_CHARS)
        .collect()
}

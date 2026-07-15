//! The protocol error taxonomy.
//!
//! Expected dispositions the UI narrates (no service, terms not yet accepted, a boot patch pending)
//! are *values* in the result types, not errors; the variants here are genuine protocol failures.
//! `#[non_exhaustive]`: the login and session-registration failures join as those surfaces land.

use crate::transport::{ProtoResponse, TransportError};

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
    /// The OAuth login top page.
    OauthTop,
    /// The OAuth credential submission.
    OauthLogin,
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

    /// The OAuth submission did not return the success callback. The excerpt is scrubbed of the
    /// submitted credentials and length-capped at the construction site.
    #[error("oauth login rejected")]
    OauthFailed { excerpt: String },

    /// The top page asked the client to relink a Steam account (`window.external.user("restartup")`).
    /// Wired for the Steam variant; a standard login never reaches it.
    #[error("steam account not linked")]
    SteamLinkNeeded,

    /// The Steam ticket is linked to a different SE account than the one submitted. `expected_hint` is
    /// a masked form of the linked id, never the full value.
    #[error("steam ticket is linked to a different account")]
    SteamWrongAccount { expected_hint: String },

    /// The top page carried no `_STORED_` blob. The excerpt is length-capped; the top page carries no
    /// submitted credentials.
    #[error("_STORED_ not found on the login top page")]
    StoredNotFound { excerpt: String },

    /// The `launchParams` list was too short or malformed to read the fields a login needs. `got_fields`
    /// is a count only, never the field contents (which include the session id).
    #[error("launchParams unparseable ({got_fields} fields)")]
    LaunchParamsUnparseable { got_fields: usize },
}

impl ProtoError {
    /// Build an [`InvalidResponse`](ProtoError::InvalidResponse) for `step` from a response, capturing
    /// the status and a redacted, length-capped body excerpt at this single construction site.
    pub(crate) fn invalid_response(step: Step, response: &ProtoResponse) -> Self {
        Self::InvalidResponse {
            step,
            status: response.status,
            excerpt: excerpt(&response.body),
        }
    }
}

/// The most characters an excerpt keeps: enough to triage, small enough that a large or binary body
/// cannot bloat the error.
const EXCERPT_MAX_CHARS: usize = 200;

/// A short, safe excerpt of a response body for an error message: lossy UTF-8, capped in length so a
/// large or binary body cannot bloat the error.
pub(crate) fn excerpt(body: &[u8]) -> String {
    String::from_utf8_lossy(body)
        .chars()
        .take(EXCERPT_MAX_CHARS)
        .collect()
}

/// Like [`excerpt`], but first removes any of `secrets` from the body so a page that echoes the
/// submitted credentials cannot leak them into an error. Scrubbing happens before the length cap, so a
/// secret near the start cannot survive by being split at the boundary.
pub(crate) fn scrubbed_excerpt(body: &[u8], secrets: &[&str]) -> String {
    let mut text = String::from_utf8_lossy(body).into_owned();
    for secret in secrets {
        if !secret.is_empty() {
            text = text.replace(secret, "[redacted]");
        }
    }
    text.chars().take(EXCERPT_MAX_CHARS).collect()
}

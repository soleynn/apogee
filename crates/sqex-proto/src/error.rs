//! The protocol error taxonomy.
//!
//! Expected dispositions the UI narrates (no service, terms not yet accepted, a boot patch pending)
//! are *values* in the result types, not errors; the variants here are genuine protocol failures.
//! `#[non_exhaustive]`: further failures join as new surfaces land.

use crate::transport::{ProtoResponse, TransportError};
use crate::version::{SanityKind, VersionRepo};

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
    /// The session-registration version report.
    Register,
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

    /// A version file failed the sanity gate before session registration, so no request was made. The
    /// install is corrupt but repairable; `repo` and `kind` locate the fault without carrying a path.
    #[error("version file for {repo:?} failed the sanity check: {kind:?}")]
    InvalidVersionFiles { repo: VersionRepo, kind: SanityKind },
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
/// submitted credentials cannot leak them into an error. Matching is verbatim and best-effort: a
/// secret the page re-encodes (HTML-escaped, percent-encoded) is not caught, so callers surface
/// attacker-influenced text sparingly rather than relying on this alone. Scrubbing happens before the
/// length cap, so a secret near the boundary cannot survive by being split.
pub(crate) fn scrubbed_excerpt(body: &[u8], secrets: &[&str]) -> String {
    // Scrub a bounded window, not the whole body: keep EXCERPT_MAX_CHARS plus the longest secret
    // (minus one) so any secret with a char in the final excerpt is fully present here and is redacted
    // before the final cut, without copying a large body once per secret.
    let max_secret = secrets.iter().map(|s| s.chars().count()).max().unwrap_or(0);
    let window = EXCERPT_MAX_CHARS + max_secret.saturating_sub(1);
    let mut text: String = String::from_utf8_lossy(body).chars().take(window).collect();
    for secret in secrets {
        if !secret.is_empty() {
            text = text.replace(secret, "[redacted]");
        }
    }
    text.chars().take(EXCERPT_MAX_CHARS).collect()
}

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

    /// The top page carried no `_STORED_` blob. The excerpt is length-capped and redacted of a
    /// reflected `session_ticket`; the top page carries no submitted credentials.
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
    ///
    /// `secrets` are the values this step put on the wire that the response can reflect back: the
    /// session id registration writes into its URL path, the bearer ticket a Steam login writes into
    /// its query. A step that sent none passes an empty slice.
    pub(crate) fn invalid_response(step: Step, response: &ProtoResponse, secrets: &[&str]) -> Self {
        Self::InvalidResponse {
            step,
            status: response.status,
            excerpt: scrubbed_excerpt(&response.body, secrets),
        }
    }
}

/// The most characters an excerpt keeps: enough to triage, small enough that a large or binary body
/// cannot bloat the error.
const EXCERPT_MAX_CHARS: usize = 200;

/// The most bytes one UTF-8 character encodes to: the factor between a character budget and the bytes
/// that are certain to hold it.
const MAX_UTF8_BYTES: usize = 4;

/// What a redaction leaves in place of the text it removed.
const REDACTED: &str = "[redacted]";

/// Query parameters whose value is a credential, redacted wherever an excerpt carries the shape.
///
/// The Steam ticket rides in the top-page query, so any page that echoes the request URL back (an
/// error page, a WAF block) reflects it. Redacting by shape rather than by value covers the sites that
/// never see the ticket ([`crate::oauth::scrape_stored`] takes only the page) and the reflections that
/// re-encode it, which a verbatim scrub of the ticket text misses.
const SECRET_QUERY_PARAMS: [&str; 1] = ["session_ticket="];

/// What ends a query parameter's value in reflected text: the query and fragment separators, plus the
/// delimiters a page embedding a URL in markup breaks on. Every other character reads as part of the
/// value, so an unfamiliar reflection over-redacts rather than under-redacts.
const VALUE_END: [char; 10] = ['&', '#', '"', '\'', '<', '>', ' ', '\t', '\r', '\n'];

/// A short, safe excerpt of a response body for an error message: lossy UTF-8, capped in length so a
/// large or binary body cannot bloat the error, with any [`SECRET_QUERY_PARAMS`] value redacted.
pub(crate) fn excerpt(body: &[u8]) -> String {
    scrubbed_excerpt(body, &[])
}

/// Like [`excerpt`], but also removes any of `secrets` from the body so a page that echoes the
/// submitted credentials cannot leak them into an error. Matching is verbatim and best-effort: a
/// secret the page re-encodes (HTML-escaped, percent-encoded) is not caught, so callers surface
/// attacker-influenced text sparingly rather than relying on this alone. Scrubbing happens before the
/// length cap, so a secret near the boundary cannot survive by being split.
pub(crate) fn scrubbed_excerpt(body: &[u8], secrets: &[&str]) -> String {
    // Scrub a bounded window, not the whole body: keep EXCERPT_MAX_CHARS plus the longest secret
    // (minus one) so any secret with a char in the final excerpt is fully present here and is redacted
    // before the final cut, without decoding or copying a large body.
    let max_secret = secrets.iter().map(|s| s.chars().count()).max().unwrap_or(0);
    let window = EXCERPT_MAX_CHARS + max_secret.saturating_sub(1);
    let text = redact_secrets(&lossy_head(body, window), secrets);
    redact_secret_params(&text)
        .chars()
        .take(EXCERPT_MAX_CHARS)
        .collect()
}

/// Decode at most `max_chars` characters from the head of `body`.
///
/// The bytes are cut before the decode, not after: `from_utf8_lossy` validates every byte it is handed
/// and reallocates the lot when it finds an invalid one, so decoding a whole body to keep 200
/// characters of it makes an error construction cost as much as the body an attacker chose to send.
fn lossy_head(body: &[u8], max_chars: usize) -> String {
    String::from_utf8_lossy(excerpt_bytes(body, max_chars))
        .chars()
        .take(max_chars)
        .collect()
}

/// The head of `body` that is certain to hold `max_chars` characters.
///
/// A character encodes to at most [`MAX_UTF8_BYTES`], so that many times the budget always covers it,
/// and the cut walks back off a continuation byte so a character split by the cut does not decode to a
/// replacement one. The walk-back is bounded: a run of stray continuation bytes is invalid UTF-8 that
/// decodes to one replacement character each, so it must not eat the window.
fn excerpt_bytes(body: &[u8], max_chars: usize) -> &[u8] {
    let limit = max_chars.saturating_mul(MAX_UTF8_BYTES);
    if limit >= body.len() {
        return body;
    }
    let floor = limit.saturating_sub(MAX_UTF8_BYTES - 1);
    let mut cut = limit;
    while cut > floor && body[cut] & 0b1100_0000 == 0b1000_0000 {
        cut -= 1;
    }
    &body[..cut]
}

/// Replace every occurrence of any of `secrets` in `text` with [`REDACTED`].
///
/// One left-to-right pass taking the longest match at each position, not one whole-buffer `replace`
/// per secret: sequential replaces share a buffer, so a secret that is a literal prefix of a longer one
/// (a username and a password that starts with it, a username and the `_STORED_` blob that embeds it)
/// consumes the shared span first and leaves the longer secret's tail behind in plaintext. Matching
/// once over disjoint ranges redacts each occurrence exactly once and never re-reads a placeholder it
/// just wrote.
fn redact_secrets(text: &str, secrets: &[&str]) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while !rest.is_empty() {
        let matched = secrets
            .iter()
            .filter(|secret| !secret.is_empty() && rest.starts_with(**secret))
            .map(|secret| secret.len())
            .max();
        match matched {
            Some(len) => {
                out.push_str(REDACTED);
                rest = &rest[len..];
            }
            None => rest = push_one_char(&mut out, rest),
        }
    }
    out
}

/// Replace the value of any [`SECRET_QUERY_PARAMS`] parameter in `text` with [`REDACTED`], keeping the
/// parameter name so the excerpt still says what was there. A value with no terminator left (the cut
/// took it) is redacted to the end of the text.
fn redact_secret_params(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while !rest.is_empty() {
        let matched = SECRET_QUERY_PARAMS
            .iter()
            .find_map(|param| rest.strip_prefix(param).map(|value| (*param, value)));
        match matched {
            Some((param, value)) => {
                out.push_str(param);
                out.push_str(REDACTED);
                rest = &value[value.find(VALUE_END).unwrap_or(value.len())..];
            }
            None => rest = push_one_char(&mut out, rest),
        }
    }
    out
}

/// Move the first character of `rest` onto `out`, returning what is left. Character-wise, so no cut
/// can land inside a multi-byte character.
fn push_one_char<'t>(out: &mut String, rest: &'t str) -> &'t str {
    let mut chars = rest.chars();
    if let Some(ch) = chars.next() {
        out.push(ch);
    }
    chars.as_str()
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    #[test]
    fn a_prefix_secret_does_not_shield_the_longer_one() {
        // The submit scrub list's real order (sqexid before password) over a password built from the
        // username, an ordinary credential shape. Redacting one secret at a time over a shared buffer
        // consumes "alice" first, leaving the password's "123!" tail in plaintext.
        let body = b"debug: rejected form sqexid=alice&password=alice123!&otppw=";
        assert_eq!(
            scrubbed_excerpt(body, &["alice", "alice123!"]),
            "debug: rejected form sqexid=[redacted]&password=[redacted]&otppw="
        );
    }

    #[test]
    fn a_short_username_does_not_shield_the_stored_blob() {
        let body = b"echo: _STORED_=XYSECRETSTORED sqexid=XY";
        let text = scrubbed_excerpt(body, &["XY", "XYSECRETSTORED"]);
        assert!(!text.contains("SECRET"), "stored blob leaked: {text}");
        assert_eq!(text, "echo: _STORED_=[redacted] sqexid=[redacted]");
    }

    #[test]
    fn the_scrub_does_not_depend_on_the_order_of_the_secrets() {
        let body = b"sqexid=alice&password=alice123!";
        assert_eq!(
            scrubbed_excerpt(body, &["alice", "alice123!"]),
            scrubbed_excerpt(body, &["alice123!", "alice"]),
        );
    }

    #[test]
    fn an_empty_secret_is_skipped() {
        // An absent OTP is submitted as an empty string and rides in the scrub list; matching it would
        // put a placeholder between every character.
        assert_eq!(scrubbed_excerpt(b"unchanged", &["", ""]), "unchanged");
    }

    #[test]
    fn a_reflected_session_ticket_is_redacted_by_shape() {
        // A page that echoes the top-page URL back: the ticket is a bearer credential and the scanner
        // that builds this excerpt never sees it, so the parameter is redacted by name.
        let body = b"404: /oauth/ffxivarr/login/top?lng=en&issteam=1\
            &session_ticket=NC1jaHVuaw*,c2Vjb25kY2h1bms*&ticket_size=42";
        let text = excerpt(body);
        assert!(!text.contains("NC1jaHVuaw"), "ticket leaked: {text}");
        assert!(!text.contains("c2Vjb25k"), "ticket leaked: {text}");
        assert!(
            text.contains("session_ticket=[redacted]&ticket_size=42"),
            "{text}"
        );
    }

    #[test]
    fn a_session_ticket_running_past_the_excerpt_is_redacted_to_the_end() {
        // No terminator survives the length cap, so the redaction runs to the end of the text rather
        // than giving up and keeping what is left of the value.
        let body = format!("reflected: ?session_ticket={}", "T".repeat(400));
        let text = excerpt(body.as_bytes());
        assert!(!text.contains('T'), "ticket leaked: {text}");
        assert_eq!(text, "reflected: ?session_ticket=[redacted]");
    }

    #[test]
    fn an_excerpt_reads_only_the_head_of_a_body() {
        // The decode is bounded by the excerpt's own budget: a body an attacker chose the size of
        // cannot make error construction cost proportional to it.
        let body = vec![b'x'; 1 << 20];
        assert_eq!(
            excerpt_bytes(&body, EXCERPT_MAX_CHARS).len(),
            EXCERPT_MAX_CHARS * MAX_UTF8_BYTES
        );
        assert_eq!(excerpt(&body).chars().count(), EXCERPT_MAX_CHARS);
    }

    #[test]
    fn the_head_cut_never_splits_a_character() {
        // The budget's last byte lands mid-character; the cut walks back to that character's start
        // instead of handing the decoder a partial sequence.
        let body = format!("a{}", "€".repeat(8));
        assert_eq!(excerpt_bytes(body.as_bytes(), 3), "a€€€".as_bytes());
        assert_eq!(lossy_head(body.as_bytes(), 3), "a€€");
    }

    #[test]
    fn a_run_of_continuation_bytes_does_not_eat_the_head() {
        // Stray continuation bytes are invalid UTF-8 that decodes to one replacement character each,
        // so the walk-back is bounded rather than following the run back to the start of the body.
        let body = vec![0x80u8; 1000];
        assert_eq!(
            excerpt_bytes(&body, EXCERPT_MAX_CHARS).len(),
            EXCERPT_MAX_CHARS * MAX_UTF8_BYTES - (MAX_UTF8_BYTES - 1)
        );
        assert_eq!(excerpt(&body).chars().count(), EXCERPT_MAX_CHARS);
    }

    proptest! {
        /// Digits only, and digit filler: the placeholder is spelled out of letters, so a generated
        /// secret could otherwise be a substring of the redaction that replaced it.
        #[test]
        fn no_secret_survives_a_scrub(
            first in "[0-9]{1,8}",
            second in "[0-9]{1,8}",
            filler in "[0-9 ]{0,50}",
        ) {
            let body = format!("{filler}{first}{filler}{second}{filler}{first}{second}");
            let text = scrubbed_excerpt(body.as_bytes(), &[&first, &second]);
            prop_assert!(!text.contains(&first), "{text}");
            prop_assert!(!text.contains(&second), "{text}");
        }

        #[test]
        fn an_excerpt_never_panics_and_stays_capped(body in proptest::collection::vec(any::<u8>(), 0..2048)) {
            prop_assert!(excerpt(&body).chars().count() <= EXCERPT_MAX_CHARS);
            prop_assert!(scrubbed_excerpt(&body, &["a", "ab"]).chars().count() <= EXCERPT_MAX_CHARS);
        }
    }
}

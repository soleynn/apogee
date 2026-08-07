//! The protocol error taxonomy.
//!
//! Expected dispositions the UI narrates (no service, terms not yet accepted, a boot patch pending)
//! are *values* in the result types, not errors; the variants here are genuine protocol failures.
//! `#[non_exhaustive]`: further failures join as new surfaces land.

use std::fmt;

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
    /// The dormant `gen_token` patch-URL tokenization request.
    GenToken,
}

/// A protocol failure.
///
/// `Debug` is hand-written (see below) so an excerpt cannot reach a log through `{:?}`.
#[derive(thiserror::Error)]
#[non_exhaustive]
pub enum ProtoError {
    /// The transport could not complete the request.
    #[error("transport: {0}")]
    Transport(#[from] TransportError),

    /// SE returned a response the step could not accept: an unexpected status or an unparseable body.
    /// The excerpt is redacted and length-capped at the construction site.
    #[error("unexpected response at {step:?}: status {status}")]
    InvalidResponse {
        /// Which protocol step the response was for.
        step: Step,
        /// The HTTP status SE answered with.
        status: u16,
        /// A redacted, length-capped slice of the response body.
        excerpt: String,
    },

    /// A patchlist line could not be parsed. `line` is 1-based; `reason` is a stable, static tag.
    #[error("patchlist parse error at line {line}: {reason}")]
    PatchListParse {
        /// The 1-based line number of the offending entry.
        line: u32,
        /// A stable, static tag identifying what about the line was wrong. Never the line's own bytes.
        reason: &'static str,
    },

    /// The OAuth submission did not return the success callback. The excerpt is scrubbed of the
    /// submitted credentials and length-capped at the construction site.
    #[error("oauth login rejected")]
    OauthFailed {
        /// A scrubbed, length-capped slice of SE's rejection page or message.
        excerpt: String,
    },

    /// The top page asked the client to relink a Steam account (`window.external.user("restartup")`).
    /// Wired for the Steam variant; a standard login never reaches it.
    #[error("steam account not linked")]
    SteamLinkNeeded,

    /// The Steam ticket is linked to a different SE account than the one submitted. `expected_hint` is
    /// a masked form of the linked id, never the full value.
    #[error("steam ticket is linked to a different account")]
    SteamWrongAccount {
        /// A masked hint of the account the ticket is actually linked to (e.g. `a***z`).
        expected_hint: String,
    },

    /// The top page carried no `_STORED_` blob. The excerpt is length-capped and redacted of a
    /// reflected `session_ticket`; the top page carries no submitted credentials.
    #[error("_STORED_ not found on the login top page")]
    StoredNotFound {
        /// A redacted, length-capped slice of the page that should have carried `_STORED_`.
        excerpt: String,
    },

    /// The `launchParams` list was too short or malformed to read the fields a login needs. `got_fields`
    /// is a count only, never the field contents (which include the session id).
    #[error("launchParams unparseable ({got_fields} fields)")]
    LaunchParamsUnparseable {
        /// How many comma-separated fields the callback actually carried.
        got_fields: usize,
    },

    /// A version file failed the sanity gate before session registration, so no request was made. The
    /// install is corrupt but repairable; `repo` and `kind` locate the fault without carrying a path.
    #[error("version file for {repo:?} failed the sanity check: {kind:?}")]
    InvalidVersionFiles {
        /// Which repository's version file (or boot EXE backup) failed.
        repo: VersionRepo,
        /// What about it failed.
        kind: SanityKind,
    },
}

/// Excerpts are kept out of `Debug`, which is what a logger, a panic message, or a `{err:?}` in a
/// caller reaches for. Every excerpt is attacker-influenced text that can reflect what the request put
/// on the wire (a URL bearing the session id, a form bearing the credentials); the construction sites
/// scrub what they know about, but scrubbing is verbatim and best-effort, so nothing downstream should
/// inherit an excerpt by accident. `Display` never carried one, and a shell that means to present one
/// reads the field.
impl fmt::Debug for ProtoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            // `TransportError`'s own derived `Debug` prints its `message` field verbatim, and that
            // field only ever redacts URL-shaped content (see `TransportError::new`). That is a
            // narrower guarantee than this crate's other excerpts get, but every construction site in
            // this crate passes it a `&'static str` or a format string naming a header, never a value
            // read off the wire (audited: `bootver.rs`, `register.rs`, and `transport.rs` itself), so
            // there is nothing left for this arm to scrub. A non-URL secret in that field would have
            // to come from the `Transport` implementor's own message text, which is out of this
            // crate's reach and stays the implementor's (`apogee-core`, in production) responsibility.
            Self::Transport(err) => f.debug_tuple("Transport").field(err).finish(),
            Self::InvalidResponse {
                step,
                status,
                excerpt,
            } => f
                .debug_struct("InvalidResponse")
                .field("step", step)
                .field("status", status)
                .field("excerpt", &Withheld(excerpt))
                .finish(),
            Self::PatchListParse { line, reason } => f
                .debug_struct("PatchListParse")
                .field("line", line)
                .field("reason", reason)
                .finish(),
            Self::OauthFailed { excerpt } => f
                .debug_struct("OauthFailed")
                .field("excerpt", &Withheld(excerpt))
                .finish(),
            Self::SteamLinkNeeded => f.write_str("SteamLinkNeeded"),
            Self::SteamWrongAccount { expected_hint } => f
                .debug_struct("SteamWrongAccount")
                .field("expected_hint", expected_hint)
                .finish(),
            Self::StoredNotFound { excerpt } => f
                .debug_struct("StoredNotFound")
                .field("excerpt", &Withheld(excerpt))
                .finish(),
            Self::LaunchParamsUnparseable { got_fields } => f
                .debug_struct("LaunchParamsUnparseable")
                .field("got_fields", got_fields)
                .finish(),
            Self::InvalidVersionFiles { repo, kind } => f
                .debug_struct("InvalidVersionFiles")
                .field("repo", repo)
                .field("kind", kind)
                .finish(),
        }
    }
}

/// An excerpt rendered as its size alone: enough to tell an empty body from a full one in a debug
/// dump, none of the text.
struct Withheld<'a>(&'a str);

impl fmt::Debug for Withheld<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "<{} chars withheld>", self.0.chars().count())
    }
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
/// error page, a WAF block) reflects it. Redacting by shape rather than only by value covers the
/// reflections that re-encode it, which a verbatim scrub of the ticket text misses, and stands in for
/// any call site that omits the ticket from its own scrub list.
const SECRET_QUERY_PARAMS: [&str; 1] = ["session_ticket="];

/// What ends a query parameter's value in reflected text: the query and fragment separators, plus the
/// delimiters a page embedding a URL in markup breaks on. Every other character reads as part of the
/// value, so an unfamiliar reflection over-redacts rather than under-redacts.
const VALUE_END: [char; 10] = ['&', '#', '"', '\'', '<', '>', ' ', '\t', '\r', '\n'];

/// [`scrubbed_excerpt`] with no secrets to scrub verbatim, kept for tests that only exercise the
/// [`SECRET_QUERY_PARAMS`] shape-based redaction. Every production call site now has a scrub list of
/// its own, even if empty, so this has no caller outside `#[cfg(test)]`.
#[cfg(test)]
fn excerpt(body: &[u8]) -> String {
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
    let head = lossy_head(body, window);
    // That budget covers exactly one redaction's shrinkage: `REDACTED` is shorter than any secret
    // worth scrubbing, so redacting an occurrence pulls later content forward into view. A *second*
    // occurrence can then straddle the window boundary the decode stopped at, so `redact_secrets`
    // sees only its head. Only pass the ambiguity guard when the decode actually hit that boundary
    // (`head` filled the window): a body that fit entirely inside it has no more text to worry about,
    // and every occurrence in `head` is already known complete.
    let truncated = head.chars().count() >= window;
    let text = redact_secrets(&head, secrets, if truncated { max_secret } else { 0 });
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
///
/// `tail_guard` is the length of the longest secret that could still be waiting past `text`'s end (0
/// when it cannot be: the caller already held the whole body, so there is nothing more to reveal).
/// Once fewer than `tail_guard` characters remain unmatched, a real occurrence could have started
/// there and had its close cut off by the caller's decode window: `rest.starts_with(secret)` can only
/// prove a *complete* string absent, never a partial one, so continuing would risk copying an
/// unredacted fragment. Stopping there instead trades a few characters of excerpt for the guarantee
/// that nothing this function did not fully see ever reaches the output.
fn redact_secrets(text: &str, secrets: &[&str], tail_guard: usize) -> String {
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
            None if rest.chars().count() < tail_guard => break,
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

    #[test]
    fn debug_withholds_every_excerpt() {
        let excerpts = [
            ProtoError::InvalidResponse {
                step: Step::Register,
                status: 404,
                excerpt: "SESSIONSECRET not found".to_owned(),
            },
            ProtoError::OauthFailed {
                excerpt: "SESSIONSECRET".to_owned(),
            },
            ProtoError::StoredNotFound {
                excerpt: "SESSIONSECRET".to_owned(),
            },
        ];
        for err in excerpts {
            let rendered = format!("{err:?}");
            assert!(!rendered.contains("SESSIONSECRET"), "{rendered}");
            assert!(rendered.contains("chars withheld"), "{rendered}");
        }
    }

    #[test]
    fn debug_keeps_the_triage_context() {
        let err = ProtoError::InvalidResponse {
            step: Step::Register,
            status: 404,
            excerpt: String::new(),
        };
        assert_eq!(
            format!("{err:?}"),
            "InvalidResponse { step: Register, status: 404, excerpt: <0 chars withheld> }"
        );
        assert_eq!(
            err.to_string(),
            "unexpected response at Register: status 404"
        );
    }

    /// A secret-shaped string of exactly `len` characters. Cycling the alphabet rather than repeating
    /// one character means an arbitrary fragment of it (as [`assert_no_partial_leak`] checks for) is
    /// still recognizably a piece of *this* string, not a coincidental match against filler.
    fn secret_of_len(len: usize) -> String {
        (0..len).map(|i| (b'a' + (i % 26) as u8) as char).collect()
    }

    /// The shortest fragment of a secret this module treats as a meaningful leak, not a coincidence.
    /// A flat cap rather than a fraction of the secret's length: the window-straddle bug does not
    /// leak a fixed proportion (the 720-char `_STORED_` blob repro loses only ~150 of it, one fifth),
    /// so a "half the secret" bar misses real leaks on anything long. 16 exact characters survives
    /// coincidentally only if a filler was engineered to produce it.
    const LEAK_FRAGMENT_LEN: usize = 16;

    /// Fails if a fragment of `secret` at least [`LEAK_FRAGMENT_LEN`] characters long (or the whole
    /// secret, if it is shorter than that) survives anywhere in `text`. `!text.contains(secret)` is
    /// not enough to catch the window-truncation bug this guards: under that bug the excerpt held
    /// neither the whole secret nor nothing of it, but a long exact fragment, which whole-string
    /// containment is structurally blind to. Checking fixed-length fragments (rather than every
    /// substring) is sufficient: any leaked run longer than the threshold contains one of this length
    /// too.
    fn assert_no_partial_leak(text: &str, secret: &str) {
        let chars: Vec<char> = secret.chars().collect();
        let threshold = chars.len().clamp(1, LEAK_FRAGMENT_LEN);
        for window in chars.windows(threshold) {
            let fragment: String = window.iter().collect();
            assert!(
                !text.contains(&fragment),
                "partial leak: {fragment:?} (fragment of a {}-char secret) survives in {text:?}",
                chars.len()
            );
        }
    }

    #[test]
    fn a_session_id_reflected_twice_does_not_leak_past_the_window() {
        // register_session's error path: the session id rides in the request URL, so a "not found"
        // page that names the path it could not find reflects it. A second reflection, far enough
        // into the body, lands past the window `scrubbed_excerpt` widens to catch exactly one
        // redaction's shrinkage. This exact shape (a 54-char session id, 150 filler characters
        // between the two reflections) is the repro that measured a 25-character plaintext leak.
        let sid = secret_of_len(54);
        let filler = " ".repeat(150);
        let body = format!("404 not found: {sid}{filler}{sid}");
        let text = scrubbed_excerpt(body.as_bytes(), &[&sid]);
        assert_no_partial_leak(&text, &sid);
    }

    #[test]
    fn a_password_reflected_three_times_does_not_leak_past_the_window() {
        // LoginFlow::submit's error path: a rejected-form page can echo the submitted password more
        // than once (once per field it complains about). This is an equivalent adversarial shape to
        // the captured repro (a 67-char password, reflected a third time far enough in to straddle
        // the window): not a byte-for-byte replay of that response body, but the same bug class.
        let pw = secret_of_len(67);
        let prefix = "400: rejected form password=";
        let mid1 = format!("&why={}", "-".repeat(15));
        let mid2 = format!("&again={}", "-".repeat(13));
        let body = format!("{prefix}{pw}{mid1}{pw}{mid2}{pw}");
        let text = scrubbed_excerpt(body.as_bytes(), &[&pw]);
        assert_no_partial_leak(&text, &pw);
    }

    #[test]
    fn a_stored_blob_reflected_twice_does_not_leak_past_the_window() {
        // LoginFlow::submit's error path: an edge error page that echoes the top page's own body
        // reflects the _STORED_ blob wherever the top page carried it, including a second time in an
        // echoed debug field. Equivalent adversarial shape to the captured repro (a 720-char blob
        // reflected twice), not a byte-for-byte replay of that response body.
        let blob = secret_of_len(720);
        let body = format!("500: error parsing _STORED_={blob} debug_echo={blob}");
        let text = scrubbed_excerpt(body.as_bytes(), &[&blob]);
        assert_no_partial_leak(&text, &blob);
    }

    /// Reverting `lossy_head`'s bounded-byte cut back to `String::from_utf8_lossy(body)` leaves every
    /// other test in this module green: they never hand it a body big enough to notice the cost.
    /// A near-end invalid byte forces the whole-body path to reallocate and copy the entire buffer
    /// (`from_utf8_lossy` only borrows when the input is entirely valid UTF-8), which the windowed
    /// path never touches, because the window sits nowhere near the tail. 50ms is far above the
    /// windowed path's cost (microseconds) and far below a 64MB whole-body copy even unoptimized.
    #[test]
    fn constructing_an_excerpt_never_touches_the_body_past_its_window() {
        let mut body = vec![b'x'; 64 * 1024 * 1024];
        *body.last_mut().unwrap() = 0xFF;
        let started = std::time::Instant::now();
        let text = excerpt(&body);
        assert!(text.chars().all(|c| c == 'x'));
        assert!(
            started.elapsed() < std::time::Duration::from_millis(50),
            "excerpt construction took {:?}; the decode is no longer bounded to the window",
            started.elapsed()
        );
    }

    proptest! {
        /// Secrets and filler large enough to actually cross the 200-char excerpt window (not just
        /// short digit runs that always fit inside it), so this exercises the truncation boundary the
        /// window-straddle bug lived at, and each secret repeats (matching the real repros, which all
        /// needed a second reflection to trigger). `first`, `second`, and `filler` draw from disjoint
        /// alphabets (lowercase, uppercase, digits-and-space) so no generated case, however proptest
        /// shrinks it, can make [`assert_no_partial_leak`] see a coincidental cross-match instead of a
        /// genuine one: a real leak is the only way a fragment of one can appear where another was
        /// generated.
        #[test]
        fn no_secret_survives_a_scrub(
            first in "[a-m]{20,90}",
            second in "[A-M]{20,90}",
            filler in "[0-9 ]{0,300}",
        ) {
            let body = format!("{filler}{first}{filler}{second}{filler}{first}{second}");
            let text = scrubbed_excerpt(body.as_bytes(), &[&first, &second]);
            assert_no_partial_leak(&text, &first);
            assert_no_partial_leak(&text, &second);
        }

        #[test]
        fn an_excerpt_never_panics_and_stays_capped(body in proptest::collection::vec(any::<u8>(), 0..2048)) {
            prop_assert!(excerpt(&body).chars().count() <= EXCERPT_MAX_CHARS);
            prop_assert!(scrubbed_excerpt(&body, &["a", "ab"]).chars().count() <= EXCERPT_MAX_CHARS);
        }
    }
}

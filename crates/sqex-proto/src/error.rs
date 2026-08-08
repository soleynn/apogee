//! The protocol's error taxonomy.
//!
//! [`ProtoError`] is the single error type every fallible surface in this crate returns. Expected
//! dispositions the UI narrates (no service, terms not yet accepted, a boot patch pending) are
//! *values* in the relevant result types, not errors; the variants here are genuine protocol
//! failures a caller cannot proceed past. Both [`Step`] and [`ProtoError`] are `#[non_exhaustive]`:
//! new surfaces add new steps and, occasionally, new failure variants.

use std::fmt;

use crate::transport::{ProtoResponse, TransportError};
use crate::version::{SanityKind, VersionRepo};

/// The protocol step a [`ProtoError`] occurred in, carried for triage.
///
/// # Examples
///
/// ```
/// use sqex_proto::Step;
///
/// assert_eq!(format!("{:?}", Step::Register), "Register");
/// ```
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
    /// The dormant `gen_token` (behind the `gen-token` feature) patch-URL tokenization request.
    #[cfg(feature = "gen-token")]
    GenToken,
}

/// A protocol failure.
///
/// Every excerpt-carrying variant holds a redacted, length-capped slice of the response body
/// rather than the response itself. An excerpt is attacker-influenced text that can reflect what
/// the request put on the wire (a URL bearing the session id, a form bearing the credentials); the
/// construction site scrubs what it knows about, but the scrub is verbatim and best-effort, so
/// nothing downstream should inherit an excerpt by accident and callers should surface one
/// sparingly (a log line, not a user-facing message verbatim). `Debug` is hand-written rather than
/// derived for exactly this reason: every excerpt field prints only its length under `{:?}`, so a
/// `{err:?}` in a panic message or a logger cannot leak one by accident. `Display` never carries an
/// excerpt; a caller that means to present one reads the field directly.
///
/// # Examples
///
/// ```
/// use sqex_proto::{ProtoError, Step};
///
/// let err = ProtoError::LaunchParamsUnparseable { got_fields: 3 };
/// assert_eq!(err.to_string(), "launchParams unparseable (3 fields)");
///
/// // Debug never leaks a triage-only field like an excerpt.
/// let leaky = ProtoError::OauthFailed {
///     excerpt: "SESSIONSECRET".to_owned(),
/// };
/// assert!(!format!("{leaky:?}").contains("SESSIONSECRET"));
/// # let _ = Step::Register;
/// ```
#[derive(thiserror::Error)]
#[non_exhaustive]
pub enum ProtoError {
    /// The transport could not complete the request.
    #[error("transport: {0}")]
    Transport(#[from] TransportError),

    /// SE returned a response the step could not accept: an unexpected status or an unparseable
    /// body.
    #[error("unexpected response at {step:?}: status {status}")]
    InvalidResponse {
        /// Which protocol step the response was for.
        step: Step,
        /// The HTTP status SE answered with.
        status: u16,
        /// A redacted, length-capped slice of the response body.
        excerpt: String,
    },

    /// A patchlist line could not be parsed.
    #[error("patchlist parse error at line {line}: {reason}")]
    PatchListParse {
        /// The 1-based line number of the offending entry.
        line: u32,
        /// A stable, static tag identifying what about the line was wrong, never the line's own
        /// bytes.
        reason: &'static str,
    },

    /// The OAuth submission did not return the success callback.
    #[error("oauth login rejected")]
    OauthFailed {
        /// A scrubbed, length-capped slice of SE's rejection message.
        excerpt: String,
    },

    /// The top page asked the client to relink a Steam account
    /// (`window.external.user("restartup")`). Only reachable from the Steam login variant; a
    /// standard login never returns this.
    #[error("steam account not linked")]
    SteamLinkNeeded,

    /// The Steam ticket submitted is linked to a different SE account than the one offered as
    /// [`Credentials`](crate::Credentials).
    #[error("steam ticket is linked to a different account")]
    SteamWrongAccount {
        /// A masked hint of the account the ticket is actually linked to (e.g. `a***z`), not the
        /// full id.
        expected_hint: String,
    },

    /// The login top page carried no `_STORED_` blob to echo back on submission.
    #[error("_STORED_ not found on the login top page")]
    StoredNotFound {
        /// A redacted, length-capped slice of the page that should have carried `_STORED_`.
        excerpt: String,
    },

    /// The login success callback's `launchParams` list was too short or malformed to read the
    /// fields a login needs.
    #[error("launchParams unparseable ({got_fields} fields)")]
    LaunchParamsUnparseable {
        /// How many comma-separated fields the callback actually carried.
        got_fields: usize,
    },

    /// A version file failed the sanity gate before session registration, so no request was made.
    /// The install is corrupt but repairable.
    #[error("version file for {repo:?} failed the sanity check: {kind:?}")]
    InvalidVersionFiles {
        /// Which repository's version file (or boot EXE backup) failed.
        repo: VersionRepo,
        /// What about it failed.
        kind: SanityKind,
    },
}

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

struct Withheld<'a>(&'a str);

impl fmt::Debug for Withheld<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "<{} chars withheld>", self.0.chars().count())
    }
}

impl ProtoError {
    // `secrets` are the values this step put on the wire that the response can reflect back: the
    // session id registration writes into its URL path, the bearer ticket a Steam login writes into
    // its query. A step that sent none passes an empty slice.
    pub(crate) fn invalid_response(step: Step, response: &ProtoResponse, secrets: &[&str]) -> Self {
        Self::InvalidResponse {
            step,
            status: response.status,
            excerpt: scrubbed_excerpt(&response.body, secrets),
        }
    }
}

const EXCERPT_MAX_CHARS: usize = 200;

const MAX_UTF8_BYTES: usize = 4;

const REDACTED: &str = "[redacted]";

// Query parameters whose value is a credential, redacted wherever an excerpt carries the shape. The
// Steam ticket rides in the top-page query, so any page that echoes the request URL back (an error
// page, a WAF block) reflects it. Redacting by shape rather than only by value covers the reflections
// that re-encode it, and stands in for any call site that omits the ticket from its own scrub list.
const SECRET_QUERY_PARAMS: [&str; 1] = ["session_ticket="];

// What ends a query parameter's value in reflected text: the query and fragment separators, plus the
// delimiters a page embedding a URL in markup breaks on. Every other character reads as part of the
// value, so an unfamiliar reflection over-redacts rather than under-redacts.
const VALUE_END: [char; 10] = ['&', '#', '"', '\'', '<', '>', ' ', '\t', '\r', '\n'];

#[cfg(test)]
fn excerpt(body: &[u8]) -> String {
    scrubbed_excerpt(body, &[])
}

// `body` must be the full, untruncated text a step read off the wire: this function does its own
// bounded-window decode and length cap, cheaply, regardless of how large `body` is, so a caller has
// no performance reason to pre-truncate before calling this. It also has no correctness license to:
// the ambiguity guard below decides whether a secret could be waiting past what it saw by checking
// whether *this function's own* window filled, so a body a caller already cut down elsewhere looks
// identical to one that legitimately ended there, and the guard silently never engages. This bug
// shipped once already (a MAX_MESSAGE-capped OAuth failure message handed here pre-truncated, which
// hid a straddling secret from the guard) -- see oauth::scan::parse_login_callback, which now borrows
// the message uncapped for exactly this reason.
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

fn lossy_head(body: &[u8], max_chars: usize) -> String {
    String::from_utf8_lossy(excerpt_bytes(body, max_chars))
        .chars()
        .take(max_chars)
        .collect()
}

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

// One left-to-right pass taking the longest match at each position, not one whole-buffer `replace`
// per secret: sequential replaces share a buffer, so a secret that is a literal prefix of a longer one
// (a username and a password that starts with it, a username and the _STORED_ blob that embeds it)
// consumes the shared span first and leaves the longer secret's tail behind in plaintext.
//
// `tail_guard` is the length of the longest secret that could still be waiting past `text`'s end (0
// when it cannot be: the caller already held the whole body). Once fewer than `tail_guard` characters
// remain unmatched, a real occurrence could have started there and had its close cut off by the
// caller's decode window: `rest.starts_with(secret)` can only prove a *complete* string absent, never
// a partial one, so continuing would risk copying an unredacted fragment.
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

    fn secret_of_len(len: usize) -> String {
        (0..len).map(|i| (b'a' + (i % 26) as u8) as char).collect()
    }

    // A flat cap rather than a fraction of the secret's length: the window-straddle bug does not leak
    // a fixed proportion (the 720-char _STORED_ blob repro loses only ~150 of it, one fifth), so a
    // "half the secret" bar misses real leaks on anything long.
    const LEAK_FRAGMENT_LEN: usize = 16;

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

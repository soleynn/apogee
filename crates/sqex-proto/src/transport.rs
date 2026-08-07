//! The network seam.
//!
//! This crate never opens a socket: every request is handed to an injected [`Transport`], whose
//! production implementation (reqwest, with dual-stack dialing) is assembled in the composition root.
//! Tests supply a fixture transport. The crate names neither `reqwest` nor `tokio`; the only async
//! surface is the `async fn` on this trait.

use std::fmt;

use http::{HeaderName, HeaderValue, Method};
use url::Url;
use zeroize::Zeroizing;

/// A single HTTP request, fully specified.
///
/// The header list is ordered and complete: a transport emits exactly these headers, in this order,
/// and injects nothing of its own (no default `Accept`, no tracing header). The one exception is
/// [`NEGOTIATED_HEADERS`], which a client answers for itself. SE plausibly fingerprints the header
/// set, so fidelity is a contract; [`check_header_fidelity`] is how an adapter proves it at the
/// boundary. The [`RequestBody`] keeps a credential-bearing body zeroizing and out of `Debug`, so
/// `ProtoRequest` can derive `Debug` without leaking it.
#[derive(Debug, Clone)]
pub struct ProtoRequest {
    /// The HTTP method.
    pub method: Method,
    /// The full request URL, including its query.
    pub url: Url,
    /// The exact headers to send, in this order. See the type docs: a transport must emit these and
    /// nothing more, [`NEGOTIATED_HEADERS`] excepted.
    pub headers: Vec<(HeaderName, HeaderValue)>,
    /// The request body, for methods that carry one.
    pub body: Option<RequestBody>,
}

impl ProtoRequest {
    /// A request with no headers and no body.
    #[must_use]
    pub fn new(method: Method, url: Url) -> Self {
        Self {
            method,
            url,
            headers: Vec::new(),
            body: None,
        }
    }

    /// Append a header, preserving order.
    #[must_use]
    pub fn header(mut self, name: HeaderName, value: HeaderValue) -> Self {
        self.headers.push((name, value));
        self
    }

    /// Attach a request body.
    #[must_use]
    pub fn body(mut self, body: RequestBody) -> Self {
        self.body = Some(body);
        self
    }
}

/// The bytes of a request body.
///
/// Held zeroizing because a login submit carries percent-encoded credentials, so the crate's copy
/// scrubs on drop instead of lingering in freed heap; and rendered in `Debug` as only its length, so a
/// logged request cannot leak it. This is defense in depth for the crate's own copy: a transport
/// (reqwest, TLS, and kernel buffers) makes further copies this type cannot reach.
#[derive(Clone)]
pub struct RequestBody(Zeroizing<Vec<u8>>);

impl RequestBody {
    /// Wrap `bytes` as a request body; they are held zeroizing from here on.
    #[must_use]
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(Zeroizing::new(bytes))
    }

    /// The body bytes, for a transport to write.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for RequestBody {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{} bytes]", self.0.len())
    }
}

/// A response: the status, the raw body, and any headers a surface needs to read. Most surfaces read
/// only the status and body; the OAuth top page reads the `Date` header (for TOTP skew correction) and
/// session registration reads `X-Patch-Unique-Id`, so a header a transport chooses to surface rides
/// along here. A transport carries only the headers a surface asks for, not the whole response set.
#[derive(Debug, Clone)]
pub struct ProtoResponse {
    /// The HTTP status code.
    pub status: u16,
    /// The raw response body.
    pub body: Vec<u8>,
    /// The headers a transport chose to surface (not necessarily the full response set); read with
    /// [`Self::header`].
    pub headers: Vec<(HeaderName, HeaderValue)>,
}

impl ProtoResponse {
    /// Build a response from its status and body, carrying no headers.
    #[must_use]
    pub fn new(status: u16, body: Vec<u8>) -> Self {
        Self {
            status,
            body,
            headers: Vec::new(),
        }
    }

    /// Attach a response header, preserving insertion order.
    #[must_use]
    pub fn with_header(mut self, name: HeaderName, value: HeaderValue) -> Self {
        self.headers.push((name, value));
        self
    }

    /// The first value carried for `name`, if any.
    #[must_use]
    pub fn header(&self, name: &HeaderName) -> Option<&HeaderValue> {
        self.headers.iter().find(|(n, _)| n == name).map(|(_, v)| v)
    }

    /// Whether SE answered with exactly `200 OK`. The protocol treats any other status as invalid, so
    /// this is a strict equality, not a 2xx-range check.
    #[must_use]
    pub fn is_ok(&self) -> bool {
        self.status == 200
    }
}

/// A transport-layer failure: DNS, connect, TLS, timeout, or a truncated read.
///
/// The message is the one free-form string an implementor outside this crate writes into the protocol's
/// error taxonomy, and it travels out of the CLI on stderr. So the type carries the obligation rather
/// than stating it: the field is private and every construction runs [`TransportError::new`], which
/// strips the path, query, and fragment from any URL in the text. That is the leak this seam has
/// actually had. A client library renders a failed send as `error sending request for url (<the whole
/// url>)`, and one step of the login flow puts the OAuth session id in the URL path, so an implementor
/// that passes the rendering through hands a live credential to whatever prints the error.
///
/// `Debug` is derived because the field is unreachable except through that constructor: there is
/// nothing left for a hand-written one to hide.
#[derive(Debug, Clone, thiserror::Error)]
#[error("transport failure: {message}")]
pub struct TransportError {
    message: String,
}

impl TransportError {
    /// Build a transport error, dropping the path, query, and fragment of any URL in `message`.
    #[must_use]
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: redact_url_paths(&message.into()),
        }
    }

    /// The redacted failure text.
    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }
}

/// Rewrite every `scheme://host/path?query#fragment` in `text` down to `scheme://host/…`.
///
/// The host is kept because which endpoint was unreachable is the whole diagnostic; the path is
/// dropped because it is fixed by the protocol and is where the credentials ride. The scan walks
/// occurrences of `://` rather than parsing, since the text around a URL is arbitrary prose: the
/// authority ends at the first path/query/fragment mark or at whatever delimiter the surrounding
/// sentence used, and only a path/query/fragment is dropped, never the prose that follows a bare host.
fn redact_url_paths(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(at) = rest.find("://") {
        let (head, tail) = rest.split_at(at + 3);
        out.push_str(head);
        let authority_end = tail
            .find(|c: char| c.is_whitespace() || "/?#\"'`<>()[]{},".contains(c))
            .unwrap_or(tail.len());
        out.push_str(&tail[..authority_end]);
        let after = &tail[authority_end..];
        if after.starts_with(['/', '?', '#']) {
            let url_end = after
                .find(|c: char| c.is_whitespace() || "\"'`<>()[]{}".contains(c))
                .unwrap_or(after.len());
            out.push_str("/…");
            rest = &after[url_end..];
        } else {
            rest = after;
        }
    }
    out.push_str(rest);
    out
}

/// Build a header value from a caller-supplied string, failing rather than panicking on stray control
/// bytes (the launcher's own values are always valid, so this is a guard, not a live path). Shared by
/// every surface that sets a header from a dynamic string.
pub(crate) fn dynamic_header(value: &str) -> Result<HeaderValue, TransportError> {
    HeaderValue::from_str(value).map_err(|_| TransportError::new("invalid header value"))
}

/// Parse a compile-time-constant base URL, mapping the (unreachable for our constants) parse failure
/// to a typed transport error so request building stays panic-free.
pub(crate) fn parse_base(url: &str, invalid_msg: &'static str) -> Result<Url, TransportError> {
    Url::parse(url).map_err(|_| TransportError::new(invalid_msg))
}

/// The only way this crate touches the network.
///
/// Implementations own pooling, dual-stack dialing, timeouts, and TLS. The crate never retries: the
/// caller owns retry policy because it owns the UX of a failed request.
#[async_trait::async_trait]
pub trait Transport: Send + Sync {
    /// Send `req` and return the response, or a [`TransportError`] if the request could not complete.
    /// Never retried by this crate: a caller that wants retries applies its own policy around the call.
    async fn execute(&self, req: ProtoRequest) -> Result<ProtoResponse, TransportError>;
}

/// The headers a client answers for itself, exempt from the fidelity contract on both sides.
///
/// `accept-encoding` is the only one. A transport that forwards a declared value switches off its
/// client's own automatic decompression (that is how every mainstream client decides whether the
/// caller took over negotiation), which leaves the parser a compressed body. So the declared value
/// records what the reference launcher negotiates and the client substitutes its own, which is a known
/// fingerprint divergence rather than a silent one: see the wire-level test in the core's adapter,
/// which pins what the production client actually appends.
///
/// Nothing else belongs here. A client's own late framing additions (`host`, `content-length`) are
/// added below the layer an adapter reads back from when a surface leaves them undeclared, so an
/// undeclared one never reaches the comparison; if a client ever starts adding one earlier, the check
/// firing is the intended outcome. One surface is a deliberate exception: `bootver.rs` declares `host`
/// explicitly, matching the reference launcher's own explicit `Host` header on that endpoint, so there
/// it is an ordinary declared header in the comparison rather than an implicit framing one.
pub const NEGOTIATED_HEADERS: [HeaderName; 1] = [http::header::ACCEPT_ENCODING];

/// Check that `emitted` is exactly the request's declared headers, in the same order, ignoring
/// [`NEGOTIATED_HEADERS`] on both sides.
///
/// A transport adapter calls this after translating a [`ProtoRequest`] into its client's
/// representation and reading the headers back, to catch a translation that reordered them, dropped
/// one, or let the client's own representation regroup them. It returns an error rather than
/// asserting, so the guard runs in every build profile: a request whose header set is not the one this
/// crate specified is a request that must not be sent, not a debug-only warning.
///
/// What it does not reach is whatever a client merges *after* a request is assembled, which is where
/// clients typically apply configured defaults and content negotiation and is below any API an adapter
/// can read. That half is checkable only from a socket, so an adapter owes a test that reads its own
/// request head off one; the core's adapter has it.
///
/// The message names headers and never their values: a referer carries a URL and a cookie carries
/// whatever SE set, and neither is worth putting in an error to diagnose an ordering bug.
pub fn check_header_fidelity(
    req: &ProtoRequest,
    emitted: &[(HeaderName, HeaderValue)],
) -> Result<(), TransportError> {
    let own = |set: &[(HeaderName, HeaderValue)]| {
        set.iter()
            .filter(|(name, _)| !NEGOTIATED_HEADERS.contains(name))
            .cloned()
            .collect::<Vec<_>>()
    };
    let declared = own(&req.headers);
    let emitted = own(emitted);

    let altered = || {
        let names = |set: &[(HeaderName, HeaderValue)]| {
            set.iter()
                .map(|(name, _)| name.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        };
        TransportError::new(format!(
            "transport altered the header set: declared [{}], emitted [{}]",
            names(&declared),
            names(&emitted)
        ))
    };

    if declared.len() != emitted.len() {
        return Err(altered());
    }
    for (declared_pair, emitted_pair) in declared.iter().zip(&emitted) {
        if declared_pair.0 != emitted_pair.0 {
            return Err(altered());
        }
        if declared_pair.1 != emitted_pair.1 {
            return Err(TransportError::new(format!(
                "transport altered the value of the {} header",
                declared_pair.0.as_str()
            )));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ua() -> (HeaderName, HeaderValue) {
        (
            HeaderName::from_static("user-agent"),
            HeaderValue::from_static("FFXIV PATCH CLIENT"),
        )
    }

    #[test]
    fn builder_preserves_header_order() {
        let url = Url::parse("http://example.invalid/").unwrap();
        let req = ProtoRequest::new(Method::GET, url)
            .header(
                HeaderName::from_static("host"),
                HeaderValue::from_static("h"),
            )
            .header(ua().0, ua().1);
        assert_eq!(req.headers.len(), 2);
        assert_eq!(req.headers[0].0.as_str(), "host");
        assert_eq!(req.headers[1].0.as_str(), "user-agent");
    }

    /// A request declaring `user-agent`, `accept-encoding`, `accept`, in that order.
    fn declaring_three() -> ProtoRequest {
        let url = Url::parse("http://example.invalid/").unwrap();
        ProtoRequest::new(Method::GET, url)
            .header(ua().0, ua().1)
            .header(
                HeaderName::from_static("accept-encoding"),
                HeaderValue::from_static("gzip, deflate"),
            )
            .header(
                HeaderName::from_static("accept"),
                HeaderValue::from_static("*/*"),
            )
    }

    #[test]
    fn fidelity_holds_when_emitted_matches() {
        let req = declaring_three();
        assert!(check_header_fidelity(&req, &req.headers.clone()).is_ok());
    }

    #[test]
    fn fidelity_fires_on_injected_header() {
        let req = declaring_three();
        let mut emitted = req.headers.clone();
        emitted.push((
            HeaderName::from_static("x-trace"),
            HeaderValue::from_static("1"),
        ));

        let err =
            check_header_fidelity(&req, &emitted).expect_err("an injected header is a failure");
        assert!(err.message().contains("altered the header set"), "{err}");
        assert!(err.message().contains("x-trace"), "{err}");
    }

    #[test]
    fn fidelity_fires_on_a_reordering() {
        let req = declaring_three();
        let mut emitted = req.headers.clone();
        emitted.swap(0, 2);

        let err = check_header_fidelity(&req, &emitted).expect_err("a reordering is a failure");
        assert!(err.message().contains("altered the header set"), "{err}");
    }

    #[test]
    fn fidelity_fires_on_a_dropped_header() {
        let req = declaring_three();
        let mut emitted = req.headers.clone();
        emitted.pop();

        let err = check_header_fidelity(&req, &emitted).expect_err("a dropped header is a failure");
        assert!(err.message().contains("altered the header set"), "{err}");
    }

    /// A changed value is reported by name only: the values themselves are a referer's URL and a
    /// cookie, and neither belongs in an error about ordering.
    #[test]
    fn fidelity_fires_on_a_rewritten_value_without_quoting_it() {
        let req = declaring_three();
        let mut emitted = req.headers.clone();
        emitted[0].1 = HeaderValue::from_static("curl/8");

        let err =
            check_header_fidelity(&req, &emitted).expect_err("a rewritten value is a failure");
        assert!(err.message().contains("user-agent"), "{err}");
        assert!(!err.message().contains("curl/8"), "{err}");
        assert!(!err.message().contains("FFXIV PATCH CLIENT"), "{err}");
    }

    /// The narrowing the one production adapter needs: it forwards no `accept-encoding` at all, and
    /// the client appends its own value later. Both shapes have to pass, or the guard could not be
    /// wired into the adapter it was written for.
    #[test]
    fn a_negotiated_header_is_exempt_in_either_direction() {
        let req = declaring_three();
        let dropped: Vec<_> = req
            .headers
            .iter()
            .filter(|(name, _)| name.as_str() != "accept-encoding")
            .cloned()
            .collect();
        assert!(check_header_fidelity(&req, &dropped).is_ok());

        let mut substituted = dropped.clone();
        substituted.push((
            HeaderName::from_static("accept-encoding"),
            HeaderValue::from_static("gzip,deflate,br"),
        ));
        assert!(check_header_fidelity(&req, &substituted).is_ok());
    }

    /// The exemption is for `accept-encoding` and nothing else: a client that drops any other declared
    /// header is still altering the fingerprint.
    #[test]
    fn the_exemption_does_not_extend_to_other_headers() {
        let req = declaring_three();
        let dropped: Vec<_> = req
            .headers
            .iter()
            .filter(|(name, _)| name.as_str() != "accept")
            .cloned()
            .collect();
        assert!(check_header_fidelity(&req, &dropped).is_err());
    }

    /// The leak this seam actually had: a client renders a failed send as the whole URL, and the
    /// registration POST carries the OAuth session id as its last path segment.
    #[test]
    fn a_url_in_an_error_keeps_its_host_and_loses_its_path() {
        let err = TransportError::new(
            "request failed: error sending request for url \
             (https://patch-gamever.ffxiv.com/http/win32/ffxivneo_release_game/1.2/SESSIONIDSECRET)",
        );

        assert!(!err.message().contains("SESSIONIDSECRET"), "{err}");
        assert_eq!(
            err.message(),
            "request failed: error sending request for url (https://patch-gamever.ffxiv.com/…)"
        );
    }

    #[test]
    fn redaction_keeps_a_bare_host_and_the_prose_around_it() {
        assert_eq!(
            TransportError::new("http://127.0.0.1:1 could not be reached").message(),
            "http://127.0.0.1:1 could not be reached"
        );
        assert_eq!(
            TransportError::new("connection refused").message(),
            "connection refused"
        );
    }

    /// A query and a fragment carry credentials just as readily as a path: the Steam login puts the
    /// session ticket in the top page's query string.
    #[test]
    fn redaction_covers_the_query_and_fragment_and_every_url_in_the_text() {
        assert_eq!(
            TransportError::new("gave up on https://a.invalid/x?session_ticket=SECRET then https://b.invalid/y#SECRET").message(),
            "gave up on https://a.invalid/… then https://b.invalid/…"
        );
    }
}

// The network seam. This crate never opens a socket: every request is handed to an injected
// Transport, whose production implementation (reqwest, with dual-stack dialing) is assembled in the
// composition root. Tests supply a fixture transport. The crate names neither reqwest nor tokio; the
// only async surface is the async fn on this trait.

use std::fmt;

use http::{HeaderName, HeaderValue, Method};
use url::Url;
use zeroize::Zeroizing;

// The header list is ordered and complete: a transport emits exactly these headers, in this order,
// and injects nothing of its own (no default Accept, no tracing header). The one exception is
// NEGOTIATED_HEADERS, which a client answers for itself. SE plausibly fingerprints the header set, so
// fidelity is a contract; check_header_fidelity is how an adapter proves it at the boundary.
#[derive(Debug, Clone)]
pub struct ProtoRequest {
    pub method: Method,
    pub url: Url,
    pub headers: Vec<(HeaderName, HeaderValue)>,
    pub body: Option<RequestBody>,
}

impl ProtoRequest {
    #[must_use]
    pub fn new(method: Method, url: Url) -> Self {
        Self {
            method,
            url,
            headers: Vec::new(),
            body: None,
        }
    }

    #[must_use]
    pub fn header(mut self, name: HeaderName, value: HeaderValue) -> Self {
        self.headers.push((name, value));
        self
    }

    #[must_use]
    pub fn body(mut self, body: RequestBody) -> Self {
        self.body = Some(body);
        self
    }
}

// Held zeroizing because a login submit carries percent-encoded credentials, so the crate's copy
// scrubs on drop instead of lingering in freed heap; this is defense in depth for the crate's own
// copy only -- a transport (reqwest, TLS, kernel buffers) makes further copies this type cannot reach.
#[derive(Clone)]
pub struct RequestBody(Zeroizing<Vec<u8>>);

impl RequestBody {
    #[must_use]
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(Zeroizing::new(bytes))
    }

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

#[derive(Debug, Clone)]
pub struct ProtoResponse {
    pub status: u16,
    pub body: Vec<u8>,
    pub headers: Vec<(HeaderName, HeaderValue)>,
}

impl ProtoResponse {
    #[must_use]
    pub fn new(status: u16, body: Vec<u8>) -> Self {
        Self {
            status,
            body,
            headers: Vec::new(),
        }
    }

    #[must_use]
    pub fn with_header(mut self, name: HeaderName, value: HeaderValue) -> Self {
        self.headers.push((name, value));
        self
    }

    #[must_use]
    pub fn header(&self, name: &HeaderName) -> Option<&HeaderValue> {
        self.headers.iter().find(|(n, _)| n == name).map(|(_, v)| v)
    }

    #[must_use]
    pub fn is_ok(&self) -> bool {
        self.status == 200
    }
}

// The message is the one free-form string an implementor outside this crate writes into the
// protocol's error taxonomy, and it travels out of the CLI on stderr. So the type carries the
// obligation rather than stating it: the field is private and every construction runs
// TransportError::new, which strips the path, query, and fragment from any URL in the text. That is
// the leak this seam has actually had: a client library renders a failed send as `error sending
// request for url (<the whole url>)`, and one step of the login flow puts the OAuth session id in the
// URL path, so an implementor that passes the rendering through hands a live credential to whatever
// prints the error.
#[derive(Debug, Clone, thiserror::Error)]
#[error("transport failure: {message}")]
pub struct TransportError {
    message: String,
}

impl TransportError {
    #[must_use]
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: redact_url_paths(&message.into()),
        }
    }

    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }
}

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

pub(crate) fn dynamic_header(value: &str) -> Result<HeaderValue, TransportError> {
    HeaderValue::from_str(value).map_err(|_| TransportError::new("invalid header value"))
}

pub(crate) fn parse_base(url: &str, invalid_msg: &'static str) -> Result<Url, TransportError> {
    Url::parse(url).map_err(|_| TransportError::new(invalid_msg))
}

#[async_trait::async_trait]
pub trait Transport: Send + Sync {
    // Never retried by this crate: a caller that wants retries applies its own policy around the call.
    async fn execute(&self, req: ProtoRequest) -> Result<ProtoResponse, TransportError>;
}

// The headers a client answers for itself, exempt from the fidelity contract on both sides.
// accept-encoding is the only one. A transport that forwards a declared value switches off its
// client's own automatic decompression (that is how mainstream clients decide whether the caller took
// over negotiation), which leaves the parser a compressed body. So the declared value records what
// the reference launcher negotiates and the client substitutes its own -- a known fingerprint
// divergence rather than a silent one; see the wire-level test in the core's adapter, which pins what
// the production client actually appends.
//
// A client's own late framing additions (host, content-length) are added below the layer an adapter
// reads back from when a surface leaves them undeclared, so an undeclared one never reaches the
// comparison. One surface is a deliberate exception: bootver.rs declares `host` explicitly, matching
// the reference launcher's own explicit Host header on that endpoint, so there it is an ordinary
// declared header in the comparison rather than an implicit framing one.
pub const NEGOTIATED_HEADERS: [HeaderName; 1] = [http::header::ACCEPT_ENCODING];

// A transport adapter calls this after translating a ProtoRequest into its client's representation
// and reading the headers back, to catch a translation that reordered them, dropped one, or let the
// client's own representation regroup them. Returns an error rather than asserting, so the guard runs
// in every build profile.
//
// What it does not reach is whatever a client merges *after* a request is assembled, which is where
// clients typically apply configured defaults and content negotiation and is below any API an adapter
// can read. That half is checkable only from a socket, so an adapter owes a test that reads its own
// request head off one; the core's adapter has it.
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

    #[test]
    fn redaction_covers_the_query_and_fragment_and_every_url_in_the_text() {
        assert_eq!(
            TransportError::new("gave up on https://a.invalid/x?session_ticket=SECRET then https://b.invalid/y#SECRET").message(),
            "gave up on https://a.invalid/… then https://b.invalid/…"
        );
    }
}

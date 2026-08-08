//! The network seam: this crate never opens a socket itself.
//!
//! Every request this crate builds is handed to an injected [`Transport`], whose production
//! implementation (reqwest, with dual-stack dialing) is assembled in the composition root; tests
//! supply a fixture. Naming neither `reqwest` nor `tokio` keeps the crate transport-free, so
//! [`Transport::execute`] is the only `async fn` anywhere in it.

use std::fmt;

use http::{HeaderName, HeaderValue, Method};
use url::Url;
use zeroize::Zeroizing;

/// A request built by this crate, ready to hand to a [`Transport`].
///
/// `headers` is ordered and complete: a transport is expected to emit exactly these headers, in
/// this order, and inject nothing of its own (no default `Accept`, no tracing header) beyond what
/// [`NEGOTIATED_HEADERS`] exempts. SE plausibly fingerprints the header set, so this fidelity is a
/// contract, not a nicety; [`check_header_fidelity`] is how an adapter proves it at the boundary.
///
/// # Examples
///
/// ```
/// use http::{HeaderName, HeaderValue, Method};
/// use sqex_proto::{ProtoRequest, RequestBody};
/// use url::Url;
///
/// let url = Url::parse("https://example.invalid/").unwrap();
/// let req = ProtoRequest::new(Method::GET, url)
///     .header(
///         HeaderName::from_static("user-agent"),
///         HeaderValue::from_static("FFXIV PATCH CLIENT"),
///     )
///     .body(RequestBody::new(b"payload".to_vec()));
/// assert_eq!(req.headers.len(), 1);
/// assert_eq!(req.body.unwrap().as_bytes(), b"payload");
/// ```
#[derive(Debug, Clone)]
pub struct ProtoRequest {
    /// The HTTP method.
    pub method: Method,
    /// The request URL.
    pub url: Url,
    /// The headers to send, in the exact order they should go on the wire.
    pub headers: Vec<(HeaderName, HeaderValue)>,
    /// The request body, if any.
    pub body: Option<RequestBody>,
}

impl ProtoRequest {
    /// Start a request with no headers and no body.
    ///
    /// # Examples
    ///
    /// ```
    /// use http::Method;
    /// use sqex_proto::ProtoRequest;
    /// use url::Url;
    ///
    /// let url = Url::parse("https://example.invalid/").unwrap();
    /// let req = ProtoRequest::new(Method::GET, url);
    /// assert!(req.headers.is_empty());
    /// assert!(req.body.is_none());
    /// ```
    #[must_use]
    pub fn new(method: Method, url: Url) -> Self {
        Self {
            method,
            url,
            headers: Vec::new(),
            body: None,
        }
    }

    /// Append a header, builder-style. Headers keep the order they are added in.
    ///
    /// # Examples
    ///
    /// ```
    /// use http::{HeaderName, HeaderValue, Method};
    /// use sqex_proto::ProtoRequest;
    /// use url::Url;
    ///
    /// let url = Url::parse("https://example.invalid/").unwrap();
    /// let req = ProtoRequest::new(Method::GET, url).header(
    ///     HeaderName::from_static("accept"),
    ///     HeaderValue::from_static("*/*"),
    /// );
    /// assert_eq!(req.headers[0].0.as_str(), "accept");
    /// ```
    #[must_use]
    pub fn header(mut self, name: HeaderName, value: HeaderValue) -> Self {
        self.headers.push((name, value));
        self
    }

    /// Attach a body, builder-style.
    ///
    /// # Examples
    ///
    /// ```
    /// use http::Method;
    /// use sqex_proto::{ProtoRequest, RequestBody};
    /// use url::Url;
    ///
    /// let url = Url::parse("https://example.invalid/").unwrap();
    /// let req = ProtoRequest::new(Method::GET, url).body(RequestBody::new(b"payload".to_vec()));
    /// assert_eq!(req.body.unwrap().as_bytes(), b"payload");
    /// ```
    #[must_use]
    pub fn body(mut self, body: RequestBody) -> Self {
        self.body = Some(body);
        self
    }
}

/// A request body, held zeroizing because a login submission carries percent-encoded credentials.
///
/// Zeroizing this crate's own copy on drop is defense in depth for that copy only: a transport
/// (reqwest, TLS, kernel buffers) makes further copies this type cannot reach. `Debug` prints only
/// the byte length, never the content.
///
/// # Examples
///
/// ```
/// use sqex_proto::RequestBody;
///
/// let body = RequestBody::new(b"payload".to_vec());
/// assert_eq!(body.as_bytes(), b"payload");
/// assert_eq!(format!("{body:?}"), "[7 bytes]");
/// ```
#[derive(Clone)]
pub struct RequestBody(Zeroizing<Vec<u8>>);

impl RequestBody {
    /// Wrap `bytes` as a request body.
    ///
    /// # Examples
    ///
    /// ```
    /// use sqex_proto::RequestBody;
    ///
    /// let body = RequestBody::new(b"payload".to_vec());
    /// assert_eq!(body.as_bytes(), b"payload");
    /// ```
    #[must_use]
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(Zeroizing::new(bytes))
    }

    /// The body's raw bytes.
    ///
    /// # Examples
    ///
    /// ```
    /// use sqex_proto::RequestBody;
    ///
    /// let body = RequestBody::new(vec![1, 2, 3]);
    /// assert_eq!(body.as_bytes(), &[1, 2, 3]);
    /// ```
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

/// A response a [`Transport`] reads back off the wire.
///
/// A `Transport` implementation constructs this directly from what it read; this crate never
/// constructs one except in its own tests and doctests.
///
/// # Examples
///
/// ```
/// use sqex_proto::ProtoResponse;
///
/// let response = ProtoResponse::new(200, b"ok".to_vec());
/// assert!(response.is_ok());
/// assert_eq!(response.body, b"ok");
/// ```
#[derive(Debug, Clone)]
pub struct ProtoResponse {
    /// The HTTP status code.
    pub status: u16,
    /// The raw response body.
    pub body: Vec<u8>,
    /// The response headers, in whatever order the transport read them.
    pub headers: Vec<(HeaderName, HeaderValue)>,
}

impl ProtoResponse {
    /// Construct a response with no headers.
    ///
    /// # Examples
    ///
    /// ```
    /// use sqex_proto::ProtoResponse;
    ///
    /// let response = ProtoResponse::new(200, b"ok".to_vec());
    /// assert!(response.headers.is_empty());
    /// ```
    #[must_use]
    pub fn new(status: u16, body: Vec<u8>) -> Self {
        Self {
            status,
            body,
            headers: Vec::new(),
        }
    }

    /// Append a header, builder-style.
    ///
    /// # Examples
    ///
    /// ```
    /// use http::{HeaderName, HeaderValue};
    /// use sqex_proto::ProtoResponse;
    ///
    /// let response = ProtoResponse::new(200, Vec::new())
    ///     .with_header(HeaderName::from_static("date"), HeaderValue::from_static("today"));
    /// assert_eq!(
    ///     response.header(&HeaderName::from_static("date")),
    ///     Some(&HeaderValue::from_static("today"))
    /// );
    /// ```
    #[must_use]
    pub fn with_header(mut self, name: HeaderName, value: HeaderValue) -> Self {
        self.headers.push((name, value));
        self
    }

    /// The value of the first header matching `name`, if any.
    ///
    /// # Examples
    ///
    /// ```
    /// use http::HeaderName;
    /// use sqex_proto::ProtoResponse;
    ///
    /// let response = ProtoResponse::new(200, Vec::new());
    /// assert_eq!(response.header(&HeaderName::from_static("date")), None);
    /// ```
    #[must_use]
    pub fn header(&self, name: &HeaderName) -> Option<&HeaderValue> {
        self.headers.iter().find(|(n, _)| n == name).map(|(_, v)| v)
    }

    /// Whether the status is exactly `200`.
    ///
    /// Every surface in this crate that treats a non-`200` status as an ordinary disposition (a
    /// `204` current-boot answer, a `409`/`410` registration outcome) checks `status` directly
    /// rather than through this method; `is_ok` is the plain "did this succeed" reading used
    /// everywhere else.
    ///
    /// # Examples
    ///
    /// ```
    /// use sqex_proto::ProtoResponse;
    ///
    /// assert!(ProtoResponse::new(200, Vec::new()).is_ok());
    /// assert!(!ProtoResponse::new(204, Vec::new()).is_ok());
    /// ```
    #[must_use]
    pub fn is_ok(&self) -> bool {
        self.status == 200
    }
}

/// A [`Transport`] implementation could not complete a request.
///
/// The message is the one free-form string an implementor outside this crate writes into the
/// protocol's error taxonomy, and it can travel as far as a CLI's stderr. So the type carries the
/// redaction obligation itself rather than merely stating it: the field is private, and every
/// construction runs through [`TransportError::new`], which strips the path, query, and fragment
/// from any URL found in the text. That is the leak this seam has actually had: a client library's
/// own error rendering can produce `error sending request for url (<the whole url>)`, and a
/// login-flow request's URL carries the OAuth session id in its path, so an implementor that passed
/// that rendering straight through would hand a live credential to whatever prints the error.
///
/// # Examples
///
/// ```
/// use sqex_proto::TransportError;
///
/// let err = TransportError::new("error sending request for url (https://a.invalid/x?secret=1)");
/// assert_eq!(err.message(), "error sending request for url (https://a.invalid/…)");
/// ```
#[derive(Debug, Clone, thiserror::Error)]
#[error("transport failure: {message}")]
pub struct TransportError {
    message: String,
}

impl TransportError {
    /// Build a `TransportError`, redacting any URL's path, query, and fragment out of `message`.
    ///
    /// # Examples
    ///
    /// ```
    /// use sqex_proto::TransportError;
    ///
    /// let err = TransportError::new("connection refused");
    /// assert_eq!(err.message(), "connection refused");
    /// ```
    #[must_use]
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: redact_url_paths(&message.into()),
        }
    }

    /// The redacted message text.
    ///
    /// # Examples
    ///
    /// ```
    /// use sqex_proto::TransportError;
    ///
    /// let err = TransportError::new("timed out");
    /// assert_eq!(err.message(), "timed out");
    /// ```
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

/// The seam this crate sends every request through. Implement this over an HTTP client to give the
/// crate a way onto the wire.
///
/// # Examples
///
/// ```
/// use sqex_proto::{ProtoRequest, ProtoResponse, Transport, TransportError};
///
/// struct Fixture;
///
/// #[async_trait::async_trait]
/// impl Transport for Fixture {
///     async fn execute(&self, _req: ProtoRequest) -> Result<ProtoResponse, TransportError> {
///         Ok(ProtoResponse::new(200, b"ok".to_vec()))
///     }
/// }
/// ```
#[async_trait::async_trait]
pub trait Transport: Send + Sync {
    /// Send `req` and return the response, or a [`TransportError`] if the request could not be
    /// completed.
    ///
    /// Never retried by this crate: a caller that wants retries applies its own policy around the
    /// call. An implementation should send `req.headers` unmodified and in order (see
    /// [`check_header_fidelity`]) and must not treat a non-`200` status as a reason to return an
    /// error itself; every surface in this crate that needs to distinguish response statuses reads
    /// [`ProtoResponse::status`](ProtoResponse) itself.
    async fn execute(&self, req: ProtoRequest) -> Result<ProtoResponse, TransportError>;
}

/// Headers a client answers for itself, exempt from [`check_header_fidelity`]'s comparison on both
/// sides.
///
/// `accept-encoding` is the only one. A transport that forwards a declared value verbatim switches
/// off its client's own automatic decompression (that is how mainstream HTTP clients decide
/// whether the caller took over negotiation), which would leave this crate's parsers a compressed
/// body instead of the decoded one they expect. So the header this crate declares records what the
/// reference launcher negotiates, and a transport substitutes its own value: a known fingerprint
/// divergence rather than a silent one (a wire-level test in the composition root's adapter pins
/// what the production client actually appends).
///
/// A client's own late framing additions (`Host`, `Content-Length`) are added below the layer an
/// adapter reads back from when a surface leaves them undeclared, so an undeclared one never
/// reaches this comparison at all. One surface is a deliberate exception:
/// [`check_boot_version`](crate::check_boot_version) declares `Host` explicitly, matching the
/// reference launcher's own explicit `Host` header on that endpoint, so there it is an ordinary
/// declared header in the comparison rather than an implicit framing one.
///
/// # Examples
///
/// ```
/// use sqex_proto::NEGOTIATED_HEADERS;
///
/// assert_eq!(NEGOTIATED_HEADERS[0], http::header::ACCEPT_ENCODING);
/// ```
pub const NEGOTIATED_HEADERS: [HeaderName; 1] = [http::header::ACCEPT_ENCODING];

/// Compare the headers a [`ProtoRequest`] declared against what a transport adapter actually
/// emitted, to catch a translation that reordered them, dropped one, added one, or rewrote a value.
///
/// A transport adapter calls this after translating `req` into its client's own request
/// representation and reading the headers back out of it, so the guard runs in every build profile
/// rather than only under `debug_assert!`. Headers named in [`NEGOTIATED_HEADERS`] are ignored on
/// both sides. This does not catch whatever a client merges into a request *after* it is assembled
/// (a default `Accept`, content negotiation): that is below any API an adapter can read back from,
/// so an adapter owes a separate wire-level test for it (the composition root's adapter has one).
///
/// # Errors
///
/// Returns a [`TransportError`] naming the declared and emitted header sets if they differ in
/// length, order, or header name, or naming the one header whose value changed if only a value
/// diverged. Returns `Ok(())` when the two header lists agree exactly, modulo
/// [`NEGOTIATED_HEADERS`].
///
/// # Examples
///
/// ```
/// use http::{HeaderName, HeaderValue, Method};
/// use sqex_proto::{ProtoRequest, check_header_fidelity};
/// use url::Url;
///
/// let url = Url::parse("https://example.invalid/").unwrap();
/// let req = ProtoRequest::new(Method::GET, url)
///     .header(
///         HeaderName::from_static("user-agent"),
///         HeaderValue::from_static("FFXIV PATCH CLIENT"),
///     )
///     .header(
///         HeaderName::from_static("accept"),
///         HeaderValue::from_static("*/*"),
///     );
///
/// assert!(check_header_fidelity(&req, &req.headers).is_ok());
///
/// let reordered: Vec<_> = req.headers.iter().rev().cloned().collect();
/// assert!(check_header_fidelity(&req, &reordered).is_err());
/// ```
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

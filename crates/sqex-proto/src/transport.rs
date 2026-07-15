//! The network seam.
//!
//! This crate never opens a socket: every request is handed to an injected [`Transport`], whose
//! production implementation (reqwest, with dual-stack dialing) is assembled in the composition root.
//! Tests supply a fixture transport. The crate names neither `reqwest` nor `tokio`; the only async
//! surface is the `async fn` on this trait.

use http::{HeaderName, HeaderValue, Method};
use url::Url;

/// A single HTTP request, fully specified.
///
/// The header list is ordered and complete: a transport emits exactly these headers, in this order,
/// and injects nothing of its own (no default `Accept`, no tracing header). SE plausibly fingerprints
/// the header set, so fidelity is a contract; [`debug_assert_header_fidelity`] lets an adapter check
/// it at the boundary.
#[derive(Debug, Clone)]
pub struct ProtoRequest {
    pub method: Method,
    pub url: Url,
    pub headers: Vec<(HeaderName, HeaderValue)>,
    pub body: Option<Vec<u8>>,
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
    pub fn body(mut self, body: Vec<u8>) -> Self {
        self.body = Some(body);
        self
    }
}

/// A response: the status, the raw body, and any headers a surface needs to read. Most surfaces read
/// only the status and body; the OAuth top page reads the `Date` header (for TOTP skew correction) and
/// session registration will read `X-Patch-Unique-Id`, so a header a transport chooses to surface rides
/// along here. A transport carries only the headers a surface asks for, not the whole response set.
#[derive(Debug, Clone)]
pub struct ProtoResponse {
    pub status: u16,
    pub body: Vec<u8>,
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
/// The message is stable and already redacted; a transport must not surface URLs bearing credentials
/// or raw SE bytes here.
#[derive(Debug, Clone, thiserror::Error)]
#[error("transport failure: {message}")]
pub struct TransportError {
    pub message: String,
}

impl TransportError {
    /// Build a transport error from an already-safe message.
    #[must_use]
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
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
    async fn execute(&self, req: ProtoRequest) -> Result<ProtoResponse, TransportError>;
}

/// Assert, in debug builds only, that `emitted` is exactly the request's declared headers: the same
/// pairs in the same order. A transport adapter calls this after translating a [`ProtoRequest`] into
/// its client's representation and reading the headers back, to catch a client that reordered them or
/// injected a default. A no-op in release builds.
pub fn debug_assert_header_fidelity(req: &ProtoRequest, emitted: &[(HeaderName, HeaderValue)]) {
    debug_assert!(
        req.headers.as_slice() == emitted,
        "transport altered the header set: declared {:?}, emitted {:?}",
        req.headers,
        emitted,
    );
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

    #[test]
    fn fidelity_holds_when_emitted_matches() {
        let url = Url::parse("http://example.invalid/").unwrap();
        let req = ProtoRequest::new(Method::GET, url).header(ua().0, ua().1);
        debug_assert_header_fidelity(&req, &req.headers.clone());
    }

    #[test]
    #[should_panic(expected = "altered the header set")]
    fn fidelity_fires_on_injected_header() {
        let url = Url::parse("http://example.invalid/").unwrap();
        let req = ProtoRequest::new(Method::GET, url).header(ua().0, ua().1);
        let mut emitted = req.headers.clone();
        emitted.push((
            HeaderName::from_static("accept"),
            HeaderValue::from_static("*/*"),
        ));
        debug_assert_header_fidelity(&req, &emitted);
    }
}

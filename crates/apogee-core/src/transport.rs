//! The concrete network transport the core owns.
//!
//! `sqex-proto` never opens a socket; it hands each request to an injected transport. This adapter
//! backs that seam with reqwest. The request contract is exact: emit precisely the declared
//! headers, in order, and inject nothing of the client's own (no default `Accept`, no
//! `Accept-Encoding`), because the header set is plausibly fingerprinted. The request translation
//! and response mapping land with the login flow that first drives this.

use reqwest::header::{DATE, HeaderName};
use sqex_proto::{ProtoRequest, ProtoResponse, Transport, TransportError};
use url::Url;

/// A reqwest-backed [`Transport`]: a pooled client with dual-stack dialing. Internal wiring: the
/// composition root is the only place a concrete transport is assembled, so this type is not exported.
#[derive(Debug, Clone)]
pub(crate) struct HttpTransport {
    client: reqwest::Client,
}

impl HttpTransport {
    /// Wrap a configured reqwest client.
    #[must_use]
    pub(crate) fn new(client: reqwest::Client) -> Self {
        Self { client }
    }
}

#[async_trait::async_trait]
impl Transport for HttpTransport {
    async fn execute(&self, req: ProtoRequest) -> Result<ProtoResponse, TransportError> {
        let mut builder = self.client.request(req.method.clone(), req.url.clone());
        for (name, value) in &req.headers {
            // reqwest runs its own content negotiation (the client enables gzip/deflate); forwarding
            // the declared accept-encoding would suppress its automatic decompression, leaving the
            // parser a compressed body.
            if name.as_str() == "accept-encoding" {
                continue;
            }
            builder = builder.header(name.clone(), value.clone());
        }
        if let Some(body) = &req.body {
            builder = builder.body(body.as_bytes().to_vec());
        }

        let response = builder.send().await.map_err(|err| {
            TransportError::new(format!("request failed: {}", why(&req.url, &err)))
        })?;
        let status = response.status().as_u16();

        // sqex-proto reads only two response headers: the top page's `Date` (for TOTP clock-skew
        // correction) and the registration `X-Patch-Unique-Id`. Copy just those out before consuming
        // the response for its body, rather than cloning the whole header map.
        let uid = HeaderName::from_static("x-patch-unique-id");
        let surfaced = [DATE, uid].map(|name| {
            let value = response.headers().get(&name).cloned();
            (name, value)
        });
        let body = response
            .bytes()
            .await
            .map_err(|err| {
                TransportError::new(format!(
                    "reading response body failed: {}",
                    why(&req.url, &err)
                ))
            })?
            .to_vec();

        let mut out = ProtoResponse::new(status, body);
        for (name, value) in surfaced {
            if let Some(value) = value {
                out = out.with_header(name, value);
            }
        }
        Ok(out)
    }
}

/// Say what went wrong with a request, without quoting the library's own message.
///
/// reqwest renders a failed send as `error sending request for url (<the whole url>)`, and at one
/// step of the login flow that URL's last path segment *is* a credential: the registration POST
/// carries the OAuth session id there. The message does not stay local either. It travels
/// `TransportError` into `ProtoError::Transport` into `CoreError::Proto` and out of the CLI on
/// stderr, so a user on a flaky connection is shown a live session token and pastes it into a bug
/// report.
///
/// The seam this backs already forbade that in writing, and `SessionId` carries a hand-written
/// redacting `Debug` written to make it impossible; routing the id through a URL walked around both.
/// So the host is named and the path is not, which loses nothing a user could act on: which of the
/// endpoints was unreachable is the actionable part, and the path is fixed by the protocol.
fn why(url: &Url, err: &reqwest::Error) -> String {
    let what = if refused_the_certificate(err) {
        "presented a certificate from an authority this launcher does not accept, which is either \
         something on this network reading the connection or Square Enix moving to an authority \
         this build predates; set APOGEE_TLS_SYSTEM_ROOTS=1 to trust this machine's own list instead"
    } else if err.is_timeout() {
        "timed out"
    } else if err.is_connect() {
        "could not be reached"
    } else if err.is_redirect() {
        "redirected too many times"
    } else if err.is_decode() {
        "sent a response that could not be decoded"
    } else if err.is_body() {
        "broke off mid-response"
    } else {
        "failed"
    };
    // Scheme and host, never the path or the query. `host_str` is `None` only for a URL with no
    // authority, which none of the protocol's endpoints is.
    match url.host_str() {
        Some(host) => format!("{} {what}", host),
        None => format!("the request {what}"),
    }
}

/// Whether the handshake failed because nothing would vouch for the certificate.
///
/// Read off the rendering rather than a predicate, because reqwest has none: rustls reports a chain
/// it will not accept through a boxed source that `is_connect` reports along with a refused
/// connection and a dead route. Those three want different sentences. This one is the only failure
/// the launcher itself causes, by narrowing the authorities it accepts (see [`crate::trust`]), so it
/// is also the only one where the answer is a setting rather than the network coming back.
///
/// The rendering is walked and never quoted, so the URL the message above is careful to withhold
/// stays out of it.
fn refused_the_certificate(err: &reqwest::Error) -> bool {
    let mut source: Option<&(dyn std::error::Error + 'static)> = Some(err);
    while let Some(cause) = source {
        let rendered = format!("{cause:?}").to_ascii_lowercase();
        if rendered.contains("unknownissuer") || rendered.contains("invalidcertificate") {
            return true;
        }
        source = cause.source();
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use apogee_test_support::chaos::ChaosServer;
    use reqwest::Method;
    use tokio::io::AsyncWriteExt;

    /// Answer one request with a fixed response carrying `headers`, and hand back the address to send
    /// it to. The request is drained rather than parsed: what is under test is the response side.
    async fn one_shot(headers: &'static str) -> std::io::Result<Url> {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let url = Url::parse(&format!("http://{}/", listener.local_addr()?))
            .map_err(|_| std::io::Error::other("the listener's address is not a url"))?;
        tokio::spawn(async move {
            if let Ok((mut socket, _)) = listener.accept().await {
                let body = "ok";
                let response = format!(
                    "HTTP/1.1 200 OK\r\ncontent-length: {}\r\n{headers}\r\n{body}",
                    body.len()
                );
                let _ = socket.write_all(response.as_bytes()).await;
                let _ = socket.flush().await;
            }
        });
        Ok(url)
    }

    /// The `Date` header comes back off a real socket.
    ///
    /// The one test that fails if the surfaced-header list above stops naming it. Every fixture in
    /// the workspace attaches that header itself, so deleting it from the list switches one-time-code
    /// clock correction off in shipping builds with every other test in the repo still green.
    #[tokio::test]
    async fn the_response_headers_a_surface_reads_come_back_off_the_wire() -> std::io::Result<()> {
        let url = one_shot(
            "date: Wed, 09 Jul 2025 12:00:00 GMT\r\n\
             x-patch-unique-id: UID-TOKEN\r\n\
             set-cookie: session=secret\r\n",
        )
        .await?;
        let transport = HttpTransport::new(reqwest::Client::new());

        let response = transport
            .execute(ProtoRequest::new(Method::GET, url))
            .await
            .map_err(|err| std::io::Error::other(err.message))?;

        assert_eq!(
            response
                .header(&reqwest::header::DATE)
                .and_then(|value| value.to_str().ok()),
            Some("Wed, 09 Jul 2025 12:00:00 GMT")
        );
        assert!(
            response
                .header(&HeaderName::from_static("x-patch-unique-id"))
                .is_some()
        );
        // Nothing beyond the two a surface asks for. A response carries credentials in headers a
        // parser has no business seeing, and the seam's contract is that they do not travel.
        assert_eq!(response.headers.len(), 2, "{:?}", response.headers);
        Ok(())
    }

    /// A refused certificate is named as one, and points at the setting that gets past it.
    ///
    /// The launcher narrows the authorities it will accept, so this is the one connection failure it
    /// causes itself, and the one whose answer is a setting rather than waiting for the network. Told
    /// apart from the others it would otherwise be filed with: reqwest reports it through the same
    /// `is_connect` as a refused connection and a dead route, so before this it read as the login
    /// server being unreachable, which is both false and unactionable.
    ///
    /// Driven through a real handshake against a server whose certificate nothing here vouches for,
    /// because the classification reads a rustls rendering that no fixture can reproduce faithfully.
    #[tokio::test]
    async fn a_refused_certificate_says_so_and_names_the_way_past_it() {
        let server = ChaosServer::builder(1, 64)
            .tls()
            .start()
            .await
            .expect("the chaos server starts");
        let url = Url::parse(server.url("file.bin").as_str()).expect("a url");
        let transport = HttpTransport::new(
            reqwest::Client::builder()
                .tls_built_in_root_certs(false)
                .build()
                .expect("a client trusting nothing"),
        );

        let err = transport
            .execute(ProtoRequest::new(Method::GET, url))
            .await
            .expect_err("a client trusting nothing must refuse this");

        let rendered = format!("{err}");
        assert!(
            rendered.contains("certificate"),
            "a refused certificate was not named as one: {rendered}"
        );
        assert!(
            rendered.contains("APOGEE_TLS_SYSTEM_ROOTS"),
            "the message does not say what to do about it: {rendered}"
        );
        assert!(
            !rendered.contains("could not be reached"),
            "a reachable server was reported unreachable: {rendered}"
        );
    }

    /// Every other connection failure keeps the sentence it had. The classification above reads a
    /// rendering, so it is exactly the shape that starts matching things it was not meant to.
    #[tokio::test]
    async fn a_dead_route_is_still_a_dead_route() {
        let url = Url::parse("http://127.0.0.1:1/").expect("a url");
        let transport = HttpTransport::new(reqwest::Client::new());

        let err = transport
            .execute(ProtoRequest::new(Method::GET, url))
            .await
            .expect_err("nothing listens on port 1");

        let rendered = format!("{err}");
        assert!(rendered.contains("could not be reached"), "{rendered}");
        assert!(!rendered.contains("certificate"), "{rendered}");
    }

    /// The registration step puts the session id in the path, so the whole URL must never reach the
    /// message. Driven against a port nothing listens on, which is the failure a user actually hits.
    #[tokio::test]
    async fn a_failed_request_names_the_host_and_not_the_path() {
        let sentinel = "SESSIONIDSECRET";
        let url =
            Url::parse(&format!("http://127.0.0.1:1/oauth/register/{sentinel}")).expect("a url");
        let transport = HttpTransport::new(reqwest::Client::new());

        let err = transport
            .execute(ProtoRequest::new(Method::POST, url))
            .await
            .expect_err("nothing listens on port 1");

        let rendered = format!("{err} {err:?}");
        assert!(
            !rendered.contains(sentinel),
            "the error carried the credential in the path: {rendered}"
        );
        assert!(
            rendered.contains("127.0.0.1"),
            "the error should still name the host: {rendered}"
        );
    }
}

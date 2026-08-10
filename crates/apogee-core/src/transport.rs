//! The concrete network transport the core owns.
//!
//! `sqex-proto` never opens a socket; it hands each request to an injected transport. This adapter
//! backs that seam with reqwest. The request contract is exact: emit precisely the declared headers, in
//! order, and inject nothing of the client's own beyond `Accept-Encoding`, the one header the client
//! answers for itself (`sqex_proto::NEGOTIATED_HEADERS`); everything else is checked back against the
//! declaration before the request is sent. That read-back happens on the built request, before reqwest
//! merges its own default `Accept: */*` into whatever still omits one, so an undeclared `Accept` reaches
//! the wire invisibly to the check: every `sqex-proto` surface declares `accept` explicitly for exactly
//! this reason, keeping the wire byte unchanged while bringing it inside the contract.

use reqwest::header::{DATE, HeaderName, HeaderValue};
use sqex_proto::{
    NEGOTIATED_HEADERS, ProtoRequest, ProtoResponse, Transport, TransportError,
    check_header_fidelity,
};
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
            // parser a compressed body. This is the one header the seam's contract lets a client
            // answer for itself, and the check below is narrowed to match.
            if NEGOTIATED_HEADERS.contains(name) {
                continue;
            }
            builder = builder.header(name.clone(), value.clone());
        }
        if let Some(body) = &req.body {
            builder = builder.body(body.as_bytes().to_vec());
        }

        // Build first and read the headers back out of reqwest's own representation, rather than
        // sending straight from the builder. The header set is what SE fingerprints, and the loop
        // above is one edit away from reordering or dropping part of it; reading back is what makes
        // the seam's fidelity contract something this adapter proves rather than promises.
        let request = builder.build().map_err(|err| {
            TransportError::new(format!(
                "building the request failed: {}",
                why(&req.url, &err)
            ))
        })?;
        let emitted: Vec<(HeaderName, HeaderValue)> = request
            .headers()
            .iter()
            .map(|(name, value)| (name.clone(), value.clone()))
            .collect();
        check_header_fidelity(&req, &emitted)?;

        let response = self.client.execute(request).await.map_err(|err| {
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
    } else if crate::redirect::refusal(err) {
        "answered with a redirect, which this launcher does not follow on a request carrying an \
         account credential"
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
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;
    use apogee_test_support::chaos::ChaosServer;
    use reqwest::Method;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::task::JoinHandle;

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

    /// The mirror of [`one_shot`]: answer one request and hand back the request head as it arrived on
    /// the socket, so a test can read the header set SE would see rather than the one this process
    /// meant to send.
    async fn capturing_head() -> std::io::Result<(Url, JoinHandle<String>)> {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let url = Url::parse(&format!("http://{}/oauth/top", listener.local_addr()?))
            .map_err(|_| std::io::Error::other("the listener's address is not a url"))?;
        let captured = tokio::spawn(async move {
            let Ok((mut socket, _)) = listener.accept().await else {
                return String::new();
            };
            let mut buf = vec![0u8; 8192];
            let read = socket.read(&mut buf).await.unwrap_or(0);
            let response = "HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nok";
            let _ = socket.write_all(response.as_bytes()).await;
            let _ = socket.flush().await;
            String::from_utf8_lossy(&buf[..read]).into_owned()
        });
        Ok((url, captured))
    }

    /// Count what reaches a second host, and answer each of its callers with a plain 200 so a client
    /// that followed a redirect here completes rather than failing for an unrelated reason. The
    /// counter is what a test reads: a request that arrives is one that carried the credential.
    async fn counting_host() -> std::io::Result<(String, std::sync::Arc<AtomicUsize>)> {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        let arrived = std::sync::Arc::new(AtomicUsize::new(0));
        let counter = std::sync::Arc::clone(&arrived);
        tokio::spawn(async move {
            while let Ok((mut socket, _)) = listener.accept().await {
                counter.fetch_add(1, Ordering::SeqCst);
                tokio::spawn(async move {
                    let mut buf = [0u8; 8192];
                    let _ = socket.read(&mut buf).await;
                    let _ = socket
                        .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nok")
                        .await;
                    let _ = socket.flush().await;
                });
            }
        });
        Ok((format!("http://{addr}/moved"), arrived))
    }

    /// The client the composition root ships hands nothing to the host a redirect names.
    ///
    /// A 307 keeps the method and the body, so following one moves the submitted password to
    /// whatever the answer points at, and the fidelity check above never sees that second request:
    /// reqwest builds it below this layer, adds a `referer`, and drops the `cookie`. The counting
    /// host is what makes the refusal legible as one, since a test that only asserted an error would
    /// pass against a client that followed the hop and failed for some other reason.
    ///
    /// Driven through `http_transport` rather than a client assembled here: the policy is client-wide
    /// wiring, so this is the test that reddens if the composition root stops applying it.
    #[tokio::test]
    async fn a_redirect_is_refused_before_the_credential_can_follow_it() -> std::io::Result<()> {
        let sentinel = "PASSWORDSECRET";
        let (elsewhere, arrived) = counting_host().await?;
        let url = one_shot_redirect(&elsewhere).await?;
        let request = ProtoRequest::new(Method::POST, url)
            .header(
                HeaderName::from_static("user-agent"),
                HeaderValue::from_static("SQEXAuthor/2.0.0(Windows 6.2; ja-jp; 1588d5721c)"),
            )
            .header(
                HeaderName::from_static("accept"),
                HeaderValue::from_static("image/gif, */*"),
            )
            .header(
                HeaderName::from_static("cookie"),
                HeaderValue::from_static("_rsid=\"\""),
            )
            .body(sqex_proto::RequestBody::new(
                format!("pwd={sentinel}").into_bytes(),
            ));

        let transport = crate::composition::http_transport()
            .map_err(|err| std::io::Error::other(format!("{err:?}")))?;
        let err = transport
            .execute(request)
            .await
            .expect_err("a redirect must not be followed");

        assert_eq!(
            arrived.load(Ordering::SeqCst),
            0,
            "the redirect target was contacted, so the submitted body followed the hop"
        );
        let rendered = format!("{err} {err:?}");
        assert!(rendered.contains("redirect"), "{rendered}");
        assert!(!rendered.contains("could not be reached"), "{rendered}");
        assert!(!rendered.contains(sentinel), "{rendered}");
        Ok(())
    }

    /// Answer one request with a 307 pointing at `target`, and hand back the URL to send it to.
    async fn one_shot_redirect(target: &str) -> std::io::Result<Url> {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let url = Url::parse(&format!(
            "http://{}/oauth/ffxivarr/login/login.send",
            listener.local_addr()?
        ))
        .map_err(|_| std::io::Error::other("the listener's address is not a url"))?;
        let response = format!(
            "HTTP/1.1 307 Temporary Redirect\r\nLocation: {target}\r\n\
             content-length: 0\r\nconnection: close\r\n\r\n"
        );
        tokio::spawn(async move {
            if let Ok((mut socket, _)) = listener.accept().await {
                let mut buf = [0u8; 8192];
                let _ = socket.read(&mut buf).await;
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
            .map_err(|err| std::io::Error::other(err.message().to_owned()))?;

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

    /// What SE actually sees, out of the client the launcher really ships.
    ///
    /// The seam's contract is that a transport emits exactly the declared headers, in order, and adds
    /// nothing of its own; `NEGOTIATED_HEADERS` narrows it by the one header reqwest answers for
    /// itself. A socket is the only vantage point where that narrowing is visible, and the only one
    /// that sees what a client merges *after* a request is built, which is where reqwest applies both
    /// its negotiated encoding and any configured default header. So this drives the composition
    /// root's own transport rather than a client assembled here: a default header added to that client
    /// reddens this test, and nothing else in the repository would notice.
    ///
    /// It is also where the one remaining divergence is legible: the declared `gzip, deflate` never
    /// travels, and reqwest's own unspaced value stands in its place after every declared header.
    /// Pinning the whole head means a dependency bump that changes what reqwest appends reddens this
    /// rather than quietly changing the fingerprint.
    #[tokio::test]
    async fn the_declared_headers_reach_the_wire_and_only_the_encoding_is_substituted()
    -> std::io::Result<()> {
        let (url, captured) = capturing_head().await?;
        let authority = url.authority().to_owned();
        let request = ProtoRequest::new(Method::POST, url)
            .header(
                HeaderName::from_static("user-agent"),
                HeaderValue::from_static("SQEXAuthor/2.0.0(Windows 6.2; ja-jp; 1588d5721c)"),
            )
            .header(
                HeaderName::from_static("accept"),
                HeaderValue::from_static("image/gif, */*"),
            )
            .header(
                HeaderName::from_static("accept-encoding"),
                HeaderValue::from_static("gzip, deflate"),
            )
            .header(
                HeaderName::from_static("accept-language"),
                HeaderValue::from_static("en-US,en;q=0.9"),
            )
            .header(
                HeaderName::from_static("cookie"),
                HeaderValue::from_static("_rsid=\"\""),
            )
            .body(sqex_proto::RequestBody::new(b"body".to_vec()));

        let transport = crate::composition::http_transport()
            .map_err(|err| std::io::Error::other(format!("{err:?}")))?;
        transport
            .execute(request)
            .await
            .map_err(|err| std::io::Error::other(err.message().to_owned()))?;

        let head = captured.await.map_err(std::io::Error::other)?;
        let lines: Vec<&str> = head
            .split("\r\n")
            .skip(1)
            .take_while(|line| !line.is_empty())
            .collect();
        assert_eq!(
            lines,
            [
                "user-agent: SQEXAuthor/2.0.0(Windows 6.2; ja-jp; 1588d5721c)",
                "accept: image/gif, */*",
                "accept-language: en-US,en;q=0.9",
                "cookie: _rsid=\"\"",
                "accept-encoding: gzip,deflate",
                &format!("host: {authority}"),
                "content-length: 4",
            ],
            "the wire head was: {head}"
        );
        Ok(())
    }

    /// The gap that motivated every `sqex-proto` surface declaring `accept` explicitly: a request that
    /// declares none still gets `Accept: */*` on the wire, added by reqwest below the layer
    /// `check_header_fidelity` reads back from, so the check sees nothing on either side to disagree
    /// about and passes silently. Left undeclared, `gate_status`/`login_status` would fingerprint as
    /// this repository's SQEXAuthor identity paired with an `Accept` the reference launcher itself never
    /// sends.
    #[tokio::test]
    async fn an_undeclared_accept_still_reaches_the_wire() -> std::io::Result<()> {
        let (url, captured) = capturing_head().await?;
        let request = ProtoRequest::new(Method::GET, url).header(
            HeaderName::from_static("user-agent"),
            HeaderValue::from_static("SQEXAuthor/2.0.0(Windows 6.2; ja-jp; 1588d5721c)"),
        );

        let transport = crate::composition::http_transport()
            .map_err(|err| std::io::Error::other(format!("{err:?}")))?;
        transport
            .execute(request)
            .await
            .map_err(|err| std::io::Error::other(err.message().to_owned()))?;

        let head = captured.await.map_err(std::io::Error::other)?;
        let lines: Vec<&str> = head
            .split("\r\n")
            .skip(1)
            .take_while(|line| !line.is_empty())
            .collect();
        let accept_lines: Vec<&str> = lines
            .iter()
            .copied()
            .filter(|line| line.to_ascii_lowercase().starts_with("accept:"))
            .collect();
        assert_eq!(
            accept_lines,
            ["accept: */*"],
            "an undeclared accept should still reach the wire: {lines:?}"
        );
        Ok(())
    }

    /// The fix for the gap above: `frontier.rs` now declares `accept: */*` itself (the identical value
    /// reqwest would otherwise inject), which brings the header inside `check_header_fidelity` and keeps
    /// the wire byte unchanged. Proven here by mirroring `frontier.rs`'s own header set and asserting
    /// `accept` reaches the wire exactly once, with the declared value and in the declared position, not
    /// duplicated by a second one merged in behind it.
    #[tokio::test]
    async fn frontiers_declared_accept_reaches_the_wire_unchanged() -> std::io::Result<()> {
        let (url, captured) = capturing_head().await?;
        let request = ProtoRequest::new(Method::GET, url)
            .header(
                HeaderName::from_static("user-agent"),
                HeaderValue::from_static("SQEXAuthor/2.0.0(Windows 6.2; ja-jp; 1588d5721c)"),
            )
            .header(
                HeaderName::from_static("accept"),
                HeaderValue::from_static("*/*"),
            )
            .header(
                HeaderName::from_static("accept-encoding"),
                HeaderValue::from_static("gzip, deflate"),
            )
            .header(
                HeaderName::from_static("accept-language"),
                HeaderValue::from_static("en-US,en;q=0.9"),
            )
            .header(
                HeaderName::from_static("origin"),
                HeaderValue::from_static("https://launcher.finalfantasyxiv.com"),
            )
            .header(
                HeaderName::from_static("referer"),
                HeaderValue::from_static("https://launcher.finalfantasyxiv.com/"),
            )
            .header(
                HeaderName::from_static("connection"),
                HeaderValue::from_static("Keep-Alive"),
            );

        let transport = crate::composition::http_transport()
            .map_err(|err| std::io::Error::other(format!("{err:?}")))?;
        transport
            .execute(request)
            .await
            .map_err(|err| std::io::Error::other(err.message().to_owned()))?;

        let head = captured.await.map_err(std::io::Error::other)?;
        let lines: Vec<&str> = head
            .split("\r\n")
            .skip(1)
            .take_while(|line| !line.is_empty())
            .collect();
        let accept_lines: Vec<&str> = lines
            .iter()
            .copied()
            .filter(|line| line.to_ascii_lowercase().starts_with("accept:"))
            .collect();
        assert_eq!(
            accept_lines,
            ["accept: */*"],
            "accept should appear exactly once, matching the declaration: {lines:?}"
        );
        Ok(())
    }

    /// The fidelity check is not a debug assertion: a build that ships refuses a request whose header
    /// set is not the one the protocol declared, rather than sending it and hoping.
    ///
    /// The wrong header set here is a reordering reqwest performs on its own. Its request headers are
    /// a `HeaderMap`, which groups repeats of a name together, so a declaration that interleaves them
    /// (`cookie`, `referer`, `cookie`) cannot survive the translation: what comes back out is
    /// `cookie`, `cookie`, `referer`. That is a real, silent alteration of the fingerprint, and the
    /// adapter's own loop is not what causes it.
    ///
    /// Aimed at a port nothing listens on, so the only way this can report an altered header set
    /// rather than an unreachable host is if the check ran before the send. It carries no debug
    /// assertion and passes identically under `--release`.
    #[tokio::test]
    async fn a_header_set_the_client_reorders_is_refused_before_the_send() {
        let transport = HttpTransport::new(reqwest::Client::new());
        let url = Url::parse("http://127.0.0.1:1/oauth/top").expect("a url");
        let request = ProtoRequest::new(Method::GET, url)
            .header(
                HeaderName::from_static("cookie"),
                HeaderValue::from_static("a=1"),
            )
            .header(
                HeaderName::from_static("referer"),
                HeaderValue::from_static("http://example.invalid/"),
            )
            .header(
                HeaderName::from_static("cookie"),
                HeaderValue::from_static("b=2"),
            );

        let err = transport
            .execute(request)
            .await
            .expect_err("a reordered header set must not reach the network");

        let rendered = format!("{err}");
        assert!(rendered.contains("altered the header set"), "{rendered}");
        assert!(
            !rendered.contains("could not be reached"),
            "the request was sent anyway: {rendered}"
        );
        // Names only: the referer's URL and the cookie's value are not diagnostics for an ordering
        // bug, and one of them is a credential on the registration step.
        assert!(!rendered.contains("a=1"), "{rendered}");
        assert!(!rendered.contains("example.invalid"), "{rendered}");
    }
}

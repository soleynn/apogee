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
    let what = if err.is_timeout() {
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

#[cfg(test)]
mod tests {
    use super::*;
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

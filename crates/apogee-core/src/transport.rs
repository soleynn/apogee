//! The concrete network transport the core owns.
//!
//! `sqex-proto` never opens a socket; it hands each request to an injected transport. This adapter
//! backs that seam with reqwest. The request contract is exact: emit precisely the declared
//! headers, in order, and inject nothing of the client's own (no default `Accept`, no
//! `Accept-Encoding`), because the header set is plausibly fingerprinted. The request translation
//! and response mapping land with the login flow that first drives this.

use reqwest::header::{DATE, HeaderName};
use sqex_proto::{ProtoRequest, ProtoResponse, Transport, TransportError};

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

        let response = builder
            .send()
            .await
            .map_err(|err| TransportError::new(format!("request failed: {err}")))?;
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
            .map_err(|err| TransportError::new(format!("reading response body failed: {err}")))?
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

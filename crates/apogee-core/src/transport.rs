//! The concrete network transport the core owns.
//!
//! `sqex-proto` never opens a socket; it hands each request to an injected transport. This adapter
//! backs that seam with reqwest. The request contract is exact: emit precisely the declared
//! headers, in order, and inject nothing of the client's own (no default `Accept`, no
//! `Accept-Encoding`), because the header set is plausibly fingerprinted. The request translation
//! and response mapping land with the login flow that first drives this.

use sqex_proto::{ProtoRequest, ProtoResponse, Transport, TransportError};

/// A reqwest-backed [`Transport`]: a pooled client with dual-stack dialing. Internal wiring: the
/// composition root is the only place a concrete transport is assembled, so this type is not exported.
#[derive(Debug, Clone)]
pub(crate) struct HttpTransport {
    // Held for the request path that lands with the login flow.
    #[allow(dead_code)]
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
    async fn execute(&self, _req: ProtoRequest) -> Result<ProtoResponse, TransportError> {
        todo!("translate the request to reqwest preserving exact header order and map the response")
    }
}

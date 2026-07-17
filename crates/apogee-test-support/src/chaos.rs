//! A scriptable streaming HTTP server for driving the download engine.
//!
//! Binds an ephemeral loopback port and serves a deterministic, position-addressable body that it
//! generates on the fly, so neither the server nor a test holds a large file in memory. Per-server
//! script knobs cover the hostile cases the transport must survive: honoring or ignoring `Range`,
//! dropping the connection partway through, changing the `ETag` between requests, and throttling.
//! `wiremock` can express none of these, which is why this is bespoke.
//!
//! The body bytes come from [`generate_into`]: a test computes the same bytes (and their hash) with
//! that function, so a ranged response and a full response reproduce identical content.

use std::convert::Infallible;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use bytes::Bytes;
use http_body_util::StreamBody;
use hyper::body::{Frame, Incoming};
use hyper::header::{
    ACCEPT_RANGES, CONTENT_LENGTH, CONTENT_RANGE, ETAG, HeaderValue, IF_RANGE, LAST_MODIFIED, RANGE,
};
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use sha2::{Digest, Sha256};
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tokio_rustls::TlsAcceptor;
use tokio_stream::wrappers::ReceiverStream;
use tokio_util::sync::{CancellationToken, DropGuard};
use url::Url;

/// The response body: generated chunks delivered over a channel, so an error frame can end a
/// response early to simulate a dropped connection.
type ChaosBody = StreamBody<ReceiverStream<Result<Frame<Bytes>, std::io::Error>>>;

/// Counters a test asserts against, updated as the server works.
#[derive(Debug, Default)]
pub struct Stats {
    requests: AtomicU64,
    bytes_served: AtomicU64,
}

impl Stats {
    /// How many requests the server has accepted.
    #[must_use]
    pub fn requests(&self) -> u64 {
        self.requests.load(Ordering::SeqCst)
    }

    /// How many body bytes the server has written across all responses. The waste-budget assertion:
    /// a resumed download must not re-fetch more than the interrupted tail.
    #[must_use]
    pub fn bytes_served(&self) -> u64 {
        self.bytes_served.load(Ordering::SeqCst)
    }
}

/// The scripted behavior of one server.
#[derive(Debug, Clone)]
struct Config {
    seed: u64,
    len: u64,
    /// Fixed bytes to serve instead of the generated body (e.g. a real tarball fixture). When set,
    /// `len` equals its length.
    body: Option<Arc<Vec<u8>>>,
    accept_ranges: bool,
    drop_after: Option<u64>,
    etag: Option<String>,
    etag_after: Option<(u64, String)>,
    last_modified: Option<String>,
    last_modified_after: Option<(u64, String)>,
    range_not_satisfiable: bool,
    throttle: Option<Duration>,
    chunk: usize,
    tls: bool,
}

/// A running chaos server. Dropping it shuts the server down (the held [`DropGuard`] cancels the
/// accept loop and all in-flight connections).
#[derive(Debug)]
pub struct ChaosServer {
    base: Url,
    stats: Arc<Stats>,
    cert_der: Option<Vec<u8>>,
    _guard: DropGuard,
}

impl ChaosServer {
    /// Configure a server that serves `len` deterministic bytes generated from `seed`. Ranges are
    /// honored by default; every other knob is off.
    #[must_use]
    pub fn builder(seed: u64, len: u64) -> ChaosServerBuilder {
        ChaosServerBuilder {
            cfg: Config {
                seed,
                len,
                body: None,
                accept_ranges: true,
                drop_after: None,
                etag: None,
                etag_after: None,
                last_modified: None,
                last_modified_after: None,
                range_not_satisfiable: false,
                throttle: None,
                chunk: 64 * 1024,
                tls: false,
            },
        }
    }

    /// Configure a server that serves the exact `bytes` provided instead of generated content, so a
    /// test can download a real fixture (e.g. a runner tarball) through the same Range/resume/drop
    /// machinery. `stats().bytes_served()` still backs the waste-budget assertion.
    #[must_use]
    pub fn serving(bytes: impl Into<Vec<u8>>) -> ChaosServerBuilder {
        let bytes = bytes.into();
        let mut builder = Self::builder(0, bytes.len() as u64);
        builder.cfg.body = Some(Arc::new(bytes));
        builder
    }

    async fn start(cfg: Config) -> std::io::Result<Self> {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let addr: SocketAddr = listener.local_addr()?;
        let (scheme, acceptor, cert_der) = if cfg.tls {
            let (cert, key) = generate_cert()?;
            ("https", Some(build_acceptor(&cert, &key)?), Some(cert))
        } else {
            ("http", None, None)
        };
        let base = Url::parse(&format!("{scheme}://{addr}/"))
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
        let stats = Arc::new(Stats::default());
        let cfg = Arc::new(cfg);
        let token = CancellationToken::new();

        let loop_stats = stats.clone();
        let loop_token = token.clone();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    () = loop_token.cancelled() => break,
                    accepted = listener.accept() => {
                        let Ok((stream, _)) = accepted else { continue };
                        let cfg = cfg.clone();
                        let stats = loop_stats.clone();
                        let conn_token = loop_token.clone();
                        let acceptor = acceptor.clone();
                        tokio::spawn(async move {
                            match acceptor {
                                Some(tls) => {
                                    if let Ok(stream) = tls.accept(stream).await {
                                        serve(TokioIo::new(stream), cfg, stats, conn_token).await;
                                    }
                                }
                                None => serve(TokioIo::new(stream), cfg, stats, conn_token).await,
                            }
                        });
                    }
                }
            }
        });

        Ok(Self {
            base,
            stats,
            cert_der,
            _guard: token.drop_guard(),
        })
    }

    /// The server's base URL (`http://127.0.0.1:PORT/`, or `https://` under [`tls`](ChaosServerBuilder::tls)).
    #[must_use]
    pub fn base_url(&self) -> &Url {
        &self.base
    }

    /// The self-signed certificate (DER) the server presents over TLS, for a client to trust via
    /// `reqwest::Certificate::from_der`. `None` when not running over TLS.
    #[must_use]
    pub fn cert_der(&self) -> Option<&[u8]> {
        self.cert_der.as_deref()
    }

    /// The URL of `path` under this server.
    #[must_use]
    pub fn url(&self, path: &str) -> Url {
        self.base.join(path).unwrap_or_else(|_| self.base.clone())
    }

    /// The server's live counters.
    #[must_use]
    pub fn stats(&self) -> &Stats {
        &self.stats
    }
}

/// Builds a [`ChaosServer`].
#[derive(Debug)]
pub struct ChaosServerBuilder {
    cfg: Config,
}

impl ChaosServerBuilder {
    /// Whether the server honors `Range` and advertises `Accept-Ranges` (on by default). When off it
    /// answers every request with the full body and `200`, exercising the demotion-to-restart path.
    #[must_use]
    pub fn accept_ranges(mut self, on: bool) -> Self {
        self.cfg.accept_ranges = on;
        self
    }

    /// Close the connection after serving this many body bytes on the first request only, leaving a
    /// truncated `.part` for a resume. Later requests complete normally.
    #[must_use]
    pub fn drop_after(mut self, bytes: u64) -> Self {
        self.cfg.drop_after = Some(bytes);
        self
    }

    /// The strong `ETag` served initially.
    #[must_use]
    pub fn etag(mut self, tag: impl Into<String>) -> Self {
        self.cfg.etag = Some(tag.into());
        self
    }

    /// Serve a different `ETag` starting with the request after `requests`, so a resume's `If-Range`
    /// no longer matches and the server falls back to a full `200`.
    #[must_use]
    pub fn change_etag_after(mut self, requests: u64, tag: impl Into<String>) -> Self {
        self.cfg.etag_after = Some((requests, tag.into()));
        self
    }

    /// The `Last-Modified` value served initially (a strong validator for `If-Range` when no `ETag`
    /// is offered).
    #[must_use]
    pub fn last_modified(mut self, value: impl Into<String>) -> Self {
        self.cfg.last_modified = Some(value.into());
        self
    }

    /// Serve a different `Last-Modified` starting with the request after `requests`, so a resume's
    /// date `If-Range` no longer matches and the server falls back to a full `200`.
    #[must_use]
    pub fn change_last_modified_after(mut self, requests: u64, value: impl Into<String>) -> Self {
        self.cfg.last_modified_after = Some((requests, value.into()));
        self
    }

    /// Answer any request carrying a `Range` header with `416 Range Not Satisfiable`, forcing a
    /// resume to demote to a fresh `200` from zero.
    #[must_use]
    pub fn range_not_satisfiable(mut self, on: bool) -> Self {
        self.cfg.range_not_satisfiable = on;
        self
    }

    /// Serve over HTTPS with a freshly generated self-signed certificate for `127.0.0.1`. The
    /// certificate is exposed via [`ChaosServer::cert_der`] so a client can be built to trust it.
    #[must_use]
    pub fn tls(mut self) -> Self {
        self.cfg.tls = true;
        self
    }

    /// Sleep between body chunks.
    #[must_use]
    pub fn throttle(mut self, delay: Duration) -> Self {
        self.cfg.throttle = Some(delay);
        self
    }

    /// The body chunk size (bytes per frame); smaller makes `drop_after` land more precisely.
    #[must_use]
    pub fn chunk(mut self, bytes: usize) -> Self {
        self.cfg.chunk = bytes.max(1);
        self
    }

    /// Bind the ephemeral port and start serving.
    ///
    /// # Errors
    /// An [`std::io::Error`] if the loopback listener cannot bind.
    pub async fn start(self) -> std::io::Result<ChaosServer> {
        ChaosServer::start(self.cfg).await
    }
}

async fn handle(
    req: Request<Incoming>,
    cfg: Arc<Config>,
    stats: Arc<Stats>,
) -> Result<Response<ChaosBody>, Infallible> {
    let request_index = stats.requests.fetch_add(1, Ordering::SeqCst) + 1;

    if req.method() != Method::GET {
        return Ok(status_only(StatusCode::METHOD_NOT_ALLOWED));
    }

    // A server that cannot satisfy the range refuses every ranged request, forcing a resume to demote
    // to a fresh request from zero.
    if cfg.range_not_satisfiable && req.headers().get(RANGE).is_some() {
        return Ok(status_only(StatusCode::RANGE_NOT_SATISFIABLE));
    }

    let current_etag = match &cfg.etag_after {
        Some((after, new)) if request_index > *after => Some(new.clone()),
        _ => cfg.etag.clone(),
    };
    let current_last_modified = match &cfg.last_modified_after {
        Some((after, new)) if request_index > *after => Some(new.clone()),
        _ => cfg.last_modified.clone(),
    };

    // Honor a `bytes=START-` range only when ranges are enabled and any `If-Range` still matches the
    // current `ETag` or `Last-Modified`.
    let range_start = if cfg.accept_ranges {
        parse_range_start(req.headers().get(RANGE))
    } else {
        None
    };
    let if_range_matches = match req.headers().get(IF_RANGE) {
        Some(sent) => {
            let sent = sent.as_bytes();
            current_etag.as_deref().map(str::as_bytes) == Some(sent)
                || current_last_modified.as_deref().map(str::as_bytes) == Some(sent)
        }
        None => true,
    };
    let (start, status) = match range_start {
        Some(s) if if_range_matches && s <= cfg.len => (s, StatusCode::PARTIAL_CONTENT),
        _ => (0, StatusCode::OK),
    };

    let body_len = cfg.len - start;
    let mut builder = Response::builder()
        .status(status)
        .header(CONTENT_LENGTH, body_len);
    if cfg.accept_ranges {
        builder = builder.header(ACCEPT_RANGES, "bytes");
    }
    if status == StatusCode::PARTIAL_CONTENT {
        builder = builder.header(
            CONTENT_RANGE,
            format!("bytes {}-{}/{}", start, cfg.len - 1, cfg.len),
        );
    }
    if let Some(tag) = &current_etag {
        builder = builder.header(ETAG, tag.clone());
    }
    if let Some(value) = &current_last_modified {
        builder = builder.header(LAST_MODIFIED, value.clone());
    }

    let (tx, rx) = mpsc::channel::<Result<Frame<Bytes>, std::io::Error>>(4);
    // Only the first request drops; a resume must be able to finish.
    let drop_after = if request_index == 1 {
        cfg.drop_after
    } else {
        None
    };
    let body_cfg = cfg.clone();
    let body_stats = stats.clone();
    tokio::spawn(async move {
        let mut off = start;
        let mut served = 0u64;
        let mut buf = vec![0u8; body_cfg.chunk];
        while off < body_cfg.len {
            if let Some(limit) = drop_after
                && served >= limit
            {
                let _ = tx
                    .send(Err(std::io::Error::new(
                        std::io::ErrorKind::ConnectionReset,
                        "chaos: dropped mid-body",
                    )))
                    .await;
                return;
            }
            let this = usize::try_from((body_cfg.len - off).min(body_cfg.chunk as u64))
                .unwrap_or(body_cfg.chunk);
            match &body_cfg.body {
                Some(bytes) => {
                    let start = off as usize;
                    buf[..this].copy_from_slice(&bytes[start..start + this]);
                }
                None => generate_into(body_cfg.seed, off, &mut buf[..this]),
            }
            if let Some(delay) = body_cfg.throttle {
                tokio::time::sleep(delay).await;
            }
            if tx
                .send(Ok(Frame::data(Bytes::copy_from_slice(&buf[..this]))))
                .await
                .is_err()
            {
                return; // the client hung up
            }
            body_stats
                .bytes_served
                .fetch_add(this as u64, Ordering::SeqCst);
            off += this as u64;
            served += this as u64;
        }
    });

    let body = StreamBody::new(ReceiverStream::new(rx));
    Ok(builder
        .body(body)
        .unwrap_or_else(|_| status_only(StatusCode::INTERNAL_SERVER_ERROR)))
}

/// Serve one HTTP/1 connection over any transport (plain or TLS-wrapped), until it closes or the
/// server shuts down.
async fn serve<I>(io: I, cfg: Arc<Config>, stats: Arc<Stats>, token: CancellationToken)
where
    I: hyper::rt::Read + hyper::rt::Write + Unpin + Send + 'static,
{
    let service = service_fn(move |req| handle(req, cfg.clone(), stats.clone()));
    let conn = hyper::server::conn::http1::Builder::new().serve_connection(io, service);
    tokio::select! {
        () = token.cancelled() => {}
        _ = conn => {}
    }
}

/// A fresh self-signed certificate (DER) and its PKCS#8 private key (DER), valid for `127.0.0.1`.
fn generate_cert() -> std::io::Result<(Vec<u8>, Vec<u8>)> {
    let mut params = rcgen::CertificateParams::new(Vec::new()).map_err(std::io::Error::other)?;
    params.subject_alt_names = vec![rcgen::SanType::IpAddress(std::net::IpAddr::V4(
        Ipv4Addr::LOCALHOST,
    ))];
    let key_pair = rcgen::KeyPair::generate().map_err(std::io::Error::other)?;
    let cert = params
        .self_signed(&key_pair)
        .map_err(std::io::Error::other)?;
    Ok((cert.der().to_vec(), key_pair.serialize_der()))
}

/// A TLS acceptor presenting `cert_der`/`key_der`, using the ring provider explicitly so it does not
/// depend on a process-wide default being installed.
fn build_acceptor(cert_der: &[u8], key_der: &[u8]) -> std::io::Result<TlsAcceptor> {
    use tokio_rustls::rustls::ServerConfig;
    use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

    let certs = vec![CertificateDer::from(cert_der.to_vec())];
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_der.to_vec()));
    let provider = Arc::new(tokio_rustls::rustls::crypto::ring::default_provider());
    let config = ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(std::io::Error::other)?
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(std::io::Error::other)?;
    Ok(TlsAcceptor::from(Arc::new(config)))
}

/// A response carrying `status` and an empty body.
fn status_only(status: StatusCode) -> Response<ChaosBody> {
    Response::builder()
        .status(status)
        .body(empty_body())
        .unwrap_or_else(|_| Response::new(empty_body()))
}

fn empty_body() -> ChaosBody {
    let (_tx, rx) = mpsc::channel::<Result<Frame<Bytes>, std::io::Error>>(1);
    StreamBody::new(ReceiverStream::new(rx))
}

/// Parse the start offset of an open-ended `bytes=START-` range, ignoring any end. Returns `None`
/// for anything else.
fn parse_range_start(header: Option<&HeaderValue>) -> Option<u64> {
    let raw = header?.to_str().ok()?;
    let spec = raw.strip_prefix("bytes=")?;
    let (start, _end) = spec.split_once('-')?;
    start.parse::<u64>().ok()
}

/// Fill `buf` with the deterministic pseudo-random bytes for the byte offsets
/// `[offset, offset + buf.len())`. Position-addressable (a splitmix64 over the index) so a ranged
/// read reproduces the same bytes as a full read, and a test can recompute any slice or the whole
/// file's hash without the server.
pub fn generate_into(seed: u64, offset: u64, buf: &mut [u8]) {
    for (i, byte) in buf.iter_mut().enumerate() {
        let mut z = offset
            .wrapping_add(i as u64)
            .wrapping_add(seed)
            .wrapping_add(0x9E37_79B9_7F4A_7C15);
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        *byte = (z ^ (z >> 31)) as u8;
    }
}

/// The deterministic bytes for `[offset, offset + len)` as a `Vec`, for small fixtures.
#[must_use]
pub fn generated_vec(seed: u64, offset: u64, len: usize) -> Vec<u8> {
    let mut out = vec![0u8; len];
    generate_into(seed, offset, &mut out);
    out
}

/// The SHA256 of the deterministic body `[0, len)` from `seed`, streamed so a large expectation is
/// never materialized. A test uses this to state the whole-file digest the download must produce.
#[must_use]
pub fn body_sha256(seed: u64, len: u64) -> [u8; 32] {
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 64 * 1024];
    let mut off = 0u64;
    while off < len {
        let want = (len - off).min(buf.len() as u64) as usize;
        generate_into(seed, off, &mut buf[..want]);
        hasher.update(&buf[..want]);
        off += want as u64;
    }
    hasher.finalize().into()
}

/// The SHA256 of a byte slice.
#[must_use]
pub fn sha256_of(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn serves_the_generated_body_and_counts_the_request() {
        let server = ChaosServer::builder(7, 4096).start().await.unwrap();
        let body = reqwest::get(server.url("f.bin"))
            .await
            .unwrap()
            .bytes()
            .await
            .unwrap();
        assert_eq!(&body[..], &generated_vec(7, 0, 4096)[..]);
        assert_eq!(server.stats().requests(), 1);
        assert_eq!(server.stats().bytes_served(), 4096);
    }

    #[tokio::test]
    async fn a_range_request_gets_a_partial_tail() {
        let server = ChaosServer::builder(3, 4096).start().await.unwrap();
        let resp = reqwest::Client::new()
            .get(server.url("f.bin"))
            .header("Range", "bytes=1000-")
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status().as_u16(), 206);
        let body = resp.bytes().await.unwrap();
        assert_eq!(body.len(), 4096 - 1000);
        assert_eq!(&body[..], &generated_vec(3, 1000, 4096 - 1000)[..]);
    }

    #[tokio::test]
    async fn ignoring_ranges_serves_the_full_body_with_200() {
        let server = ChaosServer::builder(1, 2048)
            .accept_ranges(false)
            .start()
            .await
            .unwrap();
        let resp = reqwest::Client::new()
            .get(server.url("f.bin"))
            .header("Range", "bytes=500-")
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status().as_u16(), 200);
        assert_eq!(resp.bytes().await.unwrap().len(), 2048);
    }
}

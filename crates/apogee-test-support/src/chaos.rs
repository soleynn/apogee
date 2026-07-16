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
    ACCEPT_RANGES, CONTENT_LENGTH, CONTENT_RANGE, ETAG, HeaderValue, IF_RANGE, RANGE,
};
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;
use tokio::sync::mpsc;
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
    accept_ranges: bool,
    drop_after: Option<u64>,
    etag: Option<String>,
    etag_after: Option<(u64, String)>,
    throttle: Option<Duration>,
    chunk: usize,
}

/// A running chaos server. Dropping it shuts the server down (the held [`DropGuard`] cancels the
/// accept loop and all in-flight connections).
#[derive(Debug)]
pub struct ChaosServer {
    base: Url,
    stats: Arc<Stats>,
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
                accept_ranges: true,
                drop_after: None,
                etag: None,
                etag_after: None,
                throttle: None,
                chunk: 64 * 1024,
            },
        }
    }

    async fn start(cfg: Config) -> std::io::Result<Self> {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let addr: SocketAddr = listener.local_addr()?;
        let base = Url::parse(&format!("http://{addr}/"))
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
                        let io = TokioIo::new(stream);
                        let cfg = cfg.clone();
                        let stats = loop_stats.clone();
                        let conn_token = loop_token.clone();
                        tokio::spawn(async move {
                            let service = service_fn(move |req| {
                                handle(req, cfg.clone(), stats.clone())
                            });
                            let conn = hyper::server::conn::http1::Builder::new()
                                .serve_connection(io, service);
                            tokio::select! {
                                () = conn_token.cancelled() => {}
                                _ = conn => {}
                            }
                        });
                    }
                }
            }
        });

        Ok(Self {
            base,
            stats,
            _guard: token.drop_guard(),
        })
    }

    /// The server's base URL (`http://127.0.0.1:PORT/`).
    #[must_use]
    pub fn base_url(&self) -> &Url {
        &self.base
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

    let current_etag = match &cfg.etag_after {
        Some((after, new)) if request_index > *after => Some(new.clone()),
        _ => cfg.etag.clone(),
    };

    // Honor a `bytes=START-` range only when ranges are enabled and any `If-Range` still matches.
    let range_start = if cfg.accept_ranges {
        parse_range_start(req.headers().get(RANGE))
    } else {
        None
    };
    let if_range_matches = match req.headers().get(IF_RANGE) {
        Some(sent) => current_etag.as_deref().map(str::as_bytes) == Some(sent.as_bytes()),
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
            generate_into(body_cfg.seed, off, &mut buf[..this]);
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

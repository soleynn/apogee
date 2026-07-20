//! A scriptable streaming HTTP server for driving the download engine.
//!
//! Binds an ephemeral loopback port and serves a deterministic, position-addressable body that it
//! generates on the fly, so neither the server nor a test holds a large file in memory. Per-server
//! script knobs cover the hostile cases the transport must survive: honoring or ignoring `Range`
//! (a single `bytes=START-`, or several ranges as `multipart/byteranges`), dropping the connection
//! partway through, stalling with no EOF, returning `503` + `Retry-After`, rejecting oversized
//! headers, changing the `ETag` between requests, corrupting chosen byte ranges, and throttling.
//! `wiremock` can express none of these, which is why this is bespoke.
//!
//! The body bytes come from [`generate_into`]: a test computes the same bytes (and their hash) with
//! that function, so a ranged response and a full response reproduce identical content.

use std::collections::HashSet;
use std::convert::Infallible;
use std::net::{Ipv4Addr, SocketAddr};
use std::ops::Range;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use bytes::Bytes;
use http_body_util::StreamBody;
use hyper::body::{Frame, Incoming};
use hyper::header::{
    ACCEPT_RANGES, CONTENT_LENGTH, CONTENT_RANGE, CONTENT_TYPE, ETAG, HeaderValue, IF_RANGE,
    LAST_MODIFIED, RANGE, RETRY_AFTER,
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

/// The request headers a test asserts against, captured per request so a header policy (the patch
/// client `User-Agent`, an optional `X-Patch-Unique-Id`) can be checked end to end.
#[derive(Debug, Clone, Default)]
struct RequestHeaders {
    user_agent: Option<String>,
    patch_unique_id: Option<String>,
}

/// Counters a test asserts against, updated as the server works.
#[derive(Debug, Default)]
pub struct Stats {
    requests: AtomicU64,
    bytes_served: AtomicU64,
    served_ranges: Mutex<Vec<Range<u64>>>,
    request_headers: Mutex<Vec<RequestHeaders>>,
    active: AtomicU64,
    peak_concurrency: AtomicU64,
}

impl Stats {
    /// How many requests the server has accepted.
    #[must_use]
    pub fn requests(&self) -> u64 {
        self.requests.load(Ordering::SeqCst)
    }

    /// The high-water mark of response bodies streaming at once, i.e. the peak number of concurrent
    /// connections the client opened. A segmented download drives this above 1; a demoted one holds
    /// it at 1, and it never exceeds the connection cap.
    #[must_use]
    pub fn peak_concurrency(&self) -> u64 {
        self.peak_concurrency.load(Ordering::SeqCst)
    }

    /// How many body bytes the server has written across all responses. The waste-budget assertion:
    /// a resumed download must not re-fetch more than the interrupted tail.
    #[must_use]
    pub fn bytes_served(&self) -> u64 {
        self.bytes_served.load(Ordering::SeqCst)
    }

    /// Every contiguous byte range the server actually served, in served order. Backs the repair
    /// assertion that a block-granular re-fetch touched *only* the dirty ranges, not the whole file.
    #[must_use]
    pub fn served_ranges(&self) -> Vec<Range<u64>> {
        self.served_ranges
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// Record a served range (ignoring an empty one).
    fn record_range(&self, range: Range<u64>) {
        if range.start >= range.end {
            return;
        }
        self.served_ranges
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(range);
    }

    /// The `User-Agent` sent on each request, in request order. `None` where the request carried none.
    #[must_use]
    pub fn user_agents(&self) -> Vec<Option<String>> {
        self.request_headers
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
            .map(|h| h.user_agent.clone())
            .collect()
    }

    /// The `X-Patch-Unique-Id` sent on each request, in request order. `None` where absent.
    #[must_use]
    pub fn patch_unique_ids(&self) -> Vec<Option<String>> {
        self.request_headers
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
            .map(|h| h.patch_unique_id.clone())
            .collect()
    }

    /// Capture the headers a policy test cares about from one request.
    fn record_request_headers(&self, headers: &hyper::HeaderMap) {
        let get = |name: &str| {
            headers
                .get(name)
                .and_then(|v| v.to_str().ok())
                .map(str::to_owned)
        };
        self.request_headers
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(RequestHeaders {
                user_agent: get("user-agent"),
                patch_unique_id: get("x-patch-unique-id"),
            });
    }
}

/// Counts one streaming response body as active for its lifetime, updating the peak-concurrency
/// high-water mark on creation and decrementing on drop (every return path).
struct ActiveGuard(Arc<Stats>);

impl ActiveGuard {
    fn new(stats: Arc<Stats>) -> Self {
        let now = stats.active.fetch_add(1, Ordering::SeqCst) + 1;
        stats.peak_concurrency.fetch_max(now, Ordering::SeqCst);
        Self(stats)
    }
}

impl Drop for ActiveGuard {
    fn drop(&mut self) {
        self.0.active.fetch_sub(1, Ordering::SeqCst);
    }
}

/// How a `503` names its retry delay: either delta-seconds or an HTTP-date, so both `Retry-After`
/// forms a client must parse are exercisable.
#[derive(Debug, Clone)]
pub enum RetryAfter {
    /// `Retry-After: <n>` (delta-seconds).
    Seconds(u64),
    /// `Retry-After: <http-date>` (the caller supplies the exact header string).
    HttpDate(String),
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
    /// Answer the first `n` requests with `503` + this `Retry-After`, then serve normally.
    unavailable_first: Option<(u64, RetryAfter)>,
    /// On the first request only, serve this many bytes then hang forever (a hard stall).
    stall_after: Option<u64>,
    /// Reject a request whose header bytes exceed this budget with `431`, so range packing must stay
    /// under a header-size cap.
    max_header_bytes: Option<usize>,
    /// Byte ranges whose bytes are flipped (`^= 0xFF`) as they are served, so those blocks fail
    /// verification while the rest is pristine.
    corrupt: Vec<Range<u64>>,
    /// Byte ranges corrupted only on their first serve (keyed on range start via `corrupt_fired`),
    /// then served clean: the block fails once, then its re-fetch verifies.
    corrupt_once: Vec<Range<u64>>,
    /// Range starts whose one-shot corruption has already fired, shared across connections. Separate
    /// from `fired` so a corrupt block's start cannot collide with a segment's drop/stall key.
    corrupt_fired: Arc<Mutex<HashSet<u64>>>,
    /// Drop the segment whose range starts at this offset after serving N bytes; fires once per start
    /// (via `fired`) so a re-queued retry of that segment can complete.
    drop_ranges: Vec<(u64, u64)>,
    /// Stall (hang, no EOF) the segment starting at this offset after N bytes; also one-shot.
    stall_ranges: Vec<(u64, u64)>,
    /// Throttle the segment starting at this offset by this inter-chunk delay, every attempt (not
    /// one-shot), so one connection can be held slow to trip stall detection.
    slow_ranges: Vec<(u64, Duration)>,
    /// Segment starts whose one-shot drop/stall has already fired, shared across connections.
    fired: Arc<Mutex<HashSet<u64>>>,
    /// After serving a range in full, end with a connection reset instead of a clean EOF (a real
    /// server RST after the last byte), so the client commits every byte and then sees an error - the
    /// empty-remainder path that must still complete the download.
    reset_after_range: bool,
    /// The boundary string for a `multipart/byteranges` response (a request with several ranges).
    boundary: String,
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
                unavailable_first: None,
                stall_after: None,
                max_header_bytes: None,
                corrupt: Vec::new(),
                corrupt_once: Vec::new(),
                corrupt_fired: Arc::new(Mutex::new(HashSet::new())),
                drop_ranges: Vec::new(),
                stall_ranges: Vec::new(),
                slow_ranges: Vec::new(),
                fired: Arc::new(Mutex::new(HashSet::new())),
                reset_after_range: false,
                boundary: "chaos_boundary".to_string(),
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

    /// Answer the first `times` requests with `503 Service Unavailable` and the given `Retry-After`,
    /// then serve normally. Exercises the client's backoff-and-retry.
    #[must_use]
    pub fn service_unavailable(mut self, times: u64, retry_after: RetryAfter) -> Self {
        self.cfg.unavailable_first = Some((times, retry_after));
        self
    }

    /// On the first request only, serve `bytes` body bytes and then hang with no further data and no
    /// EOF, so the client's no-progress timeout must fire. Later requests complete, so a resume can
    /// finish (like [`drop_after`](Self::drop_after), but a silent stall rather than a reset).
    #[must_use]
    pub fn stall_after(mut self, bytes: u64) -> Self {
        self.cfg.stall_after = Some(bytes);
        self
    }

    /// Reject any request whose header bytes (method + path + header names and values) exceed `max`
    /// with `431 Request Header Fields Too Large`. Keep `max` below hyper's own connection-level
    /// limit so this app-level rejection is the one that fires. Forces the client to cap
    /// ranges-per-request rather than pack an unbounded `Range` header.
    #[must_use]
    pub fn max_request_header_bytes(mut self, max: usize) -> Self {
        self.cfg.max_header_bytes = Some(max);
        self
    }

    /// Serve `range` with its bytes flipped (`^= 0xFF`), so that block fails its hash while every
    /// other block stays pristine. Repeatable: call once per corrupt block. Combined with
    /// [`ChaosServer::stats`]'s `served_ranges`, this drives the "repair re-fetches only the dirty
    /// blocks" assertion.
    #[must_use]
    pub fn corrupt_range(mut self, range: Range<u64>) -> Self {
        self.cfg.corrupt.push(range);
        self
    }

    /// Serve `range` corrupted (`^= 0xFF`) on its first serve only, then clean on every serve after:
    /// the block fails its hash once and its targeted re-fetch verifies. Fires once per range start.
    /// Combined with `served_ranges`, this drives the "repair re-fetches only the dirty block, and
    /// then succeeds" assertion.
    #[must_use]
    pub fn corrupt_range_once(mut self, range: Range<u64>) -> Self {
        self.cfg.corrupt_once.push(range);
        self
    }

    /// Drop the connection serving the segment whose `Range` starts at `start`, after that segment has
    /// sent `after` bytes. Unlike [`drop_after`](Self::drop_after) (keyed on the global first request),
    /// this targets one segment under concurrency; it fires once, so the re-queued retry completes.
    #[must_use]
    pub fn drop_range_at(mut self, start: u64, after: u64) -> Self {
        self.cfg.drop_ranges.push((start, after));
        self
    }

    /// Stall (hang with no EOF) the connection serving the segment whose `Range` starts at `start`,
    /// after that segment has sent `after` bytes. One-shot, so a re-queued retry can finish. Drives
    /// stall-detection-then-recovery under concurrency.
    #[must_use]
    pub fn stall_range_at(mut self, start: u64, after: u64) -> Self {
        self.cfg.stall_ranges.push((start, after));
        self
    }

    /// Throttle the segment whose `Range` starts at `start` by sleeping `delay` between its chunks,
    /// on every attempt (not one-shot). A `delay` beyond the client's stall window keeps that segment
    /// perpetually slow, so its retry budget is exhausted and the job fails as stalled.
    #[must_use]
    pub fn slow_range(mut self, start: u64, delay: Duration) -> Self {
        self.cfg.slow_ranges.push((start, delay));
        self
    }

    /// End every fully-served range with a connection reset instead of a clean EOF, so the client
    /// commits all the range's bytes and then sees an error. Exercises the segmented engine's
    /// completion check on the empty-remainder path (a real server RST after the last byte).
    #[must_use]
    pub fn reset_after_range(mut self) -> Self {
        self.cfg.reset_after_range = true;
        self
    }

    /// The boundary string used in a `multipart/byteranges` response (served when a request carries
    /// more than one range). A *hostile* boundary is one that also occurs inside a part's body: pair
    /// this with [`ChaosServer::serving`] over bytes that embed `\r\n--<boundary>\r\n` so a parser
    /// that scans for the delimiter instead of honoring each part's declared `Content-Range`/length
    /// mis-splits the stream.
    #[must_use]
    pub fn multipart_boundary(mut self, boundary: impl Into<String>) -> Self {
        self.cfg.boundary = boundary.into();
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
    stats.record_request_headers(req.headers());

    if req.method() != Method::GET {
        return Ok(status_only(StatusCode::METHOD_NOT_ALLOWED));
    }

    if let Some(max) = cfg.max_header_bytes
        && request_header_bytes(&req) > max
    {
        return Ok(status_only(StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE));
    }

    // The first N requests are refused with 503 + Retry-After, then service resumes, so a retry loop
    // is exercised end to end.
    if let Some((times, retry_after)) = &cfg.unavailable_first
        && request_index <= *times
    {
        return Ok(service_unavailable(retry_after));
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
    let range_end = if cfg.accept_ranges {
        parse_range_end(req.headers().get(RANGE))
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

    // A request carrying several comma-separated ranges becomes a `multipart/byteranges` response.
    // Everything the download engine sends (no range, or one `bytes=START-`) falls through to the
    // flat single-stream path below, left byte-identical so its resume/overshoot timing is unchanged.
    if cfg.accept_ranges && if_range_matches && header_has_multiple_ranges(req.headers().get(RANGE))
    {
        let ranges = parse_ranges(req.headers().get(RANGE), cfg.len);
        if ranges.len() > 1 {
            return Ok(multipart_response(&ranges, &cfg, &stats));
        }
    }

    let (start, status) = match range_start {
        Some(s) if if_range_matches && s <= cfg.len => (s, StatusCode::PARTIAL_CONTENT),
        _ => (0, StatusCode::OK),
    };
    // A closed range `bytes=start-(end-1)` stops at its declared end; an open range or a demoted 200
    // runs to EOF.
    let end = match range_end {
        Some(e) if status == StatusCode::PARTIAL_CONTENT => e.min(cfg.len),
        _ => cfg.len,
    };

    let body_len = end - start;
    let mut builder = Response::builder()
        .status(status)
        .header(CONTENT_LENGTH, body_len);
    if cfg.accept_ranges {
        builder = builder.header(ACCEPT_RANGES, "bytes");
    }
    if status == StatusCode::PARTIAL_CONTENT {
        builder = builder.header(
            CONTENT_RANGE,
            format!("bytes {}-{}/{}", start, end - 1, cfg.len),
        );
    }
    if let Some(tag) = &current_etag {
        builder = builder.header(ETAG, tag.clone());
    }
    if let Some(value) = &current_last_modified {
        builder = builder.header(LAST_MODIFIED, value.clone());
    }

    let (tx, rx) = mpsc::channel::<Result<Frame<Bytes>, std::io::Error>>(4);
    // Only the first request drops or stalls globally; a resume must be able to finish.
    let (mut drop_after, mut stall_after) = if request_index == 1 {
        (cfg.drop_after, cfg.stall_after)
    } else {
        (None, None)
    };
    // Per-segment hostility, keyed on the range start. Drop/stall fire once per start (via `fired`),
    // so a re-queued retry completes; `slow_range` throttles every attempt so a segment stays slow.
    let mut throttle = cfg.throttle;
    if status == StatusCode::PARTIAL_CONTENT {
        if let Some(&(_, delay)) = cfg.slow_ranges.iter().find(|(s, _)| *s == start) {
            throttle = Some(delay);
        }
        let mut fired = cfg.fired.lock().unwrap_or_else(PoisonError::into_inner);
        if !fired.contains(&start) {
            if let Some(&(_, after)) = cfg.drop_ranges.iter().find(|(s, _)| *s == start) {
                drop_after = Some(after);
                fired.insert(start);
            } else if let Some(&(_, after)) = cfg.stall_ranges.iter().find(|(s, _)| *s == start) {
                stall_after = Some(after);
                fired.insert(start);
            }
        }
    }
    // Corruption for this response: the always-on ranges, plus any one-shot range still armed that
    // this response fully covers. A one-shot range corrupts its first full serve (failing that block's
    // hash) and is clean on the re-fetch, so a block-granular repair can succeed. Requiring full
    // containment means a `bytes=0-0` capability probe never trips a range that starts at 0.
    let mut effective_corrupt = cfg.corrupt.clone();
    if !cfg.corrupt_once.is_empty() {
        let mut fired = cfg
            .corrupt_fired
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        for range in &cfg.corrupt_once {
            let contains = range.start >= start && range.end <= end;
            if contains && fired.insert(range.start) {
                effective_corrupt.push(range.clone());
            }
        }
    }

    let body_cfg = cfg.clone();
    let body_stats = stats.clone();
    let body_end = end;
    tokio::spawn(async move {
        let _active = ActiveGuard::new(body_stats.clone());
        let mut off = start;
        let mut served = 0u64;
        let mut buf = vec![0u8; body_cfg.chunk];
        while off < body_end {
            if let Some(limit) = stall_after
                && served >= limit
            {
                // Hang: no more frames, no EOF. `closed()` resolves when the client hangs up or the
                // server shuts down (its receiver drops), so the task frees instead of leaking.
                body_stats.record_range(start..off);
                tx.closed().await;
                return;
            }
            if let Some(limit) = drop_after
                && served >= limit
            {
                let _ = tx
                    .send(Err(std::io::Error::new(
                        std::io::ErrorKind::ConnectionReset,
                        "chaos: dropped mid-body",
                    )))
                    .await;
                body_stats.record_range(start..off);
                return;
            }
            let this = usize::try_from((body_end - off).min(body_cfg.chunk as u64))
                .unwrap_or(body_cfg.chunk);
            match &body_cfg.body {
                Some(bytes) => {
                    let start = off as usize;
                    buf[..this].copy_from_slice(&bytes[start..start + this]);
                }
                None => generate_into(body_cfg.seed, off, &mut buf[..this]),
            }
            corrupt_into(&effective_corrupt, off, &mut buf[..this]);
            if let Some(delay) = throttle {
                tokio::time::sleep(delay).await;
            }
            if tx
                .send(Ok(Frame::data(Bytes::copy_from_slice(&buf[..this]))))
                .await
                .is_err()
            {
                body_stats.record_range(start..off); // the client hung up
                return;
            }
            body_stats
                .bytes_served
                .fetch_add(this as u64, Ordering::SeqCst);
            off += this as u64;
            served += this as u64;
        }
        body_stats.record_range(start..off);
        // A full range served, then a reset instead of a clean EOF: the client has every byte but its
        // stream ends with an error, so its remaining range is empty.
        if body_cfg.reset_after_range {
            let _ = tx
                .send(Err(std::io::Error::new(
                    std::io::ErrorKind::ConnectionReset,
                    "chaos: reset after full range",
                )))
                .await;
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

/// A `503 Service Unavailable` carrying a `Retry-After` and an empty body.
fn service_unavailable(retry_after: &RetryAfter) -> Response<ChaosBody> {
    let value = match retry_after {
        RetryAfter::Seconds(secs) => secs.to_string(),
        RetryAfter::HttpDate(date) => date.clone(),
    };
    Response::builder()
        .status(StatusCode::SERVICE_UNAVAILABLE)
        .header(RETRY_AFTER, value)
        .body(empty_body())
        .unwrap_or_else(|_| status_only(StatusCode::SERVICE_UNAVAILABLE))
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

/// The approximate on-wire header size of a request: method, path, and every header name and value.
fn request_header_bytes(req: &Request<Incoming>) -> usize {
    let mut total = req.method().as_str().len() + req.uri().path().len();
    for (name, value) in req.headers() {
        total += name.as_str().len() + value.as_bytes().len();
    }
    total
}

/// Parse the start offset of a single `bytes=START-` or `bytes=START-END` range. Returns `None` for
/// anything else. This drives the single-stream path; multiple ranges take [`parse_ranges`].
fn parse_range_start(header: Option<&HeaderValue>) -> Option<u64> {
    let raw = header?.to_str().ok()?;
    let spec = raw.strip_prefix("bytes=")?;
    let (start, _end) = spec.split_once('-')?;
    start.parse::<u64>().ok()
}

/// The exclusive end of a single closed `bytes=START-END` range (inclusive `END` + 1), or `None` for
/// an open `bytes=START-` (which runs to EOF) or a multi-range header. Only the single-range forms
/// reach the single-stream path, so a segment request `bytes=start-(end-1)` is served as `[start, end)`.
fn parse_range_end(header: Option<&HeaderValue>) -> Option<u64> {
    let raw = header?.to_str().ok()?;
    let spec = raw.strip_prefix("bytes=")?;
    if spec.contains(',') {
        return None;
    }
    let (_start, end) = spec.split_once('-')?;
    if end.is_empty() {
        return None;
    }
    end.parse::<u64>().ok().map(|e| e.saturating_add(1))
}

/// A unit of a multipart body: framing bytes served verbatim, or a generated content range (the only
/// kind counted into [`Stats::served_ranges`]).
enum Segment {
    Literal(Vec<u8>),
    Generated(Range<u64>),
}

impl Segment {
    fn len(&self) -> u64 {
        match self {
            Segment::Literal(bytes) => bytes.len() as u64,
            Segment::Generated(range) => range.end - range.start,
        }
    }
}

/// True when the `Range` header lists more than one range (a comma), so the response must be
/// `multipart/byteranges`. Cheap enough to run on every request without touching the single path.
fn header_has_multiple_ranges(header: Option<&HeaderValue>) -> bool {
    header
        .and_then(|v| v.to_str().ok())
        .is_some_and(|s| s.contains(','))
}

/// Parse a `Range: bytes=...` header into concrete `[start, end)` ranges clamped to `len`, honoring
/// closed (`a-b`), open (`a-`), and suffix (`-n`) forms. Any malformed or empty range voids the whole
/// header (returns empty).
fn parse_ranges(header: Option<&HeaderValue>, len: u64) -> Vec<Range<u64>> {
    let Some(spec) = header
        .and_then(|h| h.to_str().ok())
        .and_then(|raw| raw.strip_prefix("bytes="))
    else {
        return Vec::new();
    };
    let mut ranges = Vec::new();
    for part in spec.split(',') {
        let part = part.trim();
        let Some((a, b)) = part.split_once('-') else {
            return Vec::new();
        };
        let range = match (a.is_empty(), b.is_empty()) {
            // closed `a-b`, inclusive
            (false, false) => match (a.parse::<u64>(), b.parse::<u64>()) {
                (Ok(s), Ok(e)) if s <= e => Some(s..e.saturating_add(1)),
                _ => None,
            },
            // open `a-`
            (false, true) => a.parse::<u64>().ok().map(|s| s..len),
            // suffix `-n` (the last n bytes)
            (true, false) => b.parse::<u64>().ok().map(|n| len.saturating_sub(n)..len),
            (true, true) => None,
        };
        match range {
            Some(r) => {
                let clamped = r.start.min(len)..r.end.min(len);
                if clamped.start < clamped.end {
                    ranges.push(clamped);
                }
            }
            None => return Vec::new(),
        }
    }
    ranges
}

/// Build the segment plan for a `multipart/byteranges` body: each range gets a boundary-delimited
/// part header (`Content-Range` per part) followed by its generated bytes, then a closing delimiter.
fn multipart_plan(ranges: &[Range<u64>], boundary: &str, len: u64) -> Vec<Segment> {
    let mut plan = Vec::with_capacity(ranges.len() * 2 + 1);
    for (i, range) in ranges.iter().enumerate() {
        let lead = if i == 0 { "" } else { "\r\n" };
        let header = format!(
            "{lead}--{boundary}\r\nContent-Type: application/octet-stream\r\n\
             Content-Range: bytes {}-{}/{}\r\n\r\n",
            range.start,
            range.end - 1,
            len,
        );
        plan.push(Segment::Literal(header.into_bytes()));
        plan.push(Segment::Generated(range.clone()));
    }
    plan.push(Segment::Literal(
        format!("\r\n--{boundary}--\r\n").into_bytes(),
    ));
    plan
}

/// Build a `206 multipart/byteranges` response for `ranges` and spawn its body task. Separate from
/// the single-stream path so the common download path stays untouched.
fn multipart_response(
    ranges: &[Range<u64>],
    cfg: &Arc<Config>,
    stats: &Arc<Stats>,
) -> Response<ChaosBody> {
    let plan = multipart_plan(ranges, &cfg.boundary, cfg.len);
    let content_length: u64 = plan.iter().map(Segment::len).sum();
    let mut builder = Response::builder()
        .status(StatusCode::PARTIAL_CONTENT)
        .header(CONTENT_LENGTH, content_length)
        .header(
            CONTENT_TYPE,
            format!("multipart/byteranges; boundary={}", cfg.boundary),
        );
    if cfg.accept_ranges {
        builder = builder.header(ACCEPT_RANGES, "bytes");
    }

    let (tx, rx) = mpsc::channel::<Result<Frame<Bytes>, std::io::Error>>(4);
    let body_cfg = cfg.clone();
    let body_stats = stats.clone();
    tokio::spawn(async move {
        let _active = ActiveGuard::new(body_stats.clone());
        let mut buf = vec![0u8; body_cfg.chunk];
        for segment in &plan {
            match segment {
                Segment::Literal(bytes) => {
                    if tx
                        .send(Ok(Frame::data(Bytes::copy_from_slice(bytes))))
                        .await
                        .is_err()
                    {
                        return;
                    }
                    body_stats
                        .bytes_served
                        .fetch_add(bytes.len() as u64, Ordering::SeqCst);
                }
                Segment::Generated(range) => {
                    let mut off = range.start;
                    while off < range.end {
                        let this = usize::try_from((range.end - off).min(body_cfg.chunk as u64))
                            .unwrap_or(body_cfg.chunk);
                        match &body_cfg.body {
                            Some(bytes) => {
                                let at = off as usize;
                                buf[..this].copy_from_slice(&bytes[at..at + this]);
                            }
                            None => generate_into(body_cfg.seed, off, &mut buf[..this]),
                        }
                        corrupt_into(&body_cfg.corrupt, off, &mut buf[..this]);
                        if tx
                            .send(Ok(Frame::data(Bytes::copy_from_slice(&buf[..this]))))
                            .await
                            .is_err()
                        {
                            body_stats.record_range(range.start..off);
                            return;
                        }
                        body_stats
                            .bytes_served
                            .fetch_add(this as u64, Ordering::SeqCst);
                        off += this as u64;
                    }
                    body_stats.record_range(range.clone());
                }
            }
        }
    });

    builder
        .body(StreamBody::new(ReceiverStream::new(rx)))
        .unwrap_or_else(|_| status_only(StatusCode::INTERNAL_SERVER_ERROR))
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

/// Flip (`^= 0xFF`) every byte in `buf` whose absolute offset (`offset + index`) falls in any
/// `corrupt` range. A no-op when `corrupt` is empty.
fn corrupt_into(corrupt: &[Range<u64>], offset: u64, buf: &mut [u8]) {
    if corrupt.is_empty() {
        return;
    }
    for (i, byte) in buf.iter_mut().enumerate() {
        let abs = offset.wrapping_add(i as u64);
        if corrupt.iter().any(|r| r.contains(&abs)) {
            *byte ^= 0xFF;
        }
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
    async fn a_closed_range_is_served_to_its_declared_end() {
        // A segment request `bytes=start-(end-1)` must serve exactly [start, end), not run to EOF.
        let server = ChaosServer::builder(4, 4096).start().await.unwrap();
        let resp = reqwest::Client::new()
            .get(server.url("f.bin"))
            .header("Range", "bytes=1000-1999")
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status().as_u16(), 206);
        assert_eq!(
            resp.headers().get("content-range").unwrap(),
            "bytes 1000-1999/4096"
        );
        let body = resp.bytes().await.unwrap();
        assert_eq!(body.len(), 1000);
        assert_eq!(&body[..], &generated_vec(4, 1000, 1000)[..]);
    }

    #[tokio::test]
    async fn a_targeted_range_drops_once_then_the_retry_completes() {
        let server = ChaosServer::builder(5, 4096)
            .drop_range_at(1000, 128)
            .chunk(64)
            .start()
            .await
            .unwrap();
        let client = reqwest::Client::new();
        // The segment at 1000 drops after 128 bytes on its first serve...
        let dropped = client
            .get(server.url("f.bin"))
            .header("Range", "bytes=1000-1999")
            .send()
            .await
            .unwrap()
            .bytes()
            .await;
        assert!(dropped.is_err() || dropped.unwrap().len() < 1000);
        // ...but the re-queued retry of the same segment completes.
        let retry = client
            .get(server.url("f.bin"))
            .header("Range", "bytes=1000-1999")
            .send()
            .await
            .unwrap()
            .bytes()
            .await
            .unwrap();
        assert_eq!(retry.len(), 1000);
        // A different segment is untouched by the target.
        let other = client
            .get(server.url("f.bin"))
            .header("Range", "bytes=2000-2999")
            .send()
            .await
            .unwrap()
            .bytes()
            .await
            .unwrap();
        assert_eq!(other.len(), 1000);
    }

    #[tokio::test]
    async fn peak_concurrency_tracks_simultaneous_bodies() {
        let server = ChaosServer::builder(6, 1 << 20)
            .throttle(Duration::from_millis(5))
            .chunk(4096)
            .start()
            .await
            .unwrap();
        let client = reqwest::Client::new();
        // Two overlapping ranged reads: both bodies stream at once.
        let a = client
            .get(server.url("f.bin"))
            .header("Range", "bytes=0-524287")
            .send();
        let b = client
            .get(server.url("f.bin"))
            .header("Range", "bytes=524288-1048575")
            .send();
        let (ra, rb) = tokio::join!(a, b);
        let (_ba, _bb) = tokio::join!(ra.unwrap().bytes(), rb.unwrap().bytes());
        assert!(
            server.stats().peak_concurrency() >= 2,
            "two concurrent reads must register concurrent bodies, saw {}",
            server.stats().peak_concurrency(),
        );
    }

    #[tokio::test]
    async fn service_unavailable_then_succeeds() {
        let server = ChaosServer::builder(5, 1024)
            .service_unavailable(2, RetryAfter::Seconds(1))
            .start()
            .await
            .unwrap();
        let client = reqwest::Client::new();

        for _ in 0..2 {
            let resp = client.get(server.url("f.bin")).send().await.unwrap();
            assert_eq!(resp.status().as_u16(), 503);
            assert_eq!(resp.headers().get("retry-after").unwrap(), "1");
        }
        let ok = client.get(server.url("f.bin")).send().await.unwrap();
        assert_eq!(ok.status().as_u16(), 200);
        assert_eq!(ok.bytes().await.unwrap().len(), 1024);
    }

    #[tokio::test]
    async fn retry_after_can_be_an_http_date() {
        let date = "Wed, 21 Oct 2026 07:28:00 GMT";
        let server = ChaosServer::builder(0, 16)
            .service_unavailable(1, RetryAfter::HttpDate(date.to_string()))
            .start()
            .await
            .unwrap();
        let resp = reqwest::get(server.url("f.bin")).await.unwrap();
        assert_eq!(resp.status().as_u16(), 503);
        assert_eq!(resp.headers().get("retry-after").unwrap(), date);
    }

    #[tokio::test]
    async fn a_hard_stall_times_out_then_the_resume_completes() {
        let server = ChaosServer::builder(9, 8192)
            .stall_after(1024)
            .chunk(256)
            .start()
            .await
            .unwrap();

        // First request serves 1024 bytes then hangs; a short client timeout must fire.
        let stalled = reqwest::Client::builder()
            .timeout(Duration::from_millis(300))
            .build()
            .unwrap()
            .get(server.url("f.bin"))
            .send()
            .await
            .unwrap()
            .bytes()
            .await;
        assert!(stalled.is_err(), "the stalled read should time out");

        // The second request does not stall, so a resume finishes.
        let body = reqwest::get(server.url("f.bin"))
            .await
            .unwrap()
            .bytes()
            .await
            .unwrap();
        assert_eq!(body.len(), 8192);
    }

    #[tokio::test]
    async fn served_ranges_record_what_was_served() {
        let server = ChaosServer::builder(4, 4096).start().await.unwrap();
        // A full request records the whole file.
        reqwest::get(server.url("f.bin"))
            .await
            .unwrap()
            .bytes()
            .await
            .unwrap();
        // An open-ended range records only the tail it served.
        reqwest::Client::new()
            .get(server.url("f.bin"))
            .header("Range", "bytes=1000-")
            .send()
            .await
            .unwrap()
            .bytes()
            .await
            .unwrap();
        assert_eq!(server.stats().served_ranges(), vec![0..4096, 1000..4096]);
    }

    #[tokio::test]
    async fn corrupt_range_flips_only_those_bytes() {
        let server = ChaosServer::builder(8, 4096)
            .corrupt_range(100..110)
            .start()
            .await
            .unwrap();
        let body = reqwest::get(server.url("f.bin"))
            .await
            .unwrap()
            .bytes()
            .await
            .unwrap();
        let pristine = generated_vec(8, 0, 4096);
        for i in 0..4096usize {
            if (100..110).contains(&i) {
                assert_eq!(body[i], pristine[i] ^ 0xFF, "byte {i} should be flipped");
            } else {
                assert_eq!(body[i], pristine[i], "byte {i} should be pristine");
            }
        }
        assert_eq!(server.stats().served_ranges(), vec![0..4096]);
    }

    #[tokio::test]
    async fn corrupt_range_once_is_dirty_first_then_clean() {
        let server = ChaosServer::builder(8, 4096)
            .corrupt_range_once(100..110)
            .start()
            .await
            .unwrap();
        let client = reqwest::Client::new();
        let fetch = || async {
            client
                .get(server.url("f.bin"))
                .header("range", "bytes=100-109")
                .send()
                .await
                .unwrap()
                .bytes()
                .await
                .unwrap()
        };
        let pristine = &generated_vec(8, 0, 4096)[100..110];
        // First serve of the range is corrupt; the second (the re-fetch) is clean.
        assert_ne!(&fetch().await[..], pristine, "first serve is corrupt");
        assert_eq!(&fetch().await[..], pristine, "re-fetch is clean");
    }

    #[tokio::test]
    async fn request_headers_are_captured() {
        let server = ChaosServer::builder(8, 64).start().await.unwrap();
        reqwest::Client::new()
            .get(server.url("f.bin"))
            .header("user-agent", "FFXIV PATCH CLIENT")
            .header("x-patch-unique-id", "abc123")
            .send()
            .await
            .unwrap()
            .bytes()
            .await
            .unwrap();
        assert_eq!(
            server.stats().user_agents(),
            vec![Some("FFXIV PATCH CLIENT".to_owned())]
        );
        assert_eq!(
            server.stats().patch_unique_ids(),
            vec![Some("abc123".to_owned())]
        );
    }

    #[test]
    fn parse_ranges_handles_every_form() {
        let hv = |s: &str| HeaderValue::from_str(s).unwrap();
        assert_eq!(parse_ranges(Some(&hv("bytes=0-9")), 100), vec![0..10]);
        assert_eq!(parse_ranges(Some(&hv("bytes=90-")), 100), vec![90..100]);
        assert_eq!(parse_ranges(Some(&hv("bytes=-10")), 100), vec![90..100]);
        assert_eq!(
            parse_ranges(Some(&hv("bytes=0-9,50-59")), 100),
            vec![0..10, 50..60]
        );
        assert_eq!(parse_ranges(Some(&hv("bytes=0-9")), 5), vec![0..5]); // clamped to len
        assert!(parse_ranges(Some(&hv("bytes=nonsense")), 100).is_empty());
        assert!(parse_ranges(None, 100).is_empty());
        assert!(header_has_multiple_ranges(Some(&hv("bytes=0-9,50-59"))));
        assert!(!header_has_multiple_ranges(Some(&hv("bytes=0-"))));
    }

    fn multipart_part(
        boundary: &str,
        first: bool,
        range: Range<u64>,
        len: u64,
        bytes: &[u8],
    ) -> Vec<u8> {
        let lead = if first { "" } else { "\r\n" };
        let mut part = format!(
            "{lead}--{boundary}\r\nContent-Type: application/octet-stream\r\n\
             Content-Range: bytes {}-{}/{}\r\n\r\n",
            range.start,
            range.end - 1,
            len
        )
        .into_bytes();
        part.extend_from_slice(bytes);
        part
    }

    #[tokio::test]
    async fn multipart_serves_each_requested_range() {
        let server = ChaosServer::builder(6, 4096).start().await.unwrap();
        let resp = reqwest::Client::new()
            .get(server.url("f.bin"))
            .header("Range", "bytes=0-99,2000-2099")
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status().as_u16(), 206);
        assert_eq!(
            resp.headers().get("content-type").unwrap(),
            "multipart/byteranges; boundary=chaos_boundary"
        );
        let declared_len = resp.content_length();
        let body = resp.bytes().await.unwrap();

        let mut expected = multipart_part(
            "chaos_boundary",
            true,
            0..100,
            4096,
            &generated_vec(6, 0, 100),
        );
        expected.extend(multipart_part(
            "chaos_boundary",
            false,
            2000..2100,
            4096,
            &generated_vec(6, 2000, 100),
        ));
        expected.extend_from_slice(b"\r\n--chaos_boundary--\r\n");

        assert_eq!(&body[..], &expected[..]);
        assert_eq!(declared_len, Some(expected.len() as u64));
        assert_eq!(server.stats().served_ranges(), vec![0..100, 2000..2100]);
    }

    #[tokio::test]
    async fn a_boundary_can_collide_with_the_body() {
        // A part body that literally contains the boundary delimiter: a parser scanning for the
        // delimiter instead of honoring the declared part length mis-splits here.
        let mut fixed = generated_vec(0, 0, 300);
        let decoy = b"\r\n--X\r\n";
        fixed[50..50 + decoy.len()].copy_from_slice(decoy);

        let server = ChaosServer::serving(fixed.clone())
            .multipart_boundary("X")
            .start()
            .await
            .unwrap();
        let resp = reqwest::Client::new()
            .get(server.url("f.bin"))
            .header("Range", "bytes=0-99,200-249")
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status().as_u16(), 206);
        let body = resp.bytes().await.unwrap();

        let mut expected = multipart_part("X", true, 0..100, 300, &fixed[0..100]);
        expected.extend(multipart_part("X", false, 200..250, 300, &fixed[200..250]));
        expected.extend_from_slice(b"\r\n--X--\r\n");

        assert_eq!(&body[..], &expected[..]);
        assert!(fixed[0..100].windows(decoy.len()).any(|w| w == decoy));
        assert_eq!(server.stats().served_ranges(), vec![0..100, 200..250]);
    }

    #[tokio::test]
    async fn oversized_request_headers_are_rejected() {
        let server = ChaosServer::builder(2, 512)
            .max_request_header_bytes(1024)
            .start()
            .await
            .unwrap();
        let client = reqwest::Client::new();

        // A normal request is under budget and serves.
        let ok = client.get(server.url("f.bin")).send().await.unwrap();
        assert_eq!(ok.status().as_u16(), 200);

        // A packed multi-range header (~2.7 KiB) is over budget but under hyper's own limit.
        let big_range = format!(
            "bytes={}",
            (0..250)
                .map(|i| format!("{}-{}", i * 10, i * 10 + 5))
                .collect::<Vec<_>>()
                .join(",")
        );
        assert!(big_range.len() > 1024);
        let resp = client
            .get(server.url("f.bin"))
            .header("Range", big_range)
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status().as_u16(), 431);
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

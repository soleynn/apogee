//! Scatter-gather multi-range fetch: pulls a set of byte ranges of one URL via [`fetch_ranges`],
//! packing them into `Range` requests bounded by both count and header byte length, and handling
//! whichever of a single `206`, a multipart `206`, or a range-ignoring `200` the server answers with.
//! Nothing buffers a whole body: spans are sliced from the stream and delivered as they arrive.
//!
//! This layer only guarantees that a delivered span came from its claimed offset of the URL; the
//! caller CRC-checks each part and owns mirror rotation and retry, since [`fetch_ranges`] is a single
//! attempt against one URL.

use std::ops::Range;

use futures_util::StreamExt;
use reqwest::header::{CONTENT_RANGE, CONTENT_TYPE, RANGE};
use tokio_util::sync::CancellationToken;
use url::Url;

use crate::download::{self, connect_error, transport_error};
use crate::error::FetchError;
use crate::fetcher::Shared;
use crate::headers::apply_headers;
use crate::multipart::{MultipartError, MultipartParser, RangeExpect, parse_content_range};
use crate::range_source::HttpSource;

/// Hard cap on ranges per request, independent of the byte budget: below XL's 400 for CDN header
/// headroom, and matches the multipart parser's own part cap.
const MAX_RANGES_PER_REQUEST: usize = 256;

/// How ranges are packed into `Range` requests: at most `max_ranges` ranges, and a `bytes=…` header
/// value at or below `max_range_header_bytes` (a single oversized range still gets its own request,
/// so progress is guaranteed).
///
/// `#[non_exhaustive]`: start from [`default`](Self::default) and adjust through the setters, so a
/// packing cap added later does not break every literal.
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub struct RangePacking {
    /// The most ranges one request may carry (clamped to `1..=256`).
    pub max_ranges: usize,
    /// The most bytes the `Range` header value may span before a new request is started.
    pub max_range_header_bytes: usize,
}

impl RangePacking {
    /// Set the most ranges one request may carry (clamped to `1..=256` when packing).
    #[must_use]
    pub fn max_ranges(mut self, n: usize) -> Self {
        self.max_ranges = n;
        self
    }

    /// Set the most bytes the `Range` header value may span before a new request is started.
    #[must_use]
    pub fn max_range_header_bytes(mut self, n: usize) -> Self {
        self.max_range_header_bytes = n;
        self
    }
}

impl Default for RangePacking {
    fn default() -> Self {
        // 256 ranges and ~1.2 KB of header value: comfortable headroom under a typical CDN's
        // request-header limit while keeping the number of requests low.
        Self {
            max_ranges: MAX_RANGES_PER_REQUEST,
            max_range_header_bytes: 1200,
        }
    }
}

/// The transport handles shared across a fetch: the pooled client and the scheduler/limiter. Built by
/// [`Fetcher`](crate::Fetcher) from its own client and shared state.
pub(crate) struct Engine<'a> {
    pub(crate) client: &'a reqwest::Client,
    pub(crate) shared: &'a Shared,
}

/// Fetches `ranges` (sorted, non-overlapping) of `source`, delivering each fetched span to `sink` as
/// `(absolute_offset, bytes)`. A single attempt against one URL.
///
/// # Errors
///
/// A transport, HTTP-status, length, or malformed-response [`FetchError`] (for example
/// [`FetchError::Http`] or [`FetchError::MalformedRangeResponse`]), [`FetchError::Cancelled`] if
/// `cancel` fires, or the sink's own error propagated verbatim.
pub(crate) async fn fetch_ranges<F>(
    engine: &Engine<'_>,
    source: &HttpSource,
    ranges: &[Range<u64>],
    packing: RangePacking,
    cancel: &CancellationToken,
    mut sink: F,
) -> Result<(), FetchError>
where
    F: FnMut(u64, &[u8]) -> Result<(), FetchError>,
{
    // A zero-length range requests nothing; drop it so packing and header building never see an empty
    // span (which would otherwise underflow `end - 1`). The repair planner never emits one; this keeps
    // the public entry point total for a degenerate caller.
    let ranges: Vec<Range<u64>> = ranges.iter().filter(|r| r.start < r.end).cloned().collect();
    for group in pack_ranges(&ranges, &packing) {
        if cancel.is_cancelled() {
            return Err(FetchError::Cancelled);
        }
        fetch_group(engine, source, group, cancel, &mut sink).await?;
    }
    Ok(())
}

/// Splits `ranges` greedily into request-sized groups honoring both packing caps.
fn pack_ranges<'a>(ranges: &'a [Range<u64>], packing: &RangePacking) -> Vec<&'a [Range<u64>]> {
    let max_ranges = packing.max_ranges.clamp(1, MAX_RANGES_PER_REQUEST);
    let mut groups = Vec::new();
    let mut start = 0;
    while start < ranges.len() {
        let mut end = start;
        // "bytes=" prefix, then each range's "a-b" token joined by commas.
        let mut header_len = "bytes=".len();
        while end < ranges.len() && end - start < max_ranges {
            let token = token_len(&ranges[end]) + usize::from(end > start); // comma before all but the first
            if end > start && header_len + token > packing.max_range_header_bytes {
                break;
            }
            header_len += token;
            end += 1;
        }
        // Never stall: a single oversized range still gets its own request.
        if end == start {
            end += 1;
        }
        groups.push(&ranges[start..end]);
        start = end;
    }
    groups
}

/// Decimal digit count of one range's `a-b` header token.
fn token_len(r: &Range<u64>) -> usize {
    digits(r.start) + 1 + digits(r.end.saturating_sub(1))
}

/// Decimal digit count of `n`; `0` counts as one digit.
fn digits(n: u64) -> usize {
    if n == 0 { 1 } else { (n.ilog10() + 1) as usize }
}

/// Fetches one packed group of ranges in a single request and dispatches on the response shape.
async fn fetch_group<F>(
    engine: &Engine<'_>,
    source: &HttpSource,
    group: &[Range<u64>],
    cancel: &CancellationToken,
    sink: &mut F,
) -> Result<(), FetchError>
where
    F: FnMut(u64, &[u8]) -> Result<(), FetchError>,
{
    let (url, expected_len) = (&source.url, source.expected_len);
    // The wait for a global connection slot is unbounded when the fetcher is busy, so it is raced
    // against the token: without that, a cancelled repair still queued behind every download in
    // flight before it could notice.
    let _conn = tokio::select! {
        biased;
        () = cancel.cancelled() => return Err(FetchError::Cancelled),
        conn = engine.shared.scheduler.acquire_connection() => conn,
    };
    let req = apply_headers(engine.client.get(url.clone()), source.policy.as_ref())
        .header(RANGE, range_header(group));
    let shared = engine.shared;
    // A single attempt is still a bounded one. Recovery belongs to the caller, but only if it is ever
    // handed back control: a host that takes the request and answers nothing would otherwise park a
    // repair inside this `send` with no body to time out and no attempt budget to spend.
    let sent = tokio::select! {
        biased;
        () = cancel.cancelled() => return Err(FetchError::Cancelled),
        sent = download::send_bounded(req, shared.stall_timeout) => sent,
    };
    let resp = match sent {
        Ok(sent) => sent.map_err(|e| connect_error(url, e))?,
        Err(_elapsed) => {
            // No counter beside this one: the multi-range transport carries no progress channel, so
            // the log is the whole of its observability.
            tracing::warn!(
                url = %url,
                ranges = group.len(),
                timeout_ms = shared.stall_timeout.as_millis(),
                "a range request got no response headers within the deadline",
            );
            return Err(FetchError::Stalled {
                url: url.clone(),
                at_bytes: group.first().map_or(0, |r| r.start),
            });
        }
    };

    // Tally the requested bytes actually delivered: a server that answers fewer ranges than asked (a
    // single 206 covering only the first range, or a multipart body missing parts) is a detectable
    // transport fault, so it must error rather than silently under-deliver and leave the omission for
    // the consumer's CRC to notice later. Over-delivery (a part that spans a gap) is harmless and
    // allowed. Every delivered span sits inside a requested range, so the byte count is the check.
    let needed: u64 = group.iter().map(|r| r.end - r.start).sum();
    let mut delivered: u64 = 0;
    // Scope the counting wrapper so its borrow of `delivered` ends before the coverage check reads it.
    let outcome = {
        let mut counting = |off: u64, bytes: &[u8]| -> Result<(), FetchError> {
            delivered += bytes.len() as u64;
            sink(off, bytes)
        };
        match resp.status().as_u16() {
            // Range honored: one part, or a multipart body of many.
            206 => {
                if let Some(boundary) = multipart_boundary(&resp) {
                    stream_multipart(
                        shared,
                        source,
                        group,
                        &boundary,
                        resp,
                        cancel,
                        &mut counting,
                    )
                    .await
                } else {
                    stream_single_206(
                        shared,
                        url,
                        expected_len,
                        group,
                        resp,
                        cancel,
                        &mut counting,
                    )
                    .await
                }
            }
            // Range ignored: the whole body arrived. Stream it and slice out the requested ranges.
            200 => stream_and_slice(shared, url, group, 0, resp, cancel, &mut counting).await,
            status => Err(FetchError::Http {
                status,
                url: url.clone(),
            }),
        }
    };
    outcome?;
    if delivered < needed {
        return Err(FetchError::MalformedRangeResponse {
            url: url.clone(),
            detail: "range response did not cover every requested range",
        });
    }
    Ok(())
}

/// The `bytes=a-b,c-d,…` header value for a group (inclusive `-b`).
fn range_header(group: &[Range<u64>]) -> String {
    let mut out = String::from("bytes=");
    for (i, r) in group.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        out.push_str(&r.start.to_string());
        out.push('-');
        out.push_str(&r.end.saturating_sub(1).to_string());
    }
    out
}

/// The half-open `[start, end)` envelope of a sorted, non-empty `group`: its first range's start to
/// the max of its ends.
fn envelope(group: &[Range<u64>]) -> (u64, u64) {
    let start = group.first().map_or(0, |r| r.start);
    let end = group.iter().map(|r| r.end).max().unwrap_or(0);
    (start, end)
}

/// The boundary token from a `Content-Type: multipart/byteranges; boundary=…`, or `None` for any
/// other content type.
fn multipart_boundary(resp: &reqwest::Response) -> Option<Vec<u8>> {
    let ct = resp.headers().get(CONTENT_TYPE)?.to_str().ok()?;
    let mut parts = ct.split(';');
    if !parts
        .next()?
        .trim()
        .eq_ignore_ascii_case("multipart/byteranges")
    {
        return None;
    }
    for param in parts {
        if let Some((name, value)) = param.split_once('=')
            && name.trim().eq_ignore_ascii_case("boundary")
        {
            let value = value.trim().trim_matches('"');
            if value.is_empty() {
                return None;
            }
            return Some(value.as_bytes().to_vec());
        }
    }
    None
}

/// Handles a single `206`: validates its `Content-Range`, then streams and slices the body from
/// `first`.
async fn stream_single_206<F>(
    shared: &Shared,
    url: &Url,
    expected_len: u64,
    group: &[Range<u64>],
    resp: reqwest::Response,
    cancel: &CancellationToken,
    sink: &mut F,
) -> Result<(), FetchError>
where
    F: FnMut(u64, &[u8]) -> Result<(), FetchError>,
{
    let (first, last, total) = resp
        .headers()
        .get(CONTENT_RANGE)
        .and_then(|v| v.to_str().ok())
        .and_then(parse_content_range)
        .ok_or(FetchError::MalformedRangeResponse {
            url: url.clone(),
            detail: "missing or malformed content-range",
        })?;
    if let Some(total) = total
        && total != expected_len
    {
        return Err(FetchError::LengthMismatch {
            expected: expected_len,
            got: total,
        });
    }
    let (env_start, env_end) = envelope(group);
    if first > last || first < env_start || last >= env_end {
        return Err(FetchError::MalformedRangeResponse {
            url: url.clone(),
            detail: "content-range outside requested ranges",
        });
    }
    stream_and_slice(shared, url, group, first, resp, cancel, sink).await
}

/// Streams a body whose first byte sits at absolute offset `base`, delivering to `sink` only the
/// bytes inside one of `group`'s ranges. Buffers nothing: each chunk is intersected with the sorted
/// ranges as it arrives.
async fn stream_and_slice<F>(
    shared: &Shared,
    url: &Url,
    group: &[Range<u64>],
    base: u64,
    resp: reqwest::Response,
    cancel: &CancellationToken,
    sink: &mut F,
) -> Result<(), FetchError>
where
    F: FnMut(u64, &[u8]) -> Result<(), FetchError>,
{
    let mut stream = Box::pin(resp.bytes_stream());
    let mut pos = base;
    loop {
        let Some(item) = next_chunk(shared, url, &mut stream, pos, cancel).await? else {
            break;
        };
        let chunk = item.map_err(|e| transport_error(url, e))?;
        let bytes: &[u8] = chunk.as_ref();
        throttle(shared, bytes.len() as u64, cancel).await?;
        let chunk_start = pos;
        let chunk_end = pos + bytes.len() as u64;
        for r in group {
            if r.start >= chunk_end {
                break; // ranges are sorted; nothing further overlaps this chunk
            }
            let s = r.start.max(chunk_start);
            let e = r.end.min(chunk_end);
            if s < e {
                let from = (s - chunk_start) as usize;
                let to = (e - chunk_start) as usize;
                sink(s, &bytes[from..to])?;
            }
        }
        pos = chunk_end;
    }
    Ok(())
}

/// Streams a `multipart/byteranges` body through the incremental parser, delivering each part's
/// bytes.
async fn stream_multipart<F>(
    shared: &Shared,
    source: &HttpSource,
    group: &[Range<u64>],
    boundary: &[u8],
    resp: reqwest::Response,
    cancel: &CancellationToken,
    sink: &mut F,
) -> Result<(), FetchError>
where
    F: FnMut(u64, &[u8]) -> Result<(), FetchError>,
{
    let (url, expected_len) = (&source.url, source.expected_len);
    let (start, end) = envelope(group);
    let expect = RangeExpect {
        start,
        end,
        total: expected_len,
    };
    let mut parser =
        MultipartParser::new(boundary, expect).map_err(|e| multipart_to_fetch(url, e))?;
    let mut deliver = |off: u64, bytes: &[u8]| sink(off, bytes);
    let mut stream = Box::pin(resp.bytes_stream());
    let mut fed: u64 = 0;
    loop {
        let Some(item) = next_chunk(shared, url, &mut stream, fed, cancel).await? else {
            break;
        };
        let chunk = item.map_err(|e| transport_error(url, e))?;
        let bytes: &[u8] = chunk.as_ref();
        throttle(shared, bytes.len() as u64, cancel).await?;
        fed += bytes.len() as u64;
        parser
            .feed(bytes, &mut deliver)
            .map_err(|e| multipart_to_fetch(url, e))?;
    }
    parser.finish().map_err(|e| multipart_to_fetch(url, e))
}

/// Pulls the next body chunk, racing `cancel` and the inactivity timeout; `Ok(None)` is a clean end
/// of body. Elapsing is an error, not a retry: `send` only bounds the wait for response headers, so
/// nothing else stops a quiet body from parking the caller forever.
async fn next_chunk<S>(
    shared: &Shared,
    url: &Url,
    stream: &mut S,
    at_bytes: u64,
    cancel: &CancellationToken,
) -> Result<Option<S::Item>, FetchError>
where
    S: futures_util::Stream + Unpin,
{
    tokio::select! {
        biased;
        () = cancel.cancelled() => Err(FetchError::Cancelled),
        () = tokio::time::sleep(shared.stall_timeout) => {
            tracing::warn!(
                url = %url,
                at_bytes,
                timeout_ms = shared.stall_timeout.as_millis(),
                "a range response's body went quiet past the inactivity timeout",
            );
            Err(FetchError::Stalled { url: url.clone(), at_bytes })
        }
        item = stream.next() => Ok(item),
    }
}

/// Draws limiter tokens for `n` bytes, racing `cancel`; at a low rate the wait is `n / rate` long,
/// and tokens are debited only once the wait completes.
async fn throttle(shared: &Shared, n: u64, cancel: &CancellationToken) -> Result<(), FetchError> {
    tokio::select! {
        biased;
        () = cancel.cancelled() => Err(FetchError::Cancelled),
        () = shared.limiter.acquire(n) => Ok(()),
    }
}

/// Maps a parser error to a [`FetchError`]: a sink rejection surfaces verbatim, any
/// framing/validation fault becomes [`FetchError::MalformedRangeResponse`].
fn multipart_to_fetch(url: &Url, err: MultipartError) -> FetchError {
    match err {
        MultipartError::Sink(inner) => inner,
        other => FetchError::MalformedRangeResponse {
            url: url.clone(),
            detail: other.detail(),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn packing(max_ranges: usize, max_bytes: usize) -> RangePacking {
        RangePacking {
            max_ranges,
            max_range_header_bytes: max_bytes,
        }
    }

    /// Zero counts as one digit, not zero.
    #[test]
    fn digits_counts_decimal_places() {
        assert_eq!(digits(0), 1);
        assert_eq!(digits(9), 1);
        assert_eq!(digits(10), 2);
        assert_eq!(digits(999), 3);
    }

    /// A large `max_ranges` budget still splits into groups of at most `max_ranges`.
    #[test]
    fn packing_respects_the_range_count_cap() {
        let ranges: Vec<Range<u64>> = (0..10).map(|i| (i * 100)..(i * 100 + 10)).collect();
        let groups = pack_ranges(&ranges, &packing(3, 10_000));
        assert_eq!(
            groups.iter().map(|g| g.len()).collect::<Vec<_>>(),
            [3, 3, 3, 1]
        );
    }

    /// A tiny header-byte budget forces one range per request even with room under the count cap.
    #[test]
    fn packing_respects_the_header_byte_budget() {
        let ranges: Vec<Range<u64>> = (0..6).map(|i| (i * 1000)..(i * 1000 + 100)).collect();
        // Each token "a-b" is ~9 bytes; a tiny budget forces one range per request.
        let groups = pack_ranges(&ranges, &packing(256, 8));
        assert!(groups.iter().all(|g| g.len() == 1), "{groups:?}");
        assert_eq!(groups.len(), 6);
    }

    /// A single range that alone exceeds the byte budget still gets its own request rather than
    /// stalling.
    #[test]
    fn packing_never_stalls_on_an_oversized_single_range() {
        let ranges: Vec<Range<u64>> = std::iter::once(0u64..100).collect();
        let groups = pack_ranges(&ranges, &packing(256, 1));
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].len(), 1);
    }

    /// The header's end token is inclusive (`end - 1`), not the half-open `end`.
    #[test]
    fn range_header_formats_inclusive_tokens() {
        assert_eq!(range_header(&[0..10, 100..150]), "bytes=0-9,100-149");
    }

    /// The envelope is the min start and max end, not just the first and last range.
    #[test]
    fn envelope_spans_first_start_to_last_end() {
        assert_eq!(envelope(&[10..20, 100..150]), (10, 150));
    }
}

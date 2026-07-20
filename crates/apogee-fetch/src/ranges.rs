//! Scatter-gather multi-range fetch: the transport half of game repair.
//!
//! [`fetch_ranges`] pulls a set of byte ranges of one URL and hands each fetched span to a sink with
//! its absolute offset. Ranges are packed into requests capped both by count (≤ 256, below XL's 400
//! for CDN header headroom) and by the `Range` header's byte length, so a request never trips a
//! server's header-size limit. Each request's response is handled in whichever of the three shapes a
//! server chose: a single `206` (parse the `Content-Range`, slice), a `206 multipart/byteranges`
//! (drive the in-house incremental parser), or a degenerate `200` that ignored the ranges (stream the
//! whole body and slice out what was asked). Nothing buffers a whole body: spans are sliced from the
//! transfer stream and delivered as they arrive.
//!
//! This layer only guarantees "these bytes came from that offset of that URL"; the consumer
//! (`apogee-zipatch`'s repair) CRC-checks each part before writing. Mirror rotation, retry, and
//! local-first policy live in the caller, so `fetch_ranges` is a single attempt against one URL.

use std::ops::Range;

use futures_util::StreamExt;
use reqwest::header::{CONTENT_RANGE, CONTENT_TYPE, RANGE};
use url::Url;

use crate::download::{connect_error, transport_error};
use crate::error::FetchError;
use crate::fetcher::Shared;
use crate::headers::{HeaderPolicy, apply_headers};
use crate::multipart::{MultipartError, MultipartParser, RangeExpect, parse_content_range};

/// The hard cap on ranges per request, independent of the byte budget: below XL's 400 for headroom
/// against CDN header limits, and the parser's part cap.
const MAX_RANGES_PER_REQUEST: usize = 256;

/// How ranges are packed into `Range` requests. A request holds at most `max_ranges` ranges, and its
/// `bytes=…` header value stays at or below `max_range_header_bytes` (a single range always gets its
/// own request even if it alone exceeds the budget, so progress is guaranteed).
#[derive(Debug, Clone, Copy)]
pub struct RangePacking {
    /// The most ranges one request may carry (clamped to `1..=256`).
    pub max_ranges: usize,
    /// The most bytes the `Range` header value may span before a new request is started.
    pub max_range_header_bytes: usize,
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

/// Fetch `ranges` (sorted, non-overlapping) of `url`, delivering each fetched span to `sink` as
/// `(absolute_offset, bytes)`. `expected_len` is the source file's length, cross-checked against each
/// response's `Content-Range` total. Single attempt against one URL.
///
/// # Errors
/// A [`FetchError`] for any transport, HTTP-status, length, or malformed-response fault, or the sink's
/// own error propagated verbatim.
pub(crate) async fn fetch_ranges<F>(
    engine: &Engine<'_>,
    url: &Url,
    expected_len: u64,
    ranges: &[Range<u64>],
    policy: Option<&HeaderPolicy>,
    packing: RangePacking,
    mut sink: F,
) -> Result<(), FetchError>
where
    F: FnMut(u64, &[u8]) -> Result<(), FetchError>,
{
    for group in pack_ranges(ranges, &packing) {
        fetch_group(engine, url, expected_len, group, policy, &mut sink).await?;
    }
    Ok(())
}

/// Split `ranges` greedily into request-sized groups honoring both packing caps.
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

/// Decimal length of one range's `a-b` header token.
fn token_len(r: &Range<u64>) -> usize {
    digits(r.start) + 1 + digits(r.end.saturating_sub(1))
}

/// Number of decimal digits in `n`.
fn digits(n: u64) -> usize {
    if n == 0 { 1 } else { (n.ilog10() + 1) as usize }
}

/// Fetch one packed group of ranges in a single request and dispatch on the response shape.
async fn fetch_group<F>(
    engine: &Engine<'_>,
    url: &Url,
    expected_len: u64,
    group: &[Range<u64>],
    policy: Option<&HeaderPolicy>,
    sink: &mut F,
) -> Result<(), FetchError>
where
    F: FnMut(u64, &[u8]) -> Result<(), FetchError>,
{
    let _conn = engine.shared.scheduler.acquire_connection().await;
    let req =
        apply_headers(engine.client.get(url.clone()), policy).header(RANGE, range_header(group));
    let resp = req.send().await.map_err(|e| connect_error(url, e))?;
    let shared = engine.shared;
    match resp.status().as_u16() {
        // Range honored: one part, or a multipart body of many.
        206 => {
            if let Some(boundary) = multipart_boundary(&resp) {
                stream_multipart(shared, url, expected_len, group, &boundary, resp, sink).await
            } else {
                stream_single_206(shared, url, expected_len, group, resp, sink).await
            }
        }
        // Range ignored: the whole body arrived. Stream it and slice out the requested ranges.
        200 => stream_and_slice(shared, url, group, 0, resp, sink).await,
        status => Err(FetchError::Http {
            status,
            url: url.clone(),
        }),
    }
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
        out.push_str(&(r.end - 1).to_string());
    }
    out
}

/// The `[start, end)` envelope a group spans (its first range's start to its last range's end);
/// group is non-empty and sorted, so this is the min start and max end.
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

/// Handle a single `206`: validate its `Content-Range`, then stream-and-slice the body from `first`.
async fn stream_single_206<F>(
    shared: &Shared,
    url: &Url,
    expected_len: u64,
    group: &[Range<u64>],
    resp: reqwest::Response,
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
    stream_and_slice(shared, url, group, first, resp, sink).await
}

/// Stream a body whose first byte sits at absolute offset `base`, delivering to `sink` only the bytes
/// that fall inside one of the requested `group` ranges. Buffers nothing: each arriving chunk is
/// intersected with the (sorted) ranges and the overlaps are emitted.
async fn stream_and_slice<F>(
    shared: &Shared,
    url: &Url,
    group: &[Range<u64>],
    base: u64,
    resp: reqwest::Response,
    sink: &mut F,
) -> Result<(), FetchError>
where
    F: FnMut(u64, &[u8]) -> Result<(), FetchError>,
{
    let mut stream = Box::pin(resp.bytes_stream());
    let mut pos = base;
    while let Some(item) = stream.next().await {
        let chunk = item.map_err(|e| transport_error(url, e))?;
        let bytes: &[u8] = chunk.as_ref();
        shared.limiter.acquire(bytes.len() as u64).await;
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

/// Stream a `multipart/byteranges` body through the incremental parser, delivering each part's bytes.
async fn stream_multipart<F>(
    shared: &Shared,
    url: &Url,
    expected_len: u64,
    group: &[Range<u64>],
    boundary: &[u8],
    resp: reqwest::Response,
    sink: &mut F,
) -> Result<(), FetchError>
where
    F: FnMut(u64, &[u8]) -> Result<(), FetchError>,
{
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
    while let Some(item) = stream.next().await {
        let chunk = item.map_err(|e| transport_error(url, e))?;
        let bytes: &[u8] = chunk.as_ref();
        shared.limiter.acquire(bytes.len() as u64).await;
        parser
            .feed(bytes, &mut deliver)
            .map_err(|e| multipart_to_fetch(url, e))?;
    }
    parser.finish().map_err(|e| multipart_to_fetch(url, e))
}

/// Map a parser error to a [`FetchError`]: a sink rejection is surfaced verbatim (it is the sink's own
/// error), any framing/validation fault becomes a [`FetchError::MalformedRangeResponse`].
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

    #[test]
    fn digits_counts_decimal_places() {
        assert_eq!(digits(0), 1);
        assert_eq!(digits(9), 1);
        assert_eq!(digits(10), 2);
        assert_eq!(digits(999), 3);
    }

    #[test]
    fn packing_respects_the_range_count_cap() {
        let ranges: Vec<Range<u64>> = (0..10).map(|i| (i * 100)..(i * 100 + 10)).collect();
        let groups = pack_ranges(&ranges, &packing(3, 10_000));
        assert_eq!(
            groups.iter().map(|g| g.len()).collect::<Vec<_>>(),
            [3, 3, 3, 1]
        );
    }

    #[test]
    fn packing_respects_the_header_byte_budget() {
        let ranges: Vec<Range<u64>> = (0..6).map(|i| (i * 1000)..(i * 1000 + 100)).collect();
        // Each token "a-b" is ~9 bytes; a tiny budget forces one range per request.
        let groups = pack_ranges(&ranges, &packing(256, 8));
        assert!(groups.iter().all(|g| g.len() == 1), "{groups:?}");
        assert_eq!(groups.len(), 6);
    }

    #[test]
    fn packing_never_stalls_on_an_oversized_single_range() {
        let ranges: Vec<Range<u64>> = std::iter::once(0u64..100).collect();
        let groups = pack_ranges(&ranges, &packing(256, 1));
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].len(), 1);
    }

    #[test]
    fn range_header_formats_inclusive_tokens() {
        assert_eq!(range_header(&[0..10, 100..150]), "bytes=0-9,100-149");
    }

    #[test]
    fn envelope_spans_first_start_to_last_end() {
        assert_eq!(envelope(&[10..20, 100..150]), (10, 150));
    }
}

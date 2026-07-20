//! An incremental `multipart/byteranges` response parser for the multi-range engine.
//!
//! The parser is **length-driven, not boundary-scanning**: each part carries a
//! `Content-Range: bytes first-last/total` header, so the body length is exactly `last - first + 1`.
//! Once a part's header block is parsed and validated, that many body bytes are routed straight to
//! the sink and the parser then expects the trailing delimiter. It never searches a body for the
//! boundary, so a boundary sequence appearing inside body bytes is a non-issue, and it never buffers
//! a part body, so its footprint is `O(boundary + header cap)` regardless of body or part size.
//!
//! Bytes arrive in arbitrary chunk sizes (from `reqwest`'s `bytes_stream`); the parser holds its
//! state across [`feed`](MultipartParser::feed) calls. Body bytes are handed to the sink as
//! zero-copy views into the caller's chunk, tagged with their absolute source-file offset (seeded
//! from the validated `Content-Range`), which is exactly what the range consumer keys on.
//!
//! The framing bytes (delimiters and header blocks) drive a small per-byte state machine; body bytes
//! are emitted in bulk, so the per-byte cost falls only on the tiny framing fraction. All input is
//! hostile: every field is a checked parse, header blocks are size-capped, the boundary and part
//! count are bounded, and there is no panic path (the `fetch_multipart` fuzz target pins this).

use crate::error::FetchError;

/// The callback the range engine hands each fetched span to, as `(absolute_offset, bytes)`. Shared by
/// the multipart parser and `Fetcher::fetch_ranges`; a returned error aborts the fetch.
pub(crate) type RangeSink<'a> = dyn FnMut(u64, &[u8]) -> Result<(), FetchError> + 'a;

/// A boundary token longer than this is rejected: real `multipart/byteranges` boundaries are short,
/// and an unbounded one would be an allocation lever.
const BOUNDARY_CAP: usize = 256;
/// A single part's header block may not exceed this; a part with no terminator inside it is an error,
/// not an unbounded buffer.
const MAX_HEADER_BYTES: usize = 8 * 1024;
/// The most parts a response may carry, matching the request packer's ranges-per-request cap: a
/// response with more parts than could have been asked for is malformed.
const MAX_PARTS: u32 = 256;

/// What a multi-range response must answer, for validating each part against the request.
#[derive(Debug, Clone, Copy)]
pub(crate) struct RangeExpect {
    /// The lowest requested byte offset (inclusive): a part may not start below it.
    pub start: u64,
    /// One past the highest requested byte offset (exclusive): a part may not end at or above it.
    pub end: u64,
    /// The source file's length; a part's `Content-Range` total, when concrete, must equal it.
    pub total: u64,
}

/// A malformed or unexpected `multipart/byteranges` response, or a sink that rejected a delivered
/// part. Not `PartialEq` because [`Sink`](MultipartError::Sink) carries a [`FetchError`]; match with
/// `matches!` in tests.
#[derive(Debug)]
pub(crate) enum MultipartError {
    /// The `Content-Type` carried no boundary, or it was empty.
    MissingBoundary,
    /// The boundary token exceeded [`BOUNDARY_CAP`].
    BoundaryTooLong,
    /// A part's header block ran past [`MAX_HEADER_BYTES`] without terminating.
    HeaderTooLarge,
    /// A part had no `Content-Range` header.
    MissingContentRange,
    /// A `Content-Range` header could not be parsed as `bytes first-last/total`.
    MalformedContentRange,
    /// A part's `total` disagreed with the expected source length.
    TotalMismatch,
    /// A part's byte span fell outside what the request asked for.
    RangeNotRequested,
    /// The response carried more parts than [`MAX_PARTS`].
    TooManyParts,
    /// The byte stream did not follow the boundary/delimiter framing.
    Framing,
    /// The stream ended before the closing delimiter.
    Truncated,
    /// The sink rejected a delivered part; the wrapped error is surfaced verbatim by the caller.
    Sink(FetchError),
}

impl MultipartError {
    /// A stable one-line reason for the framing/validation variants, for a caller mapping this into
    /// its own transport error. [`Sink`](MultipartError::Sink) is unwrapped by the caller, not
    /// described here.
    pub(crate) fn detail(&self) -> &'static str {
        match self {
            MultipartError::MissingBoundary => "missing multipart boundary",
            MultipartError::BoundaryTooLong => "multipart boundary too long",
            MultipartError::HeaderTooLarge => "multipart part header too large",
            MultipartError::MissingContentRange => "multipart part missing content-range",
            MultipartError::MalformedContentRange => "malformed content-range",
            MultipartError::TotalMismatch => "content-range total mismatch",
            MultipartError::RangeNotRequested => "part outside requested ranges",
            MultipartError::TooManyParts => "too many multipart parts",
            MultipartError::Framing => "malformed multipart framing",
            MultipartError::Truncated => "truncated multipart response",
            MultipartError::Sink(_) => "range sink rejected a part",
        }
    }
}

/// The parser's position in the byte stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    /// Before the first boundary: skip an optional leading CRLF, then match the boundary.
    Start,
    /// Matching the dash-boundary token byte by byte (`match_pos` bytes matched so far).
    MatchBoundary,
    /// Just after a matched boundary: the next byte decides part (CRLF) vs close (`--`).
    Decide,
    /// After a `-` in [`Decide`](State::Decide): the second `-` of the closing delimiter.
    ExpectClose,
    /// After a `\r` (in [`Decide`](State::Decide) or [`AfterBody`](State::AfterBody)): its `\n`.
    ExpectLf,
    /// Accumulating a part's header block until its blank-line terminator.
    Headers,
    /// Streaming a part's `remaining` body bytes to the sink.
    Body,
    /// Just after a body: consume the delimiter's leading CRLF, then match the next boundary.
    AfterBody,
    /// After a `\r` in [`AfterBody`](State::AfterBody): its `\n`, then match the next boundary.
    AfterBodyLf,
    /// After the closing `--`: the epilogue is ignored.
    Closed,
}

/// Incremental `multipart/byteranges` parser. Construct with the boundary from the response's
/// `Content-Type` and the [`RangeExpect`] the request implies, [`feed`](Self::feed) each arriving
/// chunk, then [`finish`](Self::finish) at end of stream.
pub(crate) struct MultipartParser {
    /// `b"--"` + the boundary token; the delimiter every part is framed by.
    dash_boundary: Vec<u8>,
    expect: RangeExpect,
    state: State,
    /// Bytes of `dash_boundary` matched so far, in [`MatchBoundary`](State::MatchBoundary).
    match_pos: usize,
    /// The current part's header-block accumulator (cleared per part); bounded by [`MAX_HEADER_BYTES`].
    scratch: Vec<u8>,
    /// Body bytes left in the current part.
    remaining: u64,
    /// Absolute source-file offset of the next body byte to emit.
    part_off: u64,
    parts_seen: u32,
}

impl MultipartParser {
    /// A parser for `boundary` (the raw token, without the leading dashes) validating parts against
    /// `expect`.
    ///
    /// # Errors
    /// [`MultipartError::MissingBoundary`] for an empty boundary, [`MultipartError::BoundaryTooLong`]
    /// past [`BOUNDARY_CAP`].
    pub(crate) fn new(boundary: &[u8], expect: RangeExpect) -> Result<Self, MultipartError> {
        if boundary.is_empty() {
            return Err(MultipartError::MissingBoundary);
        }
        if boundary.len() > BOUNDARY_CAP {
            return Err(MultipartError::BoundaryTooLong);
        }
        let mut dash_boundary = Vec::with_capacity(boundary.len() + 2);
        dash_boundary.extend_from_slice(b"--");
        dash_boundary.extend_from_slice(boundary);
        Ok(Self {
            dash_boundary,
            expect,
            state: State::Start,
            match_pos: 0,
            scratch: Vec::new(),
            remaining: 0,
            part_off: 0,
            parts_seen: 0,
        })
    }

    /// Feed one arriving chunk, emitting each part's body bytes to `sink` as `(absolute_offset, bytes)`
    /// views into `chunk`.
    ///
    /// # Errors
    /// A [`MultipartError`] on any framing or validation fault, or [`MultipartError::Sink`] wrapping a
    /// sink rejection.
    pub(crate) fn feed(
        &mut self,
        chunk: &[u8],
        sink: &mut RangeSink<'_>,
    ) -> Result<(), MultipartError> {
        let mut cursor = 0usize;
        while cursor < chunk.len() {
            match self.state {
                State::Body => {
                    let avail = (chunk.len() - cursor) as u64;
                    let n = self.remaining.min(avail) as usize;
                    if n > 0 {
                        sink(self.part_off, &chunk[cursor..cursor + n])
                            .map_err(MultipartError::Sink)?;
                        self.part_off += n as u64;
                        self.remaining -= n as u64;
                        cursor += n;
                    }
                    if self.remaining == 0 {
                        self.state = State::AfterBody;
                    }
                }
                State::Start => {
                    let b = chunk[cursor];
                    if b == b'\r' || b == b'\n' {
                        cursor += 1; // skip an optional leading CRLF before the first boundary
                    } else {
                        self.state = State::MatchBoundary;
                        self.match_pos = 0;
                    }
                }
                State::MatchBoundary => {
                    let b = chunk[cursor];
                    if b == self.dash_boundary[self.match_pos] {
                        cursor += 1;
                        self.match_pos += 1;
                        if self.match_pos == self.dash_boundary.len() {
                            self.state = State::Decide;
                        }
                    } else {
                        return Err(MultipartError::Framing);
                    }
                }
                State::Decide => {
                    let b = chunk[cursor];
                    cursor += 1;
                    match b {
                        b'-' => self.state = State::ExpectClose,
                        b'\r' => self.state = State::ExpectLf,
                        b'\n' => self.begin_headers(),
                        _ => return Err(MultipartError::Framing),
                    }
                }
                State::ExpectClose => {
                    let b = chunk[cursor];
                    cursor += 1;
                    if b == b'-' {
                        self.state = State::Closed;
                    } else {
                        return Err(MultipartError::Framing);
                    }
                }
                State::ExpectLf => {
                    let b = chunk[cursor];
                    cursor += 1;
                    if b == b'\n' {
                        self.begin_headers();
                    } else {
                        return Err(MultipartError::Framing);
                    }
                }
                State::Headers => {
                    let b = chunk[cursor];
                    cursor += 1;
                    self.scratch.push(b);
                    if self.scratch.len() > MAX_HEADER_BYTES {
                        return Err(MultipartError::HeaderTooLarge);
                    }
                    if header_block_complete(&self.scratch) {
                        let (first, last, total) = parse_part_headers(&self.scratch)?;
                        self.begin_part(first, last, total)?;
                    }
                }
                State::AfterBody => {
                    let b = chunk[cursor];
                    cursor += 1;
                    match b {
                        b'\r' => self.state = State::AfterBodyLf,
                        b'\n' => {
                            self.state = State::MatchBoundary;
                            self.match_pos = 0;
                        }
                        _ => return Err(MultipartError::Framing),
                    }
                }
                State::AfterBodyLf => {
                    let b = chunk[cursor];
                    cursor += 1;
                    if b == b'\n' {
                        self.state = State::MatchBoundary;
                        self.match_pos = 0;
                    } else {
                        return Err(MultipartError::Framing);
                    }
                }
                State::Closed => cursor = chunk.len(),
            }
        }
        Ok(())
    }

    /// The stream ended.
    ///
    /// # Errors
    /// [`MultipartError::Truncated`] if the closing delimiter was never seen.
    pub(crate) fn finish(&self) -> Result<(), MultipartError> {
        match self.state {
            State::Closed => Ok(()),
            _ => Err(MultipartError::Truncated),
        }
    }

    /// Enter the header-accumulation state for a fresh part.
    fn begin_headers(&mut self) {
        self.state = State::Headers;
        self.scratch.clear();
    }

    /// Validate a parsed part header against the request and arm the body stream.
    fn begin_part(
        &mut self,
        first: u64,
        last: u64,
        total: Option<u64>,
    ) -> Result<(), MultipartError> {
        if let Some(total) = total
            && total != self.expect.total
        {
            return Err(MultipartError::TotalMismatch);
        }
        if first > last || first < self.expect.start || last >= self.expect.end {
            return Err(MultipartError::RangeNotRequested);
        }
        let len = last
            .checked_sub(first)
            .and_then(|d| d.checked_add(1))
            .ok_or(MultipartError::MalformedContentRange)?;
        self.parts_seen += 1;
        if self.parts_seen > MAX_PARTS {
            return Err(MultipartError::TooManyParts);
        }
        self.remaining = len;
        self.part_off = first;
        self.state = State::Body;
        Ok(())
    }
}

/// Whether `block` ends with a blank-line terminator (CRLF or bare LF leniency).
fn header_block_complete(block: &[u8]) -> bool {
    block.ends_with(b"\r\n\r\n") || block.ends_with(b"\n\n")
}

/// Find the `Content-Range` line in a part's header block and parse its span.
fn parse_part_headers(block: &[u8]) -> Result<(u64, u64, Option<u64>), MultipartError> {
    for line in block.split(|&b| b == b'\n') {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        if let Some(value) = header_value(line, b"content-range:") {
            let value =
                std::str::from_utf8(value).map_err(|_| MultipartError::MalformedContentRange)?;
            return parse_content_range(value.trim()).ok_or(MultipartError::MalformedContentRange);
        }
    }
    Err(MultipartError::MissingContentRange)
}

/// The bytes after a case-insensitive `name` prefix on `line`, or `None` if `line` is a different header.
fn header_value<'a>(line: &'a [u8], name: &[u8]) -> Option<&'a [u8]> {
    if line.len() < name.len() {
        return None;
    }
    let (head, rest) = line.split_at(name.len());
    head.eq_ignore_ascii_case(name).then_some(rest)
}

/// Parse a `Content-Range: bytes first-last/total` value into `(first, last, total)`; `total` is
/// `None` for the `*` (unknown) form. Shared by the multipart part headers and the single-`206` path.
pub(crate) fn parse_content_range(value: &str) -> Option<(u64, u64, Option<u64>)> {
    let (range, total) = value.strip_prefix("bytes ")?.split_once('/')?;
    let (first, last) = range.split_once('-')?;
    let first = first.trim().parse::<u64>().ok()?;
    let last = last.trim().parse::<u64>().ok()?;
    let total = match total.trim() {
        "*" => None,
        t => Some(t.parse::<u64>().ok()?),
    };
    Some((first, last, total))
}

/// Drive the parser over arbitrary bytes, for the `fetch_multipart` fuzz target. The first input byte
/// picks the feed chunk size (so chunk-boundary handling is fuzzed too); the rest is the response
/// body, parsed against a fixed boundary and permissive expectations. The property is panic-freedom
/// and bounded allocation on any input, never a particular parse outcome.
#[cfg(feature = "fuzzing")]
pub fn fuzz_multipart(data: &[u8]) {
    let Some((&chunk_ctl, body)) = data.split_first() else {
        return;
    };
    let chunk = (chunk_ctl as usize).max(1);
    let expect = RangeExpect {
        start: 0,
        end: u64::MAX,
        total: 1_000_000,
    };
    let Ok(mut parser) = MultipartParser::new(b"sep", expect) else {
        return;
    };
    let mut sink = |_off: u64, _bytes: &[u8]| -> Result<(), FetchError> { Ok(()) };
    for piece in body.chunks(chunk) {
        if parser.feed(piece, &mut sink).is_err() {
            return;
        }
    }
    let _ = parser.finish();
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Collect every part the parser emits from `body` fed in `chunk` byte increments.
    fn run(
        boundary: &[u8],
        expect: RangeExpect,
        body: &[u8],
        chunk: usize,
    ) -> Result<Vec<(u64, Vec<u8>)>, MultipartError> {
        let mut parser = MultipartParser::new(boundary, expect)?;
        let mut parts: Vec<(u64, Vec<u8>)> = Vec::new();
        let mut sink = |off: u64, bytes: &[u8]| -> Result<(), FetchError> {
            // Coalesce contiguous emissions from the same part into one span for easy assertions.
            match parts.last_mut() {
                Some((start, buf)) if *start + buf.len() as u64 == off => {
                    buf.extend_from_slice(bytes)
                }
                _ => parts.push((off, bytes.to_vec())),
            }
            Ok(())
        };
        for piece in body.chunks(chunk.max(1)) {
            parser.feed(piece, &mut sink)?;
        }
        parser.finish()?;
        Ok(parts)
    }

    /// Build a well-formed two-part body matching the chaos server's framing.
    fn two_part_body(boundary: &str, total: u64, a: (u64, &[u8]), b: (u64, &[u8])) -> Vec<u8> {
        let mut out = Vec::new();
        let part = |out: &mut Vec<u8>, lead: &str, start: u64, bytes: &[u8]| {
            let end = start + bytes.len() as u64 - 1;
            out.extend_from_slice(
                format!("{lead}--{boundary}\r\nContent-Type: application/octet-stream\r\nContent-Range: bytes {start}-{end}/{total}\r\n\r\n").as_bytes(),
            );
            out.extend_from_slice(bytes);
        };
        part(&mut out, "", a.0, a.1);
        part(&mut out, "\r\n", b.0, b.1);
        out.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
        out
    }

    #[test]
    fn parses_two_parts_across_every_chunk_size() {
        let body = two_part_body("SEP", 300, (0, b"hello"), (100, b"world!"));
        let expect = RangeExpect {
            start: 0,
            end: 300,
            total: 300,
        };
        for chunk in 1..=body.len() {
            let parts = run(b"SEP", expect, &body, chunk).expect("parse");
            assert_eq!(
                parts,
                vec![(0, b"hello".to_vec()), (100, b"world!".to_vec())],
                "chunk={chunk}"
            );
        }
    }

    #[test]
    fn content_range_parses_and_rejects() {
        assert_eq!(
            parse_content_range("bytes 0-99/300"),
            Some((0, 99, Some(300)))
        );
        assert_eq!(parse_content_range("bytes 5-5/*"), Some((5, 5, None)));
        assert!(parse_content_range("bytes 0-99").is_none());
        assert!(parse_content_range("0-99/300").is_none());
        assert!(parse_content_range("bytes x-99/300").is_none());
    }

    #[test]
    fn a_body_containing_the_boundary_bytes_is_not_a_delimiter() {
        // The body literally contains "\r\n--SEP\r\n"; length-driven parsing must ignore it.
        let payload = b"AAAA\r\n--SEP\r\nBBBB".to_vec();
        let body = two_part_body("SEP", 1000, (0, &payload), (500, b"tail"));
        let expect = RangeExpect {
            start: 0,
            end: 1000,
            total: 1000,
        };
        let parts = run(b"SEP", expect, &body, 3).expect("parse");
        assert_eq!(parts, vec![(0, payload), (500, b"tail".to_vec())]);
    }

    #[test]
    fn lf_only_framing_is_accepted() {
        let boundary = "SEP";
        let mut body = Vec::new();
        body.extend_from_slice(b"--SEP\nContent-Range: bytes 0-2/9\n\n");
        body.extend_from_slice(b"abc");
        body.extend_from_slice(b"\n--SEP--\n");
        let expect = RangeExpect {
            start: 0,
            end: 9,
            total: 9,
        };
        let _ = boundary;
        let parts = run(b"SEP", expect, &body, 4).expect("parse");
        assert_eq!(parts, vec![(0, b"abc".to_vec())]);
    }

    #[test]
    fn a_total_that_disagrees_is_rejected() {
        let body = two_part_body("SEP", 999, (0, b"hello"), (100, b"world!"));
        let expect = RangeExpect {
            start: 0,
            end: 300,
            total: 300,
        };
        assert!(matches!(
            run(b"SEP", expect, &body, 7),
            Err(MultipartError::TotalMismatch)
        ));
    }

    #[test]
    fn a_part_outside_the_requested_envelope_is_rejected() {
        let body = two_part_body("SEP", 300, (0, b"hello"), (250, b"world!"));
        // Envelope ends at 200, but the second part ends at 255.
        let expect = RangeExpect {
            start: 0,
            end: 200,
            total: 300,
        };
        assert!(matches!(
            run(b"SEP", expect, &body, 5),
            Err(MultipartError::RangeNotRequested)
        ));
    }

    #[test]
    fn an_oversized_header_block_is_bounded() {
        let mut body = Vec::new();
        body.extend_from_slice(b"--SEP\r\nX-Filler: ");
        body.extend(std::iter::repeat_n(b'a', MAX_HEADER_BYTES + 16));
        let expect = RangeExpect {
            start: 0,
            end: 10,
            total: 10,
        };
        assert!(matches!(
            run(b"SEP", expect, &body, 64),
            Err(MultipartError::HeaderTooLarge)
        ));
    }

    #[test]
    fn a_missing_close_is_truncated() {
        let mut body = Vec::new();
        body.extend_from_slice(b"--SEP\r\nContent-Range: bytes 0-2/9\r\n\r\nabc");
        // No closing delimiter.
        let expect = RangeExpect {
            start: 0,
            end: 9,
            total: 9,
        };
        assert!(matches!(
            run(b"SEP", expect, &body, 3),
            Err(MultipartError::Truncated)
        ));
    }

    #[test]
    fn an_empty_or_oversized_boundary_is_rejected() {
        let expect = RangeExpect {
            start: 0,
            end: 1,
            total: 1,
        };
        assert!(matches!(
            MultipartParser::new(b"", expect),
            Err(MultipartError::MissingBoundary)
        ));
        let long = vec![b'a'; BOUNDARY_CAP + 1];
        assert!(matches!(
            MultipartParser::new(&long, expect),
            Err(MultipartError::BoundaryTooLong)
        ));
    }

    #[test]
    fn a_sink_rejection_propagates() {
        let body = two_part_body("SEP", 300, (0, b"hello"), (100, b"world!"));
        let expect = RangeExpect {
            start: 0,
            end: 300,
            total: 300,
        };
        let mut parser = MultipartParser::new(b"SEP", expect).expect("new");
        let mut sink =
            |_off: u64, _bytes: &[u8]| -> Result<(), FetchError> { Err(FetchError::Cancelled) };
        let err = parser.feed(&body, &mut sink).expect_err("sink error");
        assert!(matches!(err, MultipartError::Sink(FetchError::Cancelled)));
    }
}

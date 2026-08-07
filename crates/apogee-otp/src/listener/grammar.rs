//! The request grammar, and the reader that assembles a line out of however many reads it takes.
//!
//! Pure: no socket, no future, no allocation, and no `char` anywhere on the path. Everything the
//! hardening says about what a request may look like is decided here, which is what lets it be
//! driven from a plain `#[test]` and from a fuzz target rather than from a socket harness.

use zeroize::Zeroizing;

use crate::code::Code;

/// How many digits a pushed code carries.
///
/// Fixed by the companion app rather than by the account's profile: a stored secret that emits eight
/// digits still pushes six here, because the request path belongs to the app.
pub(crate) const DIGITS: usize = 6;

/// The one path this endpoint answers on, compared byte for byte.
///
/// Case-sensitive, because the reference compares ordinally and so the real client sends exactly
/// this.
pub(crate) const TARGET_PREFIX: &[u8] = b"/ffxivlauncher/";

/// The only length a target may have.
///
/// Exact rather than a lower bound, which is what refuses a query string, a fragment, a trailing
/// slash, a doubled slash, a traversal segment, an absolute-form target and a percent-escaped digit
/// without any code that knows what those are.
pub(crate) const TARGET_LEN: usize = TARGET_PREFIX.len() + DIGITS;

/// The most bytes one connection may offer before the answer is a refusal.
///
/// The reference's buffer size, so no working client has ever needed more. The buffer is allocated
/// once per connection and never grown: nothing read out of the input is reserved against, and
/// reaching the ceiling with no line terminator is an answer rather than a resize.
pub(crate) const MAX_REQUEST: usize = 1024;

/// Why a request line was refused.
///
/// Every one of these is a `400` on the wire; the distinction is test vocabulary and a tally, never a
/// status and never a body. No variant carries a byte of what was offered: these bytes came off a
/// socket a stranger opened, and rendering them is a way to write terminal escape sequences into a
/// file the user later reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Refusal {
    /// Byte zero onwards is not `GET `.
    Method,
    /// The bytes at offset four are not the prefix followed by six ASCII digits.
    Target,
    /// No space closed the target, or the token after it does not begin `HTTP`.
    Version,
    /// The cap filled with no line terminator.
    Overlong,
    /// The peer closed its write side before any terminator arrived.
    Truncated,
}

/// Six validated ASCII digits, erased when they drop.
///
/// A fixed array rather than a `Vec` or a `String`: the length is fixed by the grammar, so a growable
/// buffer only adds a reallocation that leaves the old bytes un-erased on the heap. Carried as bytes
/// rather than parsed as a number, because `"012345".parse::<u32>()` is `12345`, which reformats to a
/// five-digit code the login server rejects and the user experiences as a mystery failure, and
/// because a parse accepts a leading `+` besides. Leading zeros are data.
pub(crate) struct Digits(Zeroizing<[u8; DIGITS]>);

impl Digits {
    /// Move the digits into a live code.
    ///
    /// Built by pushing into a string with exactly the capacity it needs, so no intermediate holds a
    /// second un-erased copy, and with no fallible conversion, because the bytes are ASCII digits by
    /// construction and an error path here would be one nothing can reach.
    pub(crate) fn into_code(self) -> Code {
        let mut digits = Zeroizing::new(String::with_capacity(DIGITS));
        for byte in self.0.iter() {
            digits.push(char::from(*byte));
        }
        Code::new(digits)
    }

    /// The digits themselves, so two runs of the reader can be compared.
    ///
    /// Only for the framing checks, which need a verdict that carries equality. Nothing on the
    /// shipping path reads a code back out of one of these; it goes to [`Digits::into_code`] and
    /// leaves as a [`Code`].
    #[cfg(any(test, feature = "fuzzing"))]
    pub(crate) fn bytes(&self) -> [u8; DIGITS] {
        *self.0
    }
}

/// The verdict a reader reaches on `offered`, fed in `stride`-sized pieces.
///
/// `None` when the input ran out with no terminator and no ceiling reached. The return type carries
/// equality precisely so that two strides can be compared, which is the property the framing fuzz
/// target and its in-crate twin assert: how a peer chose its segment boundaries may not change the
/// answer.
#[cfg(any(test, feature = "fuzzing"))]
pub(crate) fn verdict(offered: &[u8], stride: usize) -> Option<Result<[u8; DIGITS], Refusal>> {
    let mut reader = RequestReader::new();
    for chunk in offered.chunks(stride.max(1)) {
        if let Feed::Line(line) = reader.feed(chunk) {
            return Some(line.map(|digits| digits.bytes()));
        }
    }
    None
}

/// Match one request line, terminator already removed, against the grammar.
///
/// Nothing here decodes, normalizes, percent-decodes, lowercases, or parses an integer. Each of those
/// creates a second spelling of a code the fixed length would otherwise have refused, and each is a
/// transformation applied to hostile bytes before they are checked, which is the reference's ordering
/// mistake: it decodes its whole zero-filled buffer with the machine's ANSI codepage and then runs an
/// unanchored regular expression over the result.
pub(crate) fn parse_request_line(line: &[u8]) -> Result<Digits, Refusal> {
    // Anchored at byte zero, not "GET appears somewhere". An unanchored search is what turns a
    // cross-origin form post, whose body a page may choose freely, into a code delivery against the
    // reference.
    let Some(rest) = line.strip_prefix(b"GET ") else {
        return Err(Refusal::Method);
    };
    // The target ends at the first space, not the last. The reference's pattern is greedy, so
    // `GET /ffxivlauncher/123456 HTTP nonsense HTTP/1.1` hands it everything up to the final marker
    // and it submits the lot as a code; ours refuses that on length.
    let Some(end) = rest.iter().position(|byte| *byte == b' ') else {
        return Err(Refusal::Version);
    };
    let (target, after) = rest.split_at(end);
    if target.len() != TARGET_LEN {
        return Err(Refusal::Target);
    }
    let (prefix, digits) = target.split_at(TARGET_PREFIX.len());
    if prefix != TARGET_PREFIX || !digits.iter().all(u8::is_ascii_digit) {
        return Err(Refusal::Target);
    }
    // `after` begins at the space the position above found, so it is never empty and this cannot
    // panic. Four bytes and no more: the reference requires the literal `HTTP` after the target and
    // inspects nothing past it, so requiring `HTTP/` would refuse a client it accepted and requiring
    // only a non-empty remainder would accept one it refused.
    if !after[1..].starts_with(b"HTTP") {
        return Err(Refusal::Version);
    }
    let mut out = Zeroizing::new([0u8; DIGITS]);
    out.copy_from_slice(digits);
    Ok(Digits(out))
}

/// What one chunk of bytes did to the reader.
pub(crate) enum Feed {
    /// No terminator yet, and there is still room. Read again.
    Need,
    /// A line arrived, or the cap filled without one, and it has been answered.
    Line(Result<Digits, Refusal>),
}

/// Accumulate one request line across however many reads it takes.
///
/// A fixed buffer, a fill mark and a scan cursor. Correctness does not depend on how the peer chose
/// its segment boundaries: one byte at a time and one kilobyte at once reach the same verdict, which
/// is what the framing fuzz target asserts and the reason this is a value with a method rather than a
/// loop inside the connection handler. The reference has no such reader, so a request split across
/// TCP segments fills part of its buffer, fails its match, and drops a legitimate code silently.
///
/// The buffer is erased when it drops, because on the accepting path it held a code, and it never
/// grows, because growth leaves the old allocation's bytes on the heap un-erased.
pub(crate) struct RequestReader {
    buf: Zeroizing<[u8; MAX_REQUEST]>,
    filled: usize,
    scanned: usize,
}

impl RequestReader {
    pub(crate) fn new() -> Self {
        Self {
            buf: Zeroizing::new([0u8; MAX_REQUEST]),
            filled: 0,
            scanned: 0,
        }
    }

    /// Take `chunk`.
    ///
    /// Bytes past the ceiling are never copied in: the answer at the ceiling is [`Refusal::Overlong`]
    /// whatever follows, so copying them would be work a peer chose for us. The terminator search
    /// resumes at the cursor rather than restarting, which makes the total work over a connection
    /// linear in the bytes read rather than quadratic: a peer dribbling a kilobyte one byte at a time
    /// costs a kilobyte of comparisons instead of half a million.
    pub(crate) fn feed(&mut self, chunk: &[u8]) -> Feed {
        let take = chunk.len().min(MAX_REQUEST - self.filled);
        self.buf[self.filled..self.filled + take].copy_from_slice(&chunk[..take]);
        self.filled += take;
        if let Some(offset) = self.buf[self.scanned..self.filled]
            .iter()
            .position(|byte| *byte == b'\n')
        {
            let at = self.scanned + offset;
            // One carriage return immediately before the terminator is dropped. A carriage return
            // anywhere else stays in the target and fails the length or the digit test, which is the
            // right split: liberal about the terminator, because the reference accepted both forms
            // and the real client's is unmeasured, and strict about the target, which is what is
            // being hardened.
            let end = if at > 0 && self.buf[at - 1] == b'\r' {
                at - 1
            } else {
                at
            };
            self.scanned = at + 1;
            // Only the bytes actually read, never the whole array: the zero tail is not content the
            // way the reference's is, and a NUL inside a target is a byte that fails the digit test
            // like any other.
            return Feed::Line(parse_request_line(&self.buf[..end]));
        }
        self.scanned = self.filled;
        if self.filled == MAX_REQUEST {
            return Feed::Line(Err(Refusal::Overlong));
        }
        Feed::Need
    }

    /// The buffer, so a test can assert what type it is.
    ///
    /// The return type is the whole point: it stops compiling if the field ever becomes a plain array,
    /// which is the one way the bytes of a code could be left in freed memory with every test still
    /// green.
    #[cfg(test)]
    pub(crate) fn buffer(&self) -> &Zeroizing<[u8; MAX_REQUEST]> {
        &self.buf
    }

    /// The peer closed its write side with no terminator seen.
    ///
    /// A peer that never completed a request line has not made a request, so there is nothing to
    /// answer. Consuming, because there is nothing left to read into.
    pub(crate) fn eof(self) -> Refusal {
        Refusal::Truncated
    }
}

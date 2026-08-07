//! The rules, driven without a socket.
//!
//! Everything section 3 of the design states lives in a module with no IO in it, which is why these
//! are plain tests rather than a socket harness. What needs a real connection is in
//! `tests/listener_wire.rs`; what needs a phone is the manual gate.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::{Duration, Instant};

use proptest::prelude::*;
use rstest::rstest;
use zeroize::Zeroizing;

use super::filter::SourceFilter;
use super::grammar::{
    DIGITS, Feed, MAX_REQUEST, Refusal, RequestReader, parse_request_line, verdict,
};
use super::limiter::{ATTEMPTS, Limiter, SourceKey, TRACKED, WINDOW};
use super::wire::{RESPONSE_BAD_REQUEST, RESPONSE_OK, RESPONSE_TOO_MANY};

/// A well-formed request line with no terminator, which is what the grammar is handed.
fn line(code: &str) -> Vec<u8> {
    format!("GET /ffxivlauncher/{code} HTTP/1.1").into_bytes()
}

/// The digits a line parsed to, or the rule it broke.
fn parsed(offered: &[u8]) -> Result<[u8; DIGITS], Refusal> {
    parse_request_line(offered).map(|digits| digits.bytes())
}

fn v4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(a, b, c, d))
}

// --- the grammar -------------------------------------------------------------------------------

/// What a companion app on a phone puts on the wire, accepted whole.
///
/// **This request is constructed, not captured.** The 0.3 gate records what the real app sends, and
/// that capture replaces this and becomes the authority for every "the app probably sends X" claim in
/// this module: the version token, the terminator, and whether a header block follows at all. The
/// shape here is an ordinary Android HTTP client's, which is what the reference's own contract implies,
/// and it is written out in full so the diff against a real capture is one file.
#[test]
fn a_typical_companion_request_is_accepted() {
    let request: &[u8] = b"GET /ffxivlauncher/482913 HTTP/1.1\r\n\
        Host: 192.168.1.5:4646\r\n\
        Connection: Keep-Alive\r\n\
        Accept-Encoding: gzip\r\n\
        User-Agent: okhttp/4.9.0\r\n\
        \r\n";
    let mut reader = RequestReader::new();
    let Feed::Line(line) = reader.feed(request) else {
        panic!("a complete request line was not recognized");
    };
    assert_eq!(line.map(|digits| digits.bytes()), Ok(*b"482913"));
}

/// The line is matched from its first byte, never searched for.
///
/// The last case is the one that matters most: against the reference, whose pattern is unanchored over
/// the whole buffer, a cross-origin form post whose body a page chooses freely delivers a code. An
/// anchored comparison is what closes a channel that needs no cross-origin permission at all.
#[rstest]
#[case::leading_junk(b"xxGET /ffxivlauncher/123456 HTTP/1.1".as_slice())]
#[case::leading_space(b" GET /ffxivlauncher/123456 HTTP/1.1".as_slice())]
#[case::leading_nul(b"\0GET /ffxivlauncher/123456 HTTP/1.1".as_slice())]
#[case::post(b"POST /ffxivlauncher/123456 HTTP/1.1".as_slice())]
#[case::head(b"HEAD /ffxivlauncher/123456 HTTP/1.1".as_slice())]
#[case::options(b"OPTIONS /ffxivlauncher/123456 HTTP/1.1".as_slice())]
#[case::lowercase(b"get /ffxivlauncher/123456 HTTP/1.1".as_slice())]
#[case::http2_preface(b"PRI * HTTP/2.0".as_slice())]
#[case::tls_hello(b"\x16\x03\x01\x02\x00\x01\x00\x01\xfc\x03\x03".as_slice())]
#[case::form_post_body(b"field=GET /ffxivlauncher/123456 HTTP".as_slice())]
fn a_request_line_is_matched_from_its_first_byte(#[case] offered: &[u8]) {
    assert_eq!(parsed(offered), Err(Refusal::Method));
}

/// A target is exactly the prefix and six digits, so its length alone refuses every other spelling.
///
/// None of these needs code that knows what a query string, a traversal segment or an absolute-form
/// target is. That is the point: one length comparison covers a family that a normalizing parser would
/// have to enumerate, and enumerating it is how one gets missed.
#[rstest]
#[case::five_digits(b"GET /ffxivlauncher/12345 HTTP/1.1".as_slice())]
#[case::seven_digits(b"GET /ffxivlauncher/1234567 HTTP/1.1".as_slice())]
#[case::trailing_slash(b"GET /ffxivlauncher/123456/ HTTP/1.1".as_slice())]
#[case::leading_double_slash(b"GET //ffxivlauncher/123456 HTTP/1.1".as_slice())]
#[case::inner_double_slash(b"GET /ffxivlauncher//123456 HTTP/1.1".as_slice())]
#[case::query(b"GET /ffxivlauncher/123456?x=1 HTTP/1.1".as_slice())]
#[case::fragment(b"GET /ffxivlauncher/123456#a HTTP/1.1".as_slice())]
#[case::percent_encoded(b"GET /ffxivlauncher/%31%32%33%34%35%36 HTTP/1.1".as_slice())]
#[case::traversal(b"GET /ffxivlauncher/../ffxivlauncher/123456 HTTP/1.1".as_slice())]
#[case::absolute_form(b"GET http://host/ffxivlauncher/123456 HTTP/1.1".as_slice())]
#[case::wrong_case(b"GET /FFXIVLauncher/123456 HTTP/1.1".as_slice())]
#[case::empty_target(b"GET  HTTP/1.1".as_slice())]
#[case::carriage_return_inside(b"GET /ffxivlauncher/12\r456 HTTP/1.1".as_slice())]
#[case::double_space(b"GET  /ffxivlauncher/123456 HTTP/1.1".as_slice())]
fn only_fifteen_bytes_of_path_and_six_digits_are_a_target(#[case] offered: &[u8]) {
    assert_eq!(parsed(offered), Err(Refusal::Target));
}

/// Digits are ASCII bytes, not numbers and not characters.
///
/// The first three are accepted by `char::is_numeric`, which is why nothing on this path builds a
/// `char`. The fourth is accepted by an integer parse, which is why nothing here parses one.
#[rstest]
#[case::arabic_indic("١٢٣٤٥٦")]
#[case::fullwidth("１２３４５６")]
#[case::devanagari("१२३४५६")]
#[case::signed("+12345")]
#[case::inner_space("12 456")]
#[case::trailing_nul("12345\0")]
fn digits_are_ascii_bytes_and_not_numbers(#[case] code: &str) {
    assert_eq!(parsed(&line(code)), Err(Refusal::Target));
}

/// Leading zeros survive.
///
/// A parse-and-reformat implementation turns this into five digits, which Square Enix rejects and the
/// user experiences as a login that mysteriously stopped working.
#[test]
fn leading_zeros_survive_the_grammar() {
    assert_eq!(parsed(&line("012345")), Ok(*b"012345"));
    assert_eq!(parsed(&line("000000")), Ok(*b"000000"));
}

/// The version token is the reference's rule: the four bytes `HTTP` and nothing about what follows.
///
/// Requiring a slash after them would refuse a client the reference accepted; requiring only a
/// non-empty remainder would accept one it refused. This is the rule the gate capture can overturn,
/// and if it does, the capture wins.
#[rstest]
#[case::bare(b"GET /ffxivlauncher/123456 HTTP".as_slice(), true)]
#[case::one_one(b"GET /ffxivlauncher/123456 HTTP/1.1".as_slice(), true)]
#[case::one_zero(b"GET /ffxivlauncher/123456 HTTP/1.0".as_slice(), true)]
#[case::trailing_junk(b"GET /ffxivlauncher/123456 HTTPnonsense".as_slice(), true)]
#[case::no_space(b"GET /ffxivlauncher/123456".as_slice(), false)]
#[case::nothing_after_space(b"GET /ffxivlauncher/123456 ".as_slice(), false)]
#[case::wrong_token(b"GET /ffxivlauncher/123456 X".as_slice(), false)]
#[case::short_token(b"GET /ffxivlauncher/123456 HTT".as_slice(), false)]
// The shape the first-space rule exists for, and where our answer and the reference's differ: it
// captures greedily to the last marker and submits `123456 HTTP nonsense` as the code.
#[case::second_http_token(b"GET /ffxivlauncher/123456 HTTP nonsense HTTP/1.1".as_slice(), true)]
fn the_version_token_is_the_reference_rule(#[case] offered: &[u8], #[case] accepted: bool) {
    match parsed(offered) {
        Ok(digits) => {
            assert!(accepted, "expected a refusal");
            assert_eq!(digits, *b"123456");
        }
        Err(refusal) => {
            assert!(!accepted, "expected an acceptance");
            assert_eq!(refusal, Refusal::Version);
        }
    }
}

/// A carriage return belongs immediately before the terminator and nowhere else.
///
/// Liberal about the terminator, because the reference accepted both forms and the real client's is
/// unmeasured; strict about the target, because that is the part being hardened. A lone carriage
/// return is not a terminator at all.
#[test]
fn a_carriage_return_belongs_only_before_the_terminator() {
    assert_eq!(
        verdict(b"GET /ffxivlauncher/123456 HTTP/1.1\r\n", 64),
        Some(Ok(*b"123456"))
    );
    assert_eq!(
        verdict(b"GET /ffxivlauncher/123456 HTTP/1.1\n", 64),
        Some(Ok(*b"123456"))
    );
    // No line feed anywhere, so nothing was terminated and the reader is still waiting.
    assert_eq!(verdict(b"GET /ffxivlauncher/123456 HTTP/1.1\r", 64), None);
    // Two of them: the first is left in the line and lands past the version token, which is not
    // inspected, so this is still the same request.
    assert_eq!(
        verdict(b"GET /ffxivlauncher/123456 HTTP/1.1\r\r\n", 64),
        Some(Ok(*b"123456"))
    );
}

/// Nothing after the first terminator is parsed, so a pipelined second line cannot be a second code
/// and cannot multiply a budget.
#[test]
fn nothing_after_the_first_terminator_is_parsed() {
    let two = b"GET /ffxivlauncher/111111 HTTP/1.1\r\nGET /ffxivlauncher/222222 HTTP/1.1\r\n";
    assert_eq!(verdict(two, usize::MAX), Some(Ok(*b"111111")));

    let with_headers = b"GET /ffxivlauncher/111111 HTTP/1.1\r\nHost: x\r\n\r\nbody";
    assert_eq!(verdict(with_headers, usize::MAX), Some(Ok(*b"111111")));
}

/// An upgrade request is a valid request line and is answered as the ordinary delivery it textually
/// is. Pinned so it stays boring: there is no upgrade machinery for it to reach.
#[test]
fn a_websocket_upgrade_is_an_ordinary_delivery() {
    let request = b"GET /ffxivlauncher/123456 HTTP/1.1\r\n\
        Upgrade: websocket\r\n\
        Connection: Upgrade\r\n\r\n";
    assert_eq!(verdict(request, usize::MAX), Some(Ok(*b"123456")));
}

/// The ceiling refuses rather than growing, and it is reached only by the absence of a terminator.
#[test]
fn the_cap_refuses_rather_than_grows() {
    let mut reader = RequestReader::new();
    let flood = vec![b'A'; MAX_REQUEST];
    let Feed::Line(line) = reader.feed(&flood) else {
        panic!("the ceiling did not answer");
    };
    assert_eq!(line.map(|digits| digits.bytes()), Err(Refusal::Overlong));
    assert_eq!(reader.buffer().len(), MAX_REQUEST);

    // One byte short of the ceiling, then a terminator: an ordinary grammar refusal, not a length one.
    let mut short = vec![b'A'; MAX_REQUEST - 1];
    short.push(b'\n');
    assert_eq!(verdict(&short, usize::MAX), Some(Err(Refusal::Method)));
}

/// A line delivered one byte at a time still parses.
///
/// The degenerate case, spelled out because it is what a phone on bad wireless produces and what the
/// reference's single unchecked read silently drops.
#[test]
fn a_line_delivered_one_byte_at_a_time_still_parses() {
    assert_eq!(
        verdict(b"GET /ffxivlauncher/424242 HTTP/1.1\r\n", 1),
        Some(Ok(*b"424242"))
    );
}

/// A carriage return at the end of one chunk and a line feed at the start of the next.
///
/// The one boundary the resumption cursor could get wrong, because the stripping rule looks one byte
/// behind a byte that arrived in a different read.
#[test]
fn a_terminator_split_from_its_carriage_return_still_strips_it() {
    let mut reader = RequestReader::new();
    assert!(matches!(
        reader.feed(b"GET /ffxivlauncher/303030 HTTP/1.1\r"),
        Feed::Need
    ));
    let Feed::Line(line) = reader.feed(b"\n") else {
        panic!("the terminator was not recognized");
    };
    assert_eq!(line.map(|digits| digits.bytes()), Ok(*b"303030"));
}

/// End of file before a terminator is a peer that never made a request, so there is nothing to answer.
#[test]
fn eof_before_a_terminator_answers_nothing() {
    let mut reader = RequestReader::new();
    assert!(matches!(reader.feed(b"GET /ffxiv"), Feed::Need));
    assert_eq!(reader.eof(), Refusal::Truncated);
}

/// Only the bytes that were actually read are inspected.
///
/// The reference decodes its whole zero-filled buffer and matches over the result; this asserts the
/// tail is not content. The line here would parse if the trailing zeros were included in it.
#[test]
fn only_the_bytes_that_were_read_are_inspected() {
    let mut reader = RequestReader::new();
    let Feed::Line(line) = reader.feed(b"GET /ffxivlauncher/909090 HTTP\n") else {
        panic!("the terminator was not recognized");
    };
    assert_eq!(line.map(|digits| digits.bytes()), Ok(*b"909090"));
    // The rest of the array is untouched zeros, and none of it reached the grammar.
    assert!(reader.buffer()[31..].iter().all(|byte| *byte == 0));
}

/// What the reader holds is erased when it drops.
///
/// Asserted by a helper that will not compile against a plain array, because on the accepting path
/// that buffer held a code and nothing running could notice it being left in freed memory. Copies the
/// shape of the reuse guard's own erasure test, which is the precedent for pinning an absence.
#[test]
fn the_read_buffer_is_erased_when_it_drops() {
    const fn erased(_: &Zeroizing<[u8; MAX_REQUEST]>) {}

    let mut reader = RequestReader::new();
    let _ = reader.feed(b"GET /ffxivlauncher/123456 HTTP\n");
    erased(reader.buffer());
}

// --- the limiter -------------------------------------------------------------------------------

/// The budget the design fixes, exactly, at one instant.
#[test]
fn five_attempts_pass_and_the_sixth_does_not() {
    let now = Instant::now();
    let key = SourceKey::of(v4(192, 0, 2, 1));
    let mut limiter = Limiter::new();
    for _ in 0..ATTEMPTS {
        assert!(!limiter.spent(key, now));
        limiter.charge(key, now);
    }
    assert!(limiter.spent(key, now));
}

/// The window slides rather than resetting.
///
/// A fixed-bucket implementation passes a naive version of this and fails this one: it would clear the
/// whole count at a boundary instead of ageing out one attempt at a time.
#[test]
fn the_window_slides_rather_than_resetting() {
    let start = Instant::now();
    let key = SourceKey::of(v4(192, 0, 2, 2));
    let mut limiter = Limiter::new();
    for _ in 0..ATTEMPTS {
        limiter.charge(key, start);
    }
    assert!(limiter.spent(key, start + Duration::from_secs(59)));
    assert!(!limiter.spent(key, start + WINDOW + Duration::from_secs(1)));
}

/// One source's flood never spends another's budget.
///
/// The whole reason the accounting is per source: a global counter is the attacker's tool rather than
/// the user's defence, because five packets from anywhere would lock out the phone.
#[test]
fn a_flooding_source_never_spends_another_sources_budget() {
    let now = Instant::now();
    let flooder = SourceKey::of(v4(192, 0, 2, 3));
    let phone = SourceKey::of(v4(192, 0, 2, 4));
    let mut limiter = Limiter::new();
    for _ in 0..ATTEMPTS * 4 {
        limiter.charge(flooder, now);
    }
    assert!(limiter.spent(flooder, now));
    assert!(!limiter.spent(phone, now));
}

/// Eviction can only grant budget, never revoke it.
///
/// The direction is the argument: an honest phone can never be refused because of another address's
/// activity. A fail-closed table would have exactly that failure and would cost the feature.
#[test]
fn eviction_can_only_grant_budget() {
    let now = Instant::now();
    let mut limiter = Limiter::new();
    let first = SourceKey::of(v4(10, 0, 0, 1));
    for _ in 0..ATTEMPTS {
        limiter.charge(first, now);
    }
    assert!(limiter.spent(first, now));

    // Fill the table past its capacity with fresh sources, which evicts the least recently seen.
    for index in 0..TRACKED + 8 {
        let filler = SourceKey::of(v4(10, 1, (index / 256) as u8, (index % 256) as u8));
        limiter.charge(filler, now + Duration::from_millis(index as u64 + 1));
    }
    assert!(!limiter.spent(first, now + Duration::from_secs(1)));
}

/// The table never grows past its capacity, whatever arrives.
///
/// A map with an entry per distinct source is itself the exhaustion vector the limiter exists to stop:
/// one host with a routing prefix can insert one row per connection, for free, without limit.
#[test]
fn the_table_never_grows() {
    let now = Instant::now();
    let mut limiter = Limiter::new();
    let capacity = limiter.capacity();
    for index in 0..10_000u32 {
        limiter.charge(SourceKey::of(IpAddr::V4(Ipv4Addr::from(index))), now);
    }
    assert!(limiter.tracked() <= TRACKED);
    assert_eq!(limiter.capacity(), capacity);
}

/// An IPv6 source is accounted on its prefix, because a prefix is one host's worth of addresses.
#[test]
fn an_ipv6_source_is_accounted_on_its_prefix() {
    let now = Instant::now();
    let mut limiter = Limiter::new();
    let one = SourceKey::of(IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)));
    let same_prefix = SourceKey::of(IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 9, 9, 9, 9)));
    let other_prefix = SourceKey::of(IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 1, 0, 0, 0, 1)));

    for _ in 0..ATTEMPTS {
        limiter.charge(one, now);
    }
    assert!(limiter.spent(same_prefix, now));
    assert!(!limiter.spent(other_prefix, now));
}

/// An address family is part of the key.
///
/// Both arms write into the leading window of one zeroed array, so without a discriminator an IPv4
/// address and the /64 whose prefix spells the same four octets share a row. The consequence runs the
/// wrong way for once: a source would get *less* than its budget, and its next code would be answered
/// without being read. The test above cannot see this, because it only ever compares IPv6 to IPv6.
#[test]
fn an_address_family_is_part_of_the_key() {
    let now = Instant::now();
    let mut limiter = Limiter::new();
    let v4 = SourceKey::of(v4(192, 168, 1, 5));
    // `c0a8:0105::/64` is 192.168.1.5 in the leading four octets.
    let v6 = SourceKey::of(IpAddr::V6(Ipv6Addr::new(0xc0a8, 0x0105, 0, 0, 0, 0, 0, 1)));

    assert_ne!(v4, v6);
    for _ in 0..ATTEMPTS {
        limiter.charge(v6, now);
    }
    assert!(limiter.spent(v6, now));
    assert!(
        !limiter.spent(v4, now),
        "an IPv6 prefix spent an IPv4 address's budget"
    );
}

/// The budget is measured on a monotonic clock.
///
/// Type-level, and that is the whole of it: a wall clock here would let a user correcting their
/// machine's time grant or revoke budget, on a project that already knows its clocks drift.
#[test]
fn the_limiter_reads_a_monotonic_clock() {
    const fn monotonic(_: fn(&Limiter, SourceKey, Instant) -> bool) {}
    monotonic(Limiter::spent);
}

// --- the filter --------------------------------------------------------------------------------

/// A mapped peer matches its plain entry, and the reverse.
///
/// Written so that removing either canonicalization fails it. The failure this prevents is silent and
/// fail-closed: a host bound to the IPv6 wildcard reports every IPv4 peer in the mapped form, the
/// user's own phone stops matching, and the symptom reads as the phone app being broken.
#[test]
fn an_ipv4_mapped_peer_matches_its_ipv4_entry() {
    let plain = v4(192, 0, 2, 10);
    let mapped = IpAddr::V6(Ipv4Addr::new(192, 0, 2, 10).to_ipv6_mapped());

    let Some(pinned_plain) = SourceFilter::only(plain, &[]) else {
        panic!("a routable address was refused");
    };
    assert!(pinned_plain.admits(mapped));
    assert!(pinned_plain.admits(plain));

    let Some(pinned_mapped) = SourceFilter::only(mapped, &[]) else {
        panic!("a mapped address was refused");
    };
    assert!(pinned_mapped.admits(plain));
}

/// Nothing is admitted implicitly, loopback least of all.
///
/// A page in the user's own browser issues this request from a loopback address and needs no
/// cross-origin permission to do it, so an implicit exemption would hand exactly that peer a way
/// around the pin the user set to stop it.
#[test]
fn nothing_is_admitted_implicitly() {
    let Some(filter) = SourceFilter::only(v4(192, 0, 2, 11), &[]) else {
        panic!("a routable address was refused");
    };
    assert!(!filter.admits(IpAddr::V4(Ipv4Addr::LOCALHOST)));
    assert!(!filter.admits(IpAddr::V6(Ipv6Addr::LOCALHOST)));
    assert!(!filter.admits(v4(192, 0, 2, 12)));
    assert!(SourceFilter::Any.admits(IpAddr::V4(Ipv4Addr::LOCALHOST)));
}

/// A link-local entry is refused at construction.
///
/// The scope identifier that gives such an address meaning is dropped by the address type, so a pin on
/// one would be satisfied by the same address arriving over a different interface. Refusing costs
/// nothing, because a phone's link-local address is not a stable thing to pin.
#[test]
fn a_link_local_entry_is_refused() {
    let link_local = IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1));
    assert!(SourceFilter::only(link_local, &[]).is_none());
    assert!(SourceFilter::only(v4(192, 0, 2, 13), &[link_local]).is_none());
    // The whole fe80::/10 range, not just the first sixteen bits.
    let high = IpAddr::V6(Ipv6Addr::new(0xfebf, 0, 0, 0, 0, 0, 0, 1));
    assert!(SourceFilter::only(high, &[]).is_none());
}

/// An empty allowlist cannot be built.
///
/// Type-level: the constructor takes its first address separately, so "admit nobody" has no spelling
/// and cannot be produced by a config format that drops empty collections. This test records the seal
/// and asserts the one thing that is observable, which is that a built filter is never empty.
#[test]
fn an_empty_allowlist_cannot_be_built() {
    let Some(SourceFilter::Only(pinned)) = SourceFilter::only(v4(192, 0, 2, 14), &[]) else {
        panic!("a routable address was refused");
    };
    assert!(!pinned.is_empty());
    assert_eq!(pinned.len(), 1);

    // Duplicates collapse rather than accumulating, so a hand-edited list cannot grow the scan.
    let Some(SourceFilter::Only(twice)) =
        SourceFilter::only(v4(192, 0, 2, 14), &[v4(192, 0, 2, 14)])
    else {
        panic!("a routable address was refused");
    };
    assert_eq!(twice.len(), 1);
}

// --- the wire ----------------------------------------------------------------------------------

/// The compatibility response is the reference's bytes.
///
/// Written here as one literal against a constant assembled from continued lines, so the two spellings
/// have to agree and a mistake in either is a failure rather than a silent change. A regression here is
/// a broken phone app, not a wording change: the line feeds are what shipping XIVLauncher emits and
/// carriage-return pairs are a guess.
#[test]
fn the_compat_response_is_the_reference_bytes() {
    let expected: &[u8] = b"HTTP/1.0 200 OK\nContent-Type: application/json; charset=UTF-8\n\n{\"app\":\"XIVLauncher\", \"version\":\"1.0.0.0\"}";
    assert_eq!(RESPONSE_OK, expected);
    assert_eq!(RESPONSE_OK.len(), 105);
    assert!(!RESPONSE_OK.contains(&b'\r'));

    assert_eq!(
        RESPONSE_BAD_REQUEST,
        b"HTTP/1.0 400 Bad Request\nContent-Length: 0\n\n".as_slice()
    );
    assert_eq!(
        RESPONSE_TOO_MANY,
        b"HTTP/1.0 429 Too Many Requests\nRetry-After: 60\nContent-Length: 0\n\n".as_slice()
    );
}

/// No response carries anything derived from a request.
///
/// This is the whole defence against a page that re-resolves its own name to this host so as to become
/// same-origin and read the body: what it can read is a constant, so reading it is worthless. The
/// status also never depends on the login outcome, which would otherwise make this an oracle for
/// validating guesses against a live account with no Square Enix rate limit in the attacker's loop.
#[test]
fn no_response_carries_anything_from_a_request() {
    for response in [RESPONSE_OK, RESPONSE_BAD_REQUEST, RESPONSE_TOO_MANY] {
        let rendered = String::from_utf8_lossy(response);
        // The target is never echoed, so a reader learns nothing about what was asked for.
        assert!(!rendered.contains("ffxivlauncher"), "{rendered}");
        // No run of six digits anywhere, which is the shape a code has. The version and the two
        // header values are the only digits in the set and none of them is that long.
        let longest = response
            .split(|byte| !byte.is_ascii_digit())
            .map(<[u8]>::len)
            .max()
            .unwrap_or(0);
        assert!(longest < DIGITS, "{rendered}");
        // Absence is the restrictive posture, and it is what the reference does, so it costs no
        // compatibility. Reading is not what needs restricting; sending is, and no header stops that.
        assert!(
            !rendered.contains("Access-Control-Allow-Origin"),
            "{rendered}"
        );
    }
}

proptest! {
    /// How a peer chose its segment boundaries may not change the answer.
    ///
    /// The in-crate twin of the framing fuzz target, so a regression is caught by the ordinary test run
    /// and not only by a soak.
    #[test]
    fn a_chunk_boundary_never_changes_the_verdict(
        bytes in proptest::collection::vec(any::<u8>(), 0..1500),
        stride in 1usize..96,
    ) {
        prop_assert_eq!(verdict(&bytes, stride), verdict(&bytes, usize::MAX));
    }

    /// The same, over inputs that are actually requests, because random bytes almost never are and so
    /// would exercise only the refusal paths.
    #[test]
    fn a_chunk_boundary_never_changes_a_real_request(
        code in "[0-9]{6}",
        stride in 1usize..64,
        crlf in any::<bool>(),
    ) {
        let mut request = line(&code);
        if crlf {
            request.push(b'\r');
        }
        request.push(b'\n');
        prop_assert_eq!(verdict(&request, stride), verdict(&request, usize::MAX));
    }

    /// Every six-digit code round-trips through the grammar as those exact bytes.
    ///
    /// The half that catches a truncation, a reformat, or a digit dropped at a boundary.
    #[test]
    fn any_six_ascii_digits_round_trip(code in "[0-9]{6}") {
        prop_assert_eq!(parsed(&line(&code)).ok(), code.as_bytes().first_chunk::<DIGITS>().copied());
    }
}

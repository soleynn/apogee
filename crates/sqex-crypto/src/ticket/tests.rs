//! Unit tests for the ticket transform.
//!
//! The traces below pin every intermediate of a fully hand-derivable case, so a failure names the
//! step that broke instead of only reporting that the final string differs. They were derived
//! independently of the recorded vectors and then found to agree with them, which is what makes them
//! a check on the recording rather than a restatement of it.

use proptest::prelude::*;
use rstest::rstest;

use super::*;

/// A second spelling of the ticket plaintext, following the reference's step order.
///
/// Independent where it counts: the head word is read back out of the buffer instead of derived from
/// the sum and the first byte's digits, and the padding count is computed up front instead of falling
/// out of the loop bound. Those are the two places the implementation departs from how the reference
/// is written, and a divergence in either fails `buffer_matches_an_independent_model`. The byte-order
/// conversions still go through [`bytes`], which is the crate's one endianness home and is pinned by
/// its own tests; restating them here would put a second spelling of the LE/BE split in the tree.
fn model_buffer(raw: &[u8], rounded: u32) -> Vec<u8> {
    let mut hex = Vec::new();
    let mut sum: u16 = 0;
    for &b in raw {
        for digit in [HEX_LOWER[(b >> 4) as usize], HEX_LOWER[(b & 0x0F) as usize]] {
            hex.push(digit);
            sum = sum.wrapping_add(u16::from(digit));
        }
    }
    hex.push(0);

    let mut buf = Vec::new();
    buf.extend_from_slice(&bytes::write_u16_le(sum));
    buf.extend_from_slice(&hex);

    let total = (hex.len() + 9) & !7;
    let padding = total - 2 - hex.len();
    let mut rng = CrtRand::new(rounded ^ (sum as i16 as i32 as u32));
    let mut running = bytes::u32_le([buf[0], buf[1], buf[2], buf[3]]);
    for _ in 0..padding {
        let ch = PAD_ALPHABET[(running.wrapping_add(rng.next()) & 0x3F) as usize];
        buf.push(ch);
        running = running.wrapping_add(u32::from(ch));
    }

    buf[..4].copy_from_slice(&bytes::write_u32_le(running));
    buf.swap(0, 1);
    buf
}

/// Every slot of the padding alphabet, derived from its structure instead of re-typed.
///
/// The recorded vectors draw only half the table, so the other half rests on the literal being typed
/// correctly once. A wrong slot yields a well-formed, correctly-sized, correctly-encoded ticket that
/// only the server rejects. Deriving the sequence here (digits, uppercase, lowercase, then `-` and
/// `_`) is an independent statement of the same table, so a transcription slip fails this.
#[test]
fn every_padding_slot_is_pinned() {
    let derived: Vec<u8> = (b'0'..=b'9')
        .chain(b'A'..=b'Z')
        .chain(b'a'..=b'z')
        .chain(*b"-_")
        .collect();
    assert_eq!(PAD_ALPHABET.as_slice(), derived.as_slice());
}

/// The hex table, same reasoning: it expands the ticket and builds the cipher key, and a wrong digit
/// in the tail of it survives every vector whose bytes never reach that nibble.
#[test]
fn every_hex_digit_is_pinned() {
    let derived: Vec<u8> = (b'0'..=b'9').chain(b'a'..=b'f').collect();
    assert_eq!(HEX_LOWER.as_slice(), derived.as_slice());
}

/// The smallest possible ticket, worked end to end.
///
/// A one-byte ticket expands to the two hex digits `61 62`, so the whole plaintext is a single
/// 8-byte block: two sum bytes, two hex digits, the terminator, and three padding characters.
#[test]
fn trace_one_byte_ticket() {
    let raw = [0xab_u8];
    let rounded = round_to_minute(100);
    assert_eq!(
        rounded, 60,
        "100 less five is 95, floored to the minute is 60"
    );

    let key = blowfish_key(rounded);
    assert_eq!(key.as_slice(), b"0000003c#un@e=x>");

    // 0x61 + 0x62, plus a terminator that contributes nothing.
    let ticket_sum: u16 = 0x61 + 0x62;
    assert_eq!(ticket_sum, 195);

    let seed = rand_seed(rounded, ticket_sum);
    assert_eq!(seed, 0xff, "60 ^ 195, with no sign extension below 0x8000");

    let mut rng = CrtRand::new(seed);
    let drawn: Vec<u32> = (0..3).map(|_| rng.next()).collect();
    assert_eq!(drawn, [871, 28819, 21850]);

    let buf = build_buffer(&raw, raw[0], rounded);
    // Head is the running sum 0x626101d1 written little-endian, then bytes 0 and 1 swapped. The
    // padding characters are `g`, `z`, `-`.
    assert_eq!(buf, [0x01, 0xd1, 0x61, 0x62, 0x00, 0x67, 0x7a, 0x2d]);

    let ciphertext = Blowfish::new(key.as_slice()).encrypt(&buf);
    assert_eq!(ciphertext, [0x97, 0xd7, 0xeb, 0x64, 0x0f, 0xb3, 0x98, 0xb8]);

    let ticket = ObfuscatedTicket::from_auth_ticket(&raw, ServerTime(100))
        .expect("a one-byte ticket is not empty");
    assert_eq!(ticket.text(), "l9frZA-zmLg*");
    assert_eq!(ticket.length(), 12);
}

/// The same ticket against a clock reading below five, where the subtraction wraps.
#[test]
fn trace_clock_wraps_below_five() {
    let raw = [0xab_u8];
    let rounded = round_to_minute(3);
    assert_eq!(
        rounded, 0xffff_fff0,
        "3 less five wraps, then floors to the minute"
    );

    let key = blowfish_key(rounded);
    assert_eq!(key.as_slice(), b"fffffff0#un@e=x>");

    let seed = rand_seed(rounded, 195);
    assert_eq!(seed, 0xffff_ff33);

    let buf = build_buffer(&raw, raw[0], rounded);
    assert_eq!(buf, [0x01, 0xbe, 0x61, 0x62, 0x00, 0x43, 0x45, 0x73]);

    let ticket =
        ObfuscatedTicket::from_auth_ticket(&raw, ServerTime(3)).expect("not an empty ticket");
    assert_eq!(ticket.text(), "3Jfy2-greQ0*");
    assert_eq!(ticket.length(), 12);
}

/// The head write always *overwrites* the first two hex digits, but it usually writes back the same
/// values, because the running sum starts out holding those very digits in its high half and the
/// padding only ever adds a few hundred to its low half. They change only when the ticket sum sits
/// close enough to the 16-bit wrap for that addition to carry.
///
/// Both traces above are in the usual case, so on their own they would equally support the wrong
/// rule that the digits survive by design. These two cases pin the actual boundary.
#[test]
fn the_head_write_changes_the_hex_digits_only_on_a_carry() {
    let rounded = round_to_minute(100);
    let digits = hex_digits(0xff);

    // Sum 0x9f60, far from the wrap: the digits are rewritten with themselves.
    let short = [0xff_u8; 200];
    let buf = build_buffer(&short, short[0], rounded);
    assert_eq!((buf[2], buf[3]), digits);

    // Sum 0xff00, near the wrap: the padding carries into the high half and the first digit moves.
    let long = [0xff_u8; 320];
    let buf = build_buffer(&long, long[0], rounded);
    assert_ne!((buf[2], buf[3]), digits);
    assert_eq!((buf[2], buf[3]), (b'g', b'f'));
}

#[rstest]
#[case(0, 0xffff_fff0)]
#[case(1, 0xffff_fff0)]
#[case(4, 0xffff_fff0)]
#[case(5, 0)]
#[case(59, 0)]
#[case(60, 0)]
#[case(64, 0)]
#[case(65, 60)]
#[case(3599, 3540)]
#[case(u32::MAX, 0xffff_fff0)]
fn rounding_table(#[case] time: u32, #[case] expected: u32) {
    assert_eq!(round_to_minute(time), expected);
}

/// The 64-to-32 narrowing keeps the low word rather than saturating.
///
/// Asserted on the word itself rather than on a ticket built from it. Rounding folds `0..=4` and
/// `u32::MAX` onto the same minute, so a reading one second either side of a boundary produces an
/// identical ticket under truncation and under clamping; only the rows more than a minute out
/// distinguish the two.
#[rstest]
#[case(0, 0)]
#[case(1_785_000_000, 1_785_000_000)]
#[case(-1, 0xffff_ffff)]
#[case(-60, 0xffff_ffc4)]
#[case(0x1_0000_0000, 0)]
#[case(0x1_0000_005b, 0x5b)]
fn from_unix_seconds_keeps_the_low_word(#[case] secs: i64, #[case] expected: u32) {
    assert_eq!(ServerTime::from_unix_seconds(secs).0, expected);
}

#[test]
fn rand_seed_sign_extends_rather_than_widening() {
    // A 200-byte run of 0xff sums to 0x9f60, which has bit 15 set.
    let rounded = round_to_minute(1_700_000_000);
    assert_eq!(rounded, 0x6553_f0ec);
    let seed = rand_seed(rounded, 0x9f60);
    assert_eq!(seed, 0x9aac_6f8c);
    // What folding the sum in unsigned would have produced. Spelled out so a reader sees the wrong
    // answer without running anything; it differs only in the high half, and every padding character
    // downstream differs with it.
    assert_ne!(seed, 0x6553_6f8c);
}

/// Folding the alphabet *index* back into the running sum instead of the character it selected still
/// draws in-range characters from the same alphabet, so neither a bounds check nor an
/// alphabet-membership assertion notices. Only a divergence test states that the distinction matters.
#[test]
fn padding_folds_the_character_not_the_index() {
    fn pad_bytes(seed: u32, mut running: u32, count: usize, fold_index: bool) -> Vec<u8> {
        let mut rng = CrtRand::new(seed);
        let mut out = Vec::with_capacity(count);
        for _ in 0..count {
            let idx = (running.wrapping_add(rng.next()) & 0x3F) as usize;
            let ch = PAD_ALPHABET[idx];
            out.push(ch);
            running = running.wrapping_add(if fold_index {
                idx as u32
            } else {
                u32::from(ch)
            });
        }
        out
    }

    let by_char = pad_bytes(0xff, 0x6261_00c3, 7, false);
    let by_index = pad_bytes(0xff, 0x6261_00c3, 7, true);
    assert_ne!(by_char, by_index);
    // Both stay inside the alphabet, which is exactly why the mistake is invisible locally.
    assert!(by_index.iter().all(|b| PAD_ALPHABET.contains(b)));
}

#[rstest]
#[case(1, 8, 3)]
#[case(2, 8, 1)]
#[case(3, 16, 7)]
#[case(4, 16, 5)]
#[case(5, 16, 3)]
#[case(6, 16, 1)]
#[case(7, 24, 7)]
#[case(8, 24, 5)]
fn buffer_and_padding_lengths_cycle(
    #[case] raw_len: usize,
    #[case] total: usize,
    #[case] padding: usize,
) {
    let raw = vec![0x5a_u8; raw_len];
    let buf = build_buffer(&raw, raw[0], 60);
    assert_eq!(buf.len(), total);
    // Two sum bytes, two hex digits per raw byte, one terminator; the rest is padding.
    assert_eq!(buf.len() - (2 * raw_len + 3), padding);
}

#[test]
fn empty_ticket_is_rejected() {
    let err = ObfuscatedTicket::from_auth_ticket(&[], ServerTime(1_700_000_000))
        .expect_err("an empty ticket has no head word to seed the generator from");
    assert!(matches!(err, CryptoError::EmptyTicket));
}

#[test]
fn debug_redacts_the_text() {
    let ticket =
        ObfuscatedTicket::from_auth_ticket(&[0xab], ServerTime(100)).expect("not an empty ticket");
    let rendered = format!("{ticket:?}");
    assert!(!rendered.contains(ticket.text()), "{rendered}");
    assert!(rendered.contains("<redacted>"), "{rendered}");
    assert!(
        rendered.contains("12"),
        "the length is not secret: {rendered}"
    );
}

#[rstest]
#[case(299, 299, 0)]
#[case(300, 300, 0)]
#[case(301, 302, 1)]
#[case(600, 601, 1)]
#[case(601, 603, 2)]
fn split_join_boundaries(
    #[case] encoded_len: usize,
    #[case] text_len: usize,
    #[case] separators: usize,
) {
    let encoded = "a".repeat(encoded_len);
    let text = split_join(&encoded);
    assert_eq!(text.len(), text_len);
    assert_eq!(text.matches(',').count(), separators);
}

proptest! {
    /// Restates the fold independently of the implementation's two-step spelling.
    #[test]
    fn round_to_minute_lands_on_a_minute(time: u32) {
        let rounded = round_to_minute(time);
        prop_assert_eq!(rounded % 60, 0);
        prop_assert_eq!(rounded, (time.wrapping_sub(5) / 60) * 60);
    }

    /// The nibble-by-nibble key render must stay byte-identical to a formatted one. Pinned rather
    /// than asserted in a comment, because the hand render exists only to keep the digits off the
    /// heap and has no other reason to be trusted.
    #[test]
    fn blowfish_key_matches_a_formatted_render(rounded: u32) {
        let key = blowfish_key(rounded);
        let expected = format!("{rounded:08x}");
        prop_assert_eq!(&key[..8], expected.as_bytes());
        prop_assert_eq!(&key[8..], KEY_SUFFIX);
    }

    /// Sign extension restated as a case split on bit 15, so the cast chain is not the only place
    /// the rule is written down.
    #[test]
    fn rand_seed_splits_at_bit_fifteen(rounded: u32, sum: u16) {
        let expected = if sum < 0x8000 {
            rounded ^ u32::from(sum)
        } else {
            rounded ^ (0xffff_0000 | u32::from(sum))
        };
        prop_assert_eq!(rand_seed(rounded, sum), expected);
    }

    /// The cipher pads silently rather than rejecting a short final block, so the block-multiple
    /// invariant cannot be delegated to it and is asserted here instead.
    #[test]
    fn buffer_is_a_non_empty_block_multiple(
        raw in prop::collection::vec(any::<u8>(), 1..300),
        time: u32,
    ) {
        let buf = build_buffer(&raw, raw[0], round_to_minute(time));
        prop_assert_eq!(buf.len() % 8, 0);
        prop_assert!(buf.len() >= 8);
        // The buffer is exactly the sum, the hex, the terminator, and under eight padding bytes.
        prop_assert_eq!(buf.len(), (2 * raw.len() + 3).next_multiple_of(8));
    }

    /// The length the transform actually produces, against the mask form the reference spells it in.
    ///
    /// Driven through `build_buffer` rather than asserted as arithmetic: the earlier form compared
    /// two constant expressions and held by algebra alone, so it stayed green for any sizing the
    /// implementation might have used.
    #[test]
    fn buffer_length_matches_the_mask_form(
        raw in prop::collection::vec(any::<u8>(), 1..2000),
        time: u32,
    ) {
        let buf = build_buffer(&raw, raw[0], round_to_minute(time));
        // The reference sizes from the NUL-terminated hex expansion plus the two sum bytes.
        let hex_len = 2 * raw.len() + 1;
        prop_assert_eq!(buf.len(), (hex_len + 9) & !7);
    }

    /// `build_buffer` against a second model of the same transform, written from the reference's step
    /// order rather than the implementation's.
    ///
    /// The model reads the head word back out of the buffer where the implementation derives it from
    /// the values in hand, and counts the padding up front where the implementation makes it the loop
    /// bound. Those are exactly the two places the implementation departs from how the reference is
    /// written, and the earlier form asserted the first of them against a restatement of itself
    /// without ever calling the code.
    #[test]
    fn buffer_matches_an_independent_model(
        raw in prop::collection::vec(any::<u8>(), 1..300),
        time: u32,
    ) {
        let rounded = round_to_minute(time);
        prop_assert_eq!(build_buffer(&raw, raw[0], rounded), model_buffer(&raw, rounded));
    }

    /// Length accounting, against a chunking written the other way round.
    #[test]
    fn reported_length_excludes_the_separators(
        raw in prop::collection::vec(any::<u8>(), 1..600),
        time: u32,
    ) {
        let ticket = ObfuscatedTicket::from_auth_ticket(&raw, ServerTime(time))
            .map_err(|e| TestCaseError::fail(format!("{e}")))?;
        let separators = ticket.text().matches(',').count();
        prop_assert_eq!(ticket.text().len() - separators, ticket.length());
        prop_assert_eq!(separators, (ticket.length() - 1) / CHUNK);
        // Every character survives a query string unescaped.
        let query_safe = |b: u8| {
            b == b',' || b == b'*' || b.is_ascii_alphanumeric() || b == b'-' || b == b'_'
        };
        prop_assert!(ticket.text().bytes().all(query_safe));
    }
}

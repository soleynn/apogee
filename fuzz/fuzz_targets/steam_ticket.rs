#![no_main]

use libfuzzer_sys::fuzz_target;

use sqex_crypto::{CryptoError, ObfuscatedTicket, ServerTime};

/// The characters a ticket may put in a query string: the mangled base64 alphabet, its padding, and
/// the chunk separator.
fn query_safe(b: u8) -> bool {
    b == b',' || b == b'*' || b == b'-' || b == b'_' || b.is_ascii_alphanumeric()
}

// The ticket transform's sizing math is what this hunts. Arithmetic overflow is not denied
// workspace-wide, so an overflowing length computation compiles clean and surfaces only as a
// debug-build panic, which is what the fuzzer builds. The clock is carved out of the front of the
// input so all 2^32 readings are reachable, including the values below five where the launcher's
// subtraction wraps.
fuzz_target!(|data: &[u8]| {
    let (time, raw) = match data.split_at_checked(4) {
        Some((head, rest)) => (u32::from_le_bytes([head[0], head[1], head[2], head[3]]), rest),
        None => (0, data),
    };

    let ticket = match ObfuscatedTicket::from_auth_ticket(raw, ServerTime(time)) {
        Ok(t) => t,
        Err(e) => {
            // The empty ticket is the only refusal. A new failure path appearing here would mean the
            // transform diverges from the launcher on an input the launcher accepts.
            assert!(matches!(e, CryptoError::EmptyTicket), "unexpected error: {e}");
            assert!(raw.is_empty());
            return;
        }
    };

    // Separator accounting, derived from the input length rather than by counting commas in the
    // output, so the two cannot agree by both being wrong. The plaintext is the 16-bit sum, two hex
    // digits per byte and a terminator, rounded up to a cipher block; base64 expands that by 4/3.
    let plaintext = (2 * raw.len() + 3).next_multiple_of(8);
    let encoded = plaintext.div_ceil(3) * 4;
    let separators = (encoded - 1) / 300;

    assert_eq!(ticket.length(), encoded, "reported length");
    assert_eq!(ticket.text().len(), encoded + separators, "text length");
    assert_eq!(ticket.text().matches(',').count(), separators, "separators");
    assert!(ticket.length() <= ticket.text().len());
    assert_eq!(ticket.length() == ticket.text().len(), separators == 0);
    assert!(ticket.text().bytes().all(query_safe), "escaped in a query");
});

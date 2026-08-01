//! Lowercase-hex ASCII rendering, kept off the heap: every function here works on stack buffers so
//! a caller building a key or a ticket from secret material never lets the digits sit in an
//! un-zeroized `String`.

/// Lowercase hex digits, indexed by nibble.
pub const LOWER: &[u8; 16] = b"0123456789abcdef";

/// One byte as its two lowercase hex digits, high nibble first.
#[must_use]
pub const fn digits(b: u8) -> (u8, u8) {
    (LOWER[(b >> 4) as usize], LOWER[(b & 0x0F) as usize])
}

/// A `u32` as 8 lowercase hex ASCII bytes, most-significant nibble first. Byte-identical to
/// `format!("{v:08x}")` for every input.
#[must_use]
pub const fn u32_lower(v: u32) -> [u8; 8] {
    // Big-endian bytes rather than shift-and-cast: each byte comes out already narrowed, so there's
    // no lossy `as u8` truncation to justify. Routed through `bytes`, the crate's one endianness
    // home, rather than reaching for the stdlib conversion here directly.
    let bytes = crate::bytes::write_u32_be(v);
    let (h0, l0) = digits(bytes[0]);
    let (h1, l1) = digits(bytes[1]);
    let (h2, l2) = digits(bytes[2]);
    let (h3, l3) = digits(bytes[3]);
    [h0, l0, h1, l1, h2, l2, h3, l3]
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    /// Every slot, not just the ones a hand-picked input happens to select: a wrong digit in the
    /// tail of the table survives every vector whose bytes never reach that nibble.
    #[test]
    fn every_digit_is_pinned() {
        let derived: Vec<u8> = (b'0'..=b'9').chain(b'a'..=b'f').collect();
        assert_eq!(LOWER.as_slice(), derived.as_slice());
    }

    proptest! {
        #[test]
        fn u32_lower_matches_a_formatted_render(v: u32) {
            let rendered = u32_lower(v);
            let expected = format!("{v:08x}");
            prop_assert_eq!(rendered.as_slice(), expected.as_bytes());
        }
    }
}

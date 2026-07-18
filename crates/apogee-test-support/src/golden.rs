//! Char-for-char byte comparison for golden tests. The byte-identity bar wants a readable failure,
//! not a wall of raw slices, so a mismatch reports the first differing offset and both hex renders.

use std::fmt::Write as _;

/// Render bytes as lowercase, space-free hex.
#[must_use]
pub fn to_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        // `write!` to a String is infallible.
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// Decode lowercase- or uppercase-hex back to bytes, or `None` if the input is not an even-length
/// run of hex digits. The inverse of [`to_hex`].
#[must_use]
pub fn from_hex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    let bytes = s.as_bytes();
    for pair in bytes.chunks_exact(2) {
        let hi = (pair[0] as char).to_digit(16)?;
        let lo = (pair[1] as char).to_digit(16)?;
        out.push((hi * 16 + lo) as u8);
    }
    Some(out)
}

/// Byte offset of the first difference, or `None` when the slices are byte-identical (a length
/// difference reports at the first excess byte).
#[must_use]
pub fn first_diff(a: &[u8], b: &[u8]) -> Option<usize> {
    let common = a.len().min(b.len());
    for i in 0..common {
        if a[i] != b[i] {
            return Some(i);
        }
    }
    if a.len() == b.len() {
        None
    } else {
        Some(common)
    }
}

/// True when the two slices are byte-identical.
#[must_use]
pub fn bytes_match(a: &[u8], b: &[u8]) -> bool {
    first_diff(a, b).is_none()
}

/// Assert byte-identity, reporting the first differing offset and both hex renders on failure.
///
/// # Panics
/// Panics (fails the test) when `actual` and `expected` differ.
#[track_caller]
pub fn assert_golden_bytes(actual: &[u8], expected: &[u8]) {
    if let Some(off) = first_diff(actual, expected) {
        let msg = format!(
            "golden mismatch at offset {off}: actual {} byte(s), expected {} byte(s)",
            actual.len(),
            expected.len(),
        );
        // The hex renders differ here, so `assert_eq!` fails and prints both plus the offset note.
        assert_eq!(to_hex(actual), to_hex(expected), "{msg}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identical_slices_match() {
        assert!(bytes_match(b"abc", b"abc"));
        assert_eq!(first_diff(b"abc", b"abc"), None);
        assert_golden_bytes(b"abc", b"abc");
    }

    #[test]
    fn reports_first_difference() {
        assert_eq!(first_diff(b"abc", b"abd"), Some(2));
        assert_eq!(first_diff(b"ab", b"abc"), Some(2));
        assert!(!bytes_match(b"ab", b"abc"));
    }

    #[test]
    fn hex_is_zero_padded() {
        assert_eq!(to_hex(&[0x00, 0x0f, 0xa0, 0xff]), "000fa0ff");
    }

    #[test]
    fn from_hex_round_trips() {
        let bytes = [0x00, 0x0f, 0xa0, 0xff];
        assert_eq!(from_hex(&to_hex(&bytes)), Some(bytes.to_vec()));
        assert_eq!(from_hex("000FA0FF"), Some(bytes.to_vec()));
        assert_eq!(from_hex(""), Some(vec![]));
    }

    #[test]
    fn from_hex_rejects_malformed() {
        assert_eq!(from_hex("abc"), None); // odd length
        assert_eq!(from_hex("zz"), None); // non-hex digits
    }
}

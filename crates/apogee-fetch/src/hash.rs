//! Whole-file digest pins a download can be verified against, and the running hash behind each one.
//!
//! SHA256 and BLAKE3 are both 32 bytes wide, so a digest's bytes alone don't say which function
//! produced them: a [`DigestPin`] carries its algorithm, and this module is the only place that turns
//! one into a [`FileHasher`]. Both engines verify through it, so neither can decide on its own what a
//! pin means.

use sha2::{Digest as _, Sha256};

/// A whole-file digest together with the hash function that produced it.
///
/// The shape a signed manifest's artifact pin takes once parsed. Two functions are accepted so a
/// catalog stays readable while being re-signed onto the newer one; the algorithm travels with the
/// pin rather than being inferred, since both digests are the same width and a wrong guess would
/// verify a file against the wrong function.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum DigestPin {
    /// A SHA256 digest: the function the pre-BLAKE3 catalogs pinned under.
    Sha256([u8; 32]),
    /// A BLAKE3 digest: what our own signed manifests pin under today.
    Blake3([u8; 32]),
}

/// The hex spellings one manifest row may carry, one field per function.
///
/// A struct rather than two positional `&str` parameters: the two are the same type, so a swapped
/// pair would compile and mint a pin under the wrong function, the exact hazard [`DigestPin`] exists
/// to prevent. The field names are the row's key names, so a call site reads as the row does.
#[derive(Debug, Clone, Copy, Default)]
pub struct HexPins<'a> {
    /// The row's BLAKE3 spelling, when present; preferred when both are.
    pub blake3: Option<&'a str>,
    /// The row's SHA256 spelling, when present.
    pub sha256: Option<&'a str>,
}

impl DigestPin {
    /// Decode a manifest row's pin from the hex spellings it may carry, preferring BLAKE3 when both
    /// are present so every build that understands both functions verifies one artifact the same way.
    ///
    /// Returns `None` when the spelling it selected does not decode; a malformed BLAKE3 pin never
    /// falls through to a well-formed SHA256 one beside it.
    ///
    /// # Examples
    ///
    /// ```
    /// use apogee_fetch::{DigestPin, HexPins};
    ///
    /// let hex = "ab".repeat(32);
    /// let pin = DigestPin::from_hex(HexPins { blake3: Some(&hex), sha256: None });
    /// assert!(matches!(pin, Some(DigestPin::Blake3(_))));
    /// ```
    #[must_use]
    pub fn from_hex(pins: HexPins<'_>) -> Option<Self> {
        if let Some(hex) = pins.blake3 {
            return decode_hex(hex).map(Self::Blake3);
        }
        decode_hex(pins.sha256?).map(Self::Sha256)
    }

    /// The expected digest bytes, whichever function they came from.
    #[must_use]
    pub fn bytes(&self) -> [u8; 32] {
        match self {
            Self::Sha256(digest) | Self::Blake3(digest) => *digest,
        }
    }

    /// A fresh running hash in this pin's algorithm.
    pub(crate) fn hasher(&self) -> FileHasher {
        match self {
            Self::Sha256(_) => FileHasher::Sha256(Sha256::new()),
            Self::Blake3(_) => FileHasher::Blake3(Box::new(blake3::Hasher::new())),
        }
    }
}

/// A running whole-file hash, in whichever function the download's pin named.
///
/// The BLAKE3 state is boxed: unboxed, its much larger chaining-value stack would widen every value
/// of this type, one per in-flight transfer, to match it.
pub(crate) enum FileHasher {
    Sha256(Sha256),
    // ~55 chaining values deep and more than an order of magnitude larger than a Sha256 state.
    Blake3(Box<blake3::Hasher>),
}

impl FileHasher {
    pub(crate) fn update(&mut self, bytes: &[u8]) {
        match self {
            Self::Sha256(h) => h.update(bytes),
            Self::Blake3(h) => {
                h.update(bytes);
            }
        }
    }

    /// Discard everything hashed so far, for a transfer that restarted from zero.
    pub(crate) fn reset(&mut self) {
        match self {
            Self::Sha256(h) => *h = Sha256::new(),
            Self::Blake3(h) => {
                h.reset();
            }
        }
    }

    pub(crate) fn finalize(self) -> [u8; 32] {
        match self {
            Self::Sha256(h) => h.finalize().into(),
            Self::Blake3(h) => *h.finalize().as_bytes(),
        }
    }
}

/// Decode exactly 64 hex digits into 32 bytes; any other length or a non-hex digit is `None`.
fn decode_hex(s: &str) -> Option<[u8; 32]> {
    let bytes = s.as_bytes();
    if bytes.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, slot) in out.iter_mut().enumerate() {
        let hi = hex_val(bytes[2 * i])?;
        let lo = hex_val(bytes[2 * i + 1])?;
        *slot = (hi << 4) | lo;
    }
    Some(out)
}

fn hex_val(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: &str = "0000000000000000000000000000000000000000000000000000000000000001";
    const B: &str = "0000000000000000000000000000000000000000000000000000000000000002";

    /// Reading a mixed row as BLAKE3 is what keeps two builds that both understand it from verifying
    /// the same artifact differently.
    #[test]
    fn a_row_carrying_both_pins_is_read_as_blake3() {
        let pin = DigestPin::from_hex(HexPins {
            blake3: Some(A),
            sha256: Some(B),
        })
        .expect("decodes");
        assert!(matches!(pin, DigestPin::Blake3(_)));
        assert_eq!(pin.bytes()[31], 1);
    }

    /// Accepting either spelling alone is what lets a catalog be re-signed one row at a time.
    #[test]
    fn either_pin_alone_is_accepted_and_keeps_its_function() {
        assert!(matches!(
            DigestPin::from_hex(HexPins {
                blake3: Some(A),
                sha256: None
            }),
            Some(DigestPin::Blake3(_))
        ));
        assert!(matches!(
            DigestPin::from_hex(HexPins {
                blake3: None,
                sha256: Some(A)
            }),
            Some(DigestPin::Sha256(_))
        ));
        assert_eq!(DigestPin::from_hex(HexPins::default()), None);
    }

    /// A malformed BLAKE3 pin does not fall through to a well-formed SHA256 one beside it: the row
    /// named a function, and falling through would verify against a digest the publisher didn't
    /// intend.
    #[test]
    fn a_bad_blake3_pin_does_not_fall_through_to_a_good_sha256_one() {
        assert_eq!(
            DigestPin::from_hex(HexPins {
                blake3: Some("not-hex"),
                sha256: Some(A)
            }),
            None
        );
    }

    /// Exercises both decoder checks, length and digit validity: right-length wrong-character input
    /// is the case that would otherwise silently decode to wrong bytes.
    #[test]
    fn a_pin_must_be_64_hex_digits() {
        for bad in ["", "ab", &A[..63], &format!("{A}0"), &"g".repeat(64)] {
            assert_eq!(decode_hex(bad), None, "{bad:?} should not decode");
        }
        assert_eq!(decode_hex(&A.to_uppercase()), decode_hex(A));
    }

    /// Both hashers match their reference implementations over a multi-chunk input, and a reset
    /// leaves one indistinguishable from fresh.
    #[test]
    fn each_hasher_matches_its_reference_and_survives_a_reset() {
        // Past BLAKE3's 1 KiB chunk boundary, so the chaining-value stack is exercised.
        let payload = vec![0xa5u8; 5000];
        for pin in [DigestPin::Sha256([0; 32]), DigestPin::Blake3([0; 32])] {
            let mut hasher = pin.hasher();
            hasher.update(b"discarded");
            hasher.reset();
            hasher.update(&payload[..1000]);
            hasher.update(&payload[1000..]);
            let got = hasher.finalize();

            let want: [u8; 32] = match pin {
                DigestPin::Sha256(_) => Sha256::digest(&payload).into(),
                DigestPin::Blake3(_) => *blake3::hash(&payload).as_bytes(),
            };
            assert_eq!(got, want);
        }
    }
}

//! The whole-file digests a download can be pinned to, and the running hash behind each one.
//!
//! SHA256 and BLAKE3 are both 32 bytes wide, so a digest's bytes never say which function produced
//! them. A pin therefore carries its algorithm, and this module is the single place that turns one
//! into a hasher: both engines verify through it, so neither can decide on its own what a pin means.

use sha2::{Digest as _, Sha256};

/// A whole-file digest together with the hash that produced it.
///
/// This is the shape a signed manifest's artifact pin takes once parsed. Two functions are accepted
/// so a hosted catalog stays readable while it is being re-signed onto the newer one; which of them
/// a row named travels with the pin rather than being inferred, because the widths are equal and a
/// wrong guess would verify a file against the wrong function and reject good bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum DigestPin {
    /// A SHA256 digest, the function the pre-BLAKE3 catalogs pinned under.
    Sha256([u8; 32]),
    /// A BLAKE3 digest, what our own signed manifests pin under today.
    Blake3([u8; 32]),
}

/// The hex spellings one manifest row may carry, one field per function. A struct rather than two
/// positional `Option<&str>` parameters because the two are the same type: a swapped pair would
/// compile and mint a pin under the wrong function, which is the exact hazard [`DigestPin`] exists
/// to prevent. The field names are the row's key names, so a call site reads as the row does.
#[derive(Debug, Clone, Copy, Default)]
pub struct HexPins<'a> {
    /// The row's BLAKE3 spelling, when present. Preferred when both are.
    pub blake3: Option<&'a str>,
    /// The row's SHA256 spelling, when present.
    pub sha256: Option<&'a str>,
}

impl DigestPin {
    /// Decode a manifest row's pin from the hex spellings it may carry, **preferring BLAKE3** when a
    /// row publishes both. `None` is a row that pins nothing decodable, which every catalog parser
    /// turns into its own bad-pin error.
    ///
    /// The preference is what makes a mixed catalog behave: a row can carry the older digest for
    /// builds that predate the newer one and the newer one for builds that have it, and every build
    /// that understands both takes the same arm, so two clients never verify one artifact differently.
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
/// The BLAKE3 state is boxed: it carries a 55-deep stack of chaining values and is more than an
/// order of magnitude larger than a SHA256 state, and an inline variant would widen every value of
/// this type (one per in-flight transfer) to the larger of the two.
pub(crate) enum FileHasher {
    Sha256(Sha256),
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

    /// The transition rule: a row that carries both is read as the newer function, so every build
    /// that understands both verifies one artifact the same way.
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

    /// Either spelling on its own is accepted, so a catalog can be re-signed one row at a time.
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

    /// A malformed BLAKE3 pin is not silently answered by a well-formed SHA256 one beside it: the
    /// row named a function, and falling through would verify against a digest the publisher did not
    /// intend for that build.
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

    /// Both halves of the decoder: the length, and the digits. A pin of the right length made of
    /// wrong characters is the one that would otherwise decode to silently wrong bytes.
    #[test]
    fn a_pin_must_be_64_hex_digits() {
        for bad in ["", "ab", &A[..63], &format!("{A}0"), &"g".repeat(64)] {
            assert_eq!(decode_hex(bad), None, "{bad:?} should not decode");
        }
        assert_eq!(decode_hex(&A.to_uppercase()), decode_hex(A));
    }

    /// The two hashers agree with their reference implementations over a multi-chunk input, and a
    /// reset leaves a hasher indistinguishable from a fresh one (the restart-from-zero path).
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

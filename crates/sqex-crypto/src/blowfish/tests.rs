//! Blowfish goldens: published vectors for the standard cipher, and pinned snapshots for the
//! launcher variant's signed-key schedule and little-endian blocks.

use apogee_test_support::golden::{assert_golden_bytes, to_hex};
use proptest::prelude::*;
use rstest::rstest;

use super::{Blowfish, LegacyBlowfish, pad8};

/// ASCII-hex key: every byte < 0x80, so the launcher variant's signed folding is dormant.
const LOW_KEY: &[u8] = b"1a2b3c4d";
/// Contains bytes >= 0x80, so the signed folding diverges from textbook Blowfish.
const HIGH_KEY: &[u8] = &[0x80, 0x81, 0xff, 0x00, 0x7f, 0x90, 0xab, 0xcd];
const PLAINTEXT: &[u8] = b"apogee!!";

/// Published Blowfish ECB test vectors (Eric Young's `bftest`, universally republished).
#[rstest]
#[case([0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
       [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
       [0x4e, 0xf9, 0x97, 0x45, 0x61, 0x98, 0xdd, 0x78])]
#[case([0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
       [0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
       [0x51, 0x86, 0x6f, 0xd5, 0xb8, 0x5e, 0xcb, 0x8a])]
#[case([0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef],
       [0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11],
       [0x61, 0xf9, 0xc3, 0x80, 0x22, 0x81, 0xb0, 0x96])]
#[case([0x7c, 0xa1, 0x10, 0x45, 0x4a, 0x1a, 0x6e, 0x57],
       [0x01, 0xa1, 0xd6, 0xd0, 0x39, 0x77, 0x67, 0x42],
       [0x59, 0xc6, 0x82, 0x45, 0xeb, 0x05, 0x28, 0x2b])]
#[case([0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10],
       [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef],
       [0x0a, 0xce, 0xab, 0x0f, 0xc6, 0xa0, 0xa2, 0x8d])]
fn standard_blowfish_published_vectors(
    #[case] key: [u8; 8],
    #[case] plaintext: [u8; 8],
    #[case] ciphertext: [u8; 8],
) {
    let cipher = Blowfish::new(&key);
    assert_golden_bytes(&cipher.encrypt(&plaintext), &ciphertext);
    assert_golden_bytes(&cipher.decrypt(&ciphertext), &plaintext);
}

#[test]
fn legacy_schedule_state_low_byte_key() {
    let cipher = LegacyBlowfish::new(LOW_KEY);
    insta::assert_snapshot!("legacy_schedule_low_byte", cipher.state_dump());
}

#[test]
fn legacy_schedule_state_high_byte_key() {
    let cipher = LegacyBlowfish::new(HIGH_KEY);
    insta::assert_snapshot!("legacy_schedule_high_byte", cipher.state_dump());
}

#[test]
fn legacy_ciphertext_high_byte_key() {
    let ct = LegacyBlowfish::new(HIGH_KEY).encrypt(PLAINTEXT);
    insta::assert_snapshot!("legacy_ciphertext_high_byte", to_hex(&ct));
}

/// The signed-byte schedule agrees with textbook Blowfish for low bytes and diverges for high ones.
#[test]
fn signed_key_schedule_diverges_only_on_high_bytes() {
    assert_eq!(
        LegacyBlowfish::new(LOW_KEY).state_dump(),
        Blowfish::new(LOW_KEY).state_dump(),
        "low-byte keys must schedule identically to textbook Blowfish",
    );
    assert_ne!(
        LegacyBlowfish::new(HIGH_KEY).state_dump(),
        Blowfish::new(HIGH_KEY).state_dump(),
        "high-byte keys must diverge (the reproduced SE bug)",
    );
}

/// With an identical (low-byte) key schedule, the only difference between the two variants is block
/// endianness: launcher = little-endian, standard = big-endian.
#[test]
fn block_endianness_split_is_pinned() {
    let le = LegacyBlowfish::new(LOW_KEY).encrypt(PLAINTEXT);
    let be = Blowfish::new(LOW_KEY).encrypt(PLAINTEXT);
    assert_ne!(le, be, "the LE/BE block split must be observable");
    insta::assert_snapshot!("legacy_le_block", to_hex(&le));
    insta::assert_snapshot!("standard_be_block", to_hex(&be));
}

proptest! {
    #[test]
    fn legacy_round_trips(
        key in prop::collection::vec(any::<u8>(), 1..24),
        data in prop::collection::vec(any::<u8>(), 0..48),
    ) {
        let cipher = LegacyBlowfish::new(&key);
        let restored = cipher.decrypt(&cipher.encrypt(&data));
        prop_assert_eq!(restored, pad8(&data));
    }

    #[test]
    fn standard_round_trips(
        key in prop::collection::vec(any::<u8>(), 1..24),
        data in prop::collection::vec(any::<u8>(), 0..48),
    ) {
        let cipher = Blowfish::new(&key);
        let restored = cipher.decrypt(&cipher.encrypt(&data));
        prop_assert_eq!(restored, pad8(&data));
    }
}

//! Argument-builder goldens and the byte-level serialization pins.
//!
//! The encrypted output rides on the already-golden `LegacyBlowfish` and `sqex_base64` primitives, so
//! these tests pin the new logic: escaping, checksum indexing, `T` insertion, and the exact serialized
//! plaintext (recovered by decrypting, so it is human-reviewable in the snapshot).

use proptest::prelude::*;

use super::{ArgKey, ArgumentBuilder, TickCount, derive_checksum, push_escaped};
use crate::{LegacyBlowfish, sqex_base64};

/// The old allocating escaper, expressed over the in-place `push_escaped`, kept so the escaping
/// rules stay directly unit-tested.
fn escape(s: &str) -> String {
    let mut out = String::new();
    push_escaped(&mut out, s);
    out
}

/// A deterministic `ArgKey` for goldens, composed through the `TickCount` seam.
fn arg_key(raw: u32) -> ArgKey {
    ArgKey::from_tick(TickCount::from_raw(raw))
}

/// A fixed, obviously-synthetic argument set in the launcher's order. No SE bytes.
fn fixed_builder() -> ArgumentBuilder {
    ArgumentBuilder::new()
        .add("DEV.DataPathType", "1")
        .add("DEV.MaxEntitledExpansionID", "4")
        .add("DEV.TestSID", "0123456789abcdef")
        .add("DEV.UseSqPack", "1")
        .add("SYS.Region", "0")
        .add("language", "1")
        .add("resetConfig", "0")
        .add("ver", "2000.00.00.0000.0000")
}

/// The serialized plaintext `fixed_builder` + `arg_key(0x1234_5678)` encrypts. `0x1234_5678`
/// is 305419896 decimal; every quirk (leading space, `/`, space before `=`) is visible here.
const FIXED_PLAINTEXT: &str = " /T =305419896 /DEV.DataPathType =1 /DEV.MaxEntitledExpansionID =4 /DEV.TestSID =0123456789abcdef /DEV.UseSqPack =1 /SYS.Region =0 /language =1 /resetConfig =0 /ver =2000.00.00.0000.0000";

/// Recover the serialized plaintext from an `sqex0003` string by decrypting its body.
fn decrypt_to_string(s: &str, key: &ArgKey) -> String {
    let inner = s
        .strip_prefix("//**sqex0003")
        .and_then(|r| r.strip_suffix("**//"))
        .unwrap();
    let (body, _checksum) = inner.split_at(inner.len() - 1);
    let ciphertext = sqex_base64::decode(body).unwrap();
    let plaintext = LegacyBlowfish::new(&key.key_bytes()).decrypt(&ciphertext);
    String::from_utf8(plaintext)
        .unwrap()
        .trim_end_matches('\0')
        .to_string()
}

#[test]
fn escape_doubles_spaces() {
    assert_eq!(escape("nospace"), "nospace");
    assert_eq!(escape("a b"), "a  b");
    assert_eq!(escape("a  b"), "a    b");
    assert_eq!(escape(" lead"), "  lead");
}

#[test]
fn checksum_indexes_one_nibble() {
    assert_eq!(derive_checksum(0x0000_0000), 'f');
    assert_eq!(derive_checksum(0x0004_0000), 'G');
    assert_eq!(derive_checksum(0x000F_0000), 'L');
    // Only bits 16-19 select the char.
    assert_eq!(derive_checksum(0x1234_0000), 'G');
}

#[test]
fn key_is_high_half_as_ascii_hex() {
    let key = arg_key(0x1234_5678);
    assert_eq!(key.key(), 0x1234_0000);
    assert_eq!(&key.key_bytes(), b"12340000");
    assert_eq!(key.ticks(), 0x1234_5678);
}

#[test]
fn from_tick_derives_key_and_ticks() {
    let key = ArgKey::from_tick(TickCount::from_raw(0x1234_5678));
    assert_eq!(key.ticks(), 0x1234_5678);
    assert_eq!(key.key(), 0x1234_0000);
}

#[test]
fn t_is_prepended_from_the_key() {
    let key = arg_key(0x1234_5678);
    let s = ArgumentBuilder::new().add("a", "b").build_encrypted(&key);
    assert_eq!(decrypt_to_string(&s, &key), " /T =305419896 /a =b");
}

#[test]
fn explicit_t_is_overwritten_not_duplicated() {
    let key = arg_key(0x1234_5678);
    let s = ArgumentBuilder::new()
        .add("T", "999")
        .add("a", "b")
        .build_encrypted(&key);
    // The caller's "999" is gone; a single key-derived T leads.
    assert_eq!(decrypt_to_string(&s, &key), " /T =305419896 /a =b");
}

#[test]
fn build_plain_has_no_slash_no_escape_no_t() {
    let plain = ArgumentBuilder::new()
        .add("DEV.UseSqPack", "1")
        .add("extra", "a b")
        .build_plain();
    assert_eq!(plain, " DEV.UseSqPack=1 extra=a b");
}

#[test]
fn decrypt_round_trip_matches_serialized_plaintext() {
    let key = arg_key(0x1234_5678);
    let s = fixed_builder().build_encrypted(&key);

    let inner = s
        .strip_prefix("//**sqex0003")
        .and_then(|r| r.strip_suffix("**//"))
        .unwrap();
    let (body, checksum) = inner.split_at(inner.len() - 1);
    assert_eq!(checksum, "G");

    let ciphertext = sqex_base64::decode(body).unwrap();
    let plaintext = LegacyBlowfish::new(&key.key_bytes()).decrypt(&ciphertext);

    let mut expected = FIXED_PLAINTEXT.as_bytes().to_vec();
    expected.resize(FIXED_PLAINTEXT.len().next_multiple_of(8), 0);
    assert_eq!(plaintext, expected);
}

/// Human-reviewable pin of the serialized plaintext, including doubled spaces in a value.
#[test]
fn plaintext_serialization_pinned() {
    let key = arg_key(0x00AB_CDEF);
    let s = ArgumentBuilder::new()
        .add("DEV.UseSqPack", "1")
        .add("extra", "a b c")
        .build_encrypted(&key);
    insta::assert_snapshot!("plaintext_serialization", decrypt_to_string(&s, &key));
}

/// The headline byte-identity golden: the `sqex0003` argument string for a fixed key and argument
/// set, pinned so any drift in the codec is caught.
#[test]
fn sqex0003_fixed_args_pinned() {
    let key = arg_key(0x1234_5678);
    insta::assert_snapshot!("sqex0003_fixed_args", fixed_builder().build_encrypted(&key));
}

proptest! {
    #[test]
    fn escape_is_reversible(s in "[a ]{0,40}") {
        // escape only ever produces even-length space runs, so halving recovers the original.
        let unescaped = escape(&s).replace("  ", " ");
        prop_assert_eq!(unescaped, s);
    }
}

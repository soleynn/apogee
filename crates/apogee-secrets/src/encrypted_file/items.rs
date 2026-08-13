//! The record table: what the store holds, laid out as the bytes that get sealed.
//!
//! The table is inside the seal, so nothing here is reached by an attacker who has not already
//! produced the key. It is still written as if it were: the caps below bound every allocation, and
//! the decoder is the second of the two entry points the fuzz workspace drives. What the strictness
//! actually buys is that the encoder's canonical form is machine-checked, so an unchanged store
//! re-encodes to identical bytes.

use std::collections::BTreeMap;

use uuid::Uuid;
use zeroize::Zeroizing;

use super::frame::{BUCKET, MAX_FILE, OVERHEAD, corrupt};
use crate::{SecretKind, SecretsError};

/// The most records one store may hold. Far above a realistic account list, and low enough that the
/// count read off the front of the table cannot drive a large reservation on its own.
const MAX_ITEMS: u32 = 4096;

/// The longest one stored value may be.
const MAX_VALUE: u32 = 64 << 10;

const COUNT_LEN: usize = 4;
const ACCOUNT_LEN: usize = 16;
const KIND_LEN: usize = 1;
const VALUE_LEN_LEN: usize = 4;
const RECORD_HEAD: usize = ACCOUNT_LEN + KIND_LEN + VALUE_LEN_LEN;

/// What one stored value is filed under: the account, and which secret of that account's it is.
///
/// The kind travels as a raw byte rather than as a [`SecretKind`], which is what lets a build meet a
/// tag it does not know and put it back where it found it.
pub(crate) type Key = ([u8; ACCOUNT_LEN], u8);

/// Every secret the store holds, in memory.
///
/// A `BTreeMap` because its iteration order *is* the canonical order the table is written in, so the
/// encoder has no sort step that could be forgotten.
pub(crate) type Table = BTreeMap<Key, Zeroizing<Vec<u8>>>;

/// The tag a kind is filed under in this format.
///
/// Deliberately not [`SecretKind::slug`]: the slug is the platform credential store's on-disk
/// contract, and folding the two together would make a rename over there an unannounced break in
/// this file.
pub(crate) const fn tag_of(kind: SecretKind) -> u8 {
    match kind {
        SecretKind::Password => 1,
        SecretKind::TotpSecret => 2,
    }
}

/// The key one account's kind is filed under.
pub(crate) fn key_for(account: Uuid, kind: SecretKind) -> Key {
    (*account.as_bytes(), tag_of(kind))
}

/// Lay the table out and pad it to a whole number of buckets.
///
/// # Errors
/// [`SecretsError::Backend`] if the result would be larger than a file this build can read back. A
/// write that produced an unreadable file would be a store that silently ate the secret it was given.
pub(crate) fn encode(table: &Table) -> Result<Zeroizing<Vec<u8>>, SecretsError> {
    let step = "lay out the secret store";
    let count = u32::try_from(table.len()).map_err(|_| SecretsError::Backend { step })?;
    if count > MAX_ITEMS {
        return Err(SecretsError::Backend { step });
    }

    let mut body = COUNT_LEN;
    for value in table.values() {
        let len = u32::try_from(value.len()).map_err(|_| SecretsError::Backend { step })?;
        if len > MAX_VALUE {
            return Err(SecretsError::Backend { step });
        }
        body = body
            .checked_add(RECORD_HEAD + value.len())
            .ok_or(SecretsError::Backend { step })?;
    }
    let padded = body.next_multiple_of(BUCKET).max(BUCKET);
    if (padded + OVERHEAD) as u64 > MAX_FILE {
        return Err(SecretsError::Backend { step });
    }

    let mut out = Zeroizing::new(vec![0u8; padded]);
    out[..COUNT_LEN].copy_from_slice(&count.to_be_bytes());
    let mut at = COUNT_LEN;
    for ((account, kind), value) in table {
        out[at..at + ACCOUNT_LEN].copy_from_slice(account);
        at += ACCOUNT_LEN;
        out[at] = *kind;
        at += KIND_LEN;
        // Re-checked rather than carried over from the sizing pass above: a fallible conversion given
        // a default would write a length that does not match the bytes that follow it, and the file
        // would seal and then never decode.
        let len = u32::try_from(value.len()).map_err(|_| SecretsError::Backend { step })?;
        out[at..at + VALUE_LEN_LEN].copy_from_slice(&len.to_be_bytes());
        at += VALUE_LEN_LEN;
        out[at..at + value.len()].copy_from_slice(value);
        at += value.len();
    }
    // The tail is already zero: the buffer was allocated zeroed and nothing wrote past `at`. Stated
    // rather than assumed, because the decoder refuses a nonzero tail and the two have to agree.
    debug_assert!(out[at..].iter().all(|b| *b == 0));
    Ok(out)
}

/// Read a table back.
///
/// Requires strictly ascending keys and a zero tail. Neither is reachable by an attacker, since this
/// runs on plaintext the seal already authenticated; what they buy is that the encoder above has
/// exactly one legal output for a given store, which is what makes an unchanged store rewrite to
/// identical bytes.
///
/// # Errors
/// [`SecretsError::Corrupt`] with detail `"record table"` if the length, key ordering, or tail does
/// not hold up.
pub(crate) fn decode(bytes: &[u8]) -> Result<Table, SecretsError> {
    // A function rather than a value: the condition is not `Clone`, deliberately, and every rejection
    // below is the same one.
    let bad = || corrupt("record table");
    if bytes.len() < BUCKET || !bytes.len().is_multiple_of(BUCKET) {
        return Err(bad());
    }
    let count = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    if count > MAX_ITEMS {
        return Err(bad());
    }

    let mut table = Table::new();
    let mut at = COUNT_LEN;
    let mut previous: Option<Key> = None;
    for _ in 0..count {
        let head = bytes.get(at..at + RECORD_HEAD).ok_or_else(bad)?;
        let mut account = [0u8; ACCOUNT_LEN];
        account.copy_from_slice(&head[..ACCOUNT_LEN]);
        let kind = head[ACCOUNT_LEN];
        let len = u32::from_be_bytes([
            head[ACCOUNT_LEN + 1],
            head[ACCOUNT_LEN + 2],
            head[ACCOUNT_LEN + 3],
            head[ACCOUNT_LEN + 4],
        ]);
        if len > MAX_VALUE {
            return Err(bad());
        }
        at += RECORD_HEAD;
        let value = bytes.get(at..at + len as usize).ok_or_else(bad)?;
        at += len as usize;

        let key = (account, kind);
        if previous.is_some_and(|last| last >= key) {
            return Err(bad());
        }
        previous = Some(key);
        table.insert(key, Zeroizing::new(value.to_vec()));
    }

    if bytes[at..].iter().any(|b| *b != 0) {
        return Err(bad());
    }
    Ok(table)
}

#[cfg(test)]
mod tests {
    use super::*;

    const ACCOUNT: Uuid = Uuid::from_u128(0x0194_8f2c_7d3e_4a51_9b60_c2e8_1f45_a903);
    const OTHER: Uuid = Uuid::from_u128(2);

    fn table(entries: &[(Uuid, u8, &[u8])]) -> Table {
        entries
            .iter()
            .map(|(account, kind, value)| {
                ((*account.as_bytes(), *kind), Zeroizing::new(value.to_vec()))
            })
            .collect()
    }

    /// The tags are half of every stored key. A change to one orphans every secret filed under it,
    /// with no error at the point of the change. The wildcard-free match is what makes a new kind
    /// stop this compiling until it has been given a tag on purpose.
    #[test]
    fn kind_tags_are_frozen() {
        #[allow(dead_code)]
        fn every_variant_has_an_entry(kind: SecretKind) {
            match kind {
                SecretKind::Password => (),
                SecretKind::TotpSecret => (),
            }
        }

        assert_eq!(tag_of(SecretKind::Password), 1);
        assert_eq!(tag_of(SecretKind::TotpSecret), 2);
        let tags: Vec<u8> = SecretKind::ALL.into_iter().map(tag_of).collect();
        let mut unique = tags.clone();
        unique.sort_unstable();
        unique.dedup();
        assert_eq!(unique.len(), tags.len(), "two kinds share one tag");
    }

    #[test]
    fn a_table_round_trips() {
        let original = table(&[
            (ACCOUNT, 1, b"hunter2"),
            (ACCOUNT, 2, b"JBSWY3DPEHPK3PXP"),
            (OTHER, 1, b""),
        ]);
        let encoded = encode(&original).expect("encode");
        assert_eq!(decode(&encoded).expect("decode"), original);
    }

    /// An unchanged store has to re-encode to identical bytes, or every read would look like a write
    /// to anything watching the file. A map is what guarantees it, and this is the assertion that
    /// keeps a later switch to an insertion-ordered container from quietly breaking it.
    #[test]
    fn the_encoding_does_not_depend_on_the_order_items_arrived_in() {
        let forwards = table(&[(ACCOUNT, 1, b"a"), (ACCOUNT, 2, b"b"), (OTHER, 1, b"c")]);
        let backwards = table(&[(OTHER, 1, b"c"), (ACCOUNT, 2, b"b"), (ACCOUNT, 1, b"a")]);
        assert_eq!(
            *encode(&forwards).expect("a"),
            *encode(&backwards).expect("b")
        );
    }

    /// The claim the padding exists to make: the file's length says nothing about how much is in it.
    #[test]
    fn an_empty_table_and_a_full_one_are_the_same_size() {
        let empty = encode(&Table::new()).expect("empty");
        let full = encode(&table(&[
            (ACCOUNT, 1, b"a long enough password to be typical"),
            (ACCOUNT, 2, b"JBSWY3DPEHPK3PXP"),
            (OTHER, 1, b"another account's password"),
            (OTHER, 2, b"JBSWY3DPEHPK3PXQ"),
        ]))
        .expect("full");
        assert_eq!(empty.len(), BUCKET);
        assert_eq!(empty.len(), full.len());
    }

    #[test]
    fn a_nonzero_tail_is_refused() {
        let mut encoded = encode(&table(&[(ACCOUNT, 1, b"pw")])).expect("encode");
        let last = encoded.len() - 1;
        encoded[last] = 1;
        assert!(decode(&encoded).is_err());
    }

    /// Repeated or descending keys are the two ways a table can hold the same slot twice, and a
    /// decoder that took the last one would silently drop a secret.
    #[test]
    fn records_out_of_order_or_repeated_are_refused() {
        let mut encoded =
            encode(&table(&[(ACCOUNT, 1, b"a"), (ACCOUNT, 2, b"b")])).expect("encode");
        // Rewrite the second record's kind tag to match the first, which makes the pair equal.
        let second = COUNT_LEN + RECORD_HEAD + 1 + ACCOUNT_LEN;
        encoded[second] = 1;
        assert!(decode(&encoded).is_err());
        // And to a tag below the first, which makes the pair descending.
        encoded[second] = 0;
        assert!(decode(&encoded).is_err());
    }

    /// Downgrading the launcher must not destroy a secret a newer build wrote. The map is keyed on
    /// the raw tag, so a record this build has no name for is carried through untouched.
    #[test]
    fn a_tag_this_build_does_not_know_survives_a_decode_and_re_encode() {
        let unknown = 200;
        assert!(!SecretKind::ALL.iter().any(|k| tag_of(*k) == unknown));
        let original = table(&[
            (ACCOUNT, 1, b"pw"),
            (ACCOUNT, unknown, b"from a later build"),
        ]);
        let once = encode(&original).expect("encode");
        let read_back = decode(&once).expect("decode");
        assert_eq!(read_back, original);
        assert_eq!(*encode(&read_back).expect("re-encode"), *once);
    }

    #[test]
    fn a_value_longer_than_the_cap_is_refused_both_ways() {
        let too_long = vec![0u8; MAX_VALUE as usize + 1];
        assert!(encode(&table(&[(ACCOUNT, 1, &too_long)])).is_err());

        let mut encoded = encode(&table(&[(ACCOUNT, 1, b"pw")])).expect("encode");
        encoded[COUNT_LEN + ACCOUNT_LEN + KIND_LEN..COUNT_LEN + RECORD_HEAD]
            .copy_from_slice(&(MAX_VALUE + 1).to_be_bytes());
        assert!(decode(&encoded).is_err());
    }

    /// A count that outruns the buffer must be refused rather than reserving for what it claims.
    #[test]
    fn a_count_larger_than_the_table_is_refused() {
        let mut encoded = encode(&Table::new()).expect("encode");
        encoded[..COUNT_LEN].copy_from_slice(&MAX_ITEMS.to_be_bytes());
        assert!(decode(&encoded).is_err());
        encoded[..COUNT_LEN].copy_from_slice(&u32::MAX.to_be_bytes());
        assert!(decode(&encoded).is_err());
    }

    /// Both caps, on a table long enough that the cap is what refuses.
    ///
    /// The two cases above declare an outsized count or length inside a single 512-byte bucket,
    /// where `bytes.get(..)` runs out first and refuses for a reason that has nothing to do with
    /// either cap: delete one and they stay green. What each cap is for is bounding the work a
    /// declared size can ask for, so each is checked here on a table where the declared size fits.
    #[test]
    fn the_caps_refuse_before_the_buffer_does() {
        let mut buf = vec![0u8; 66_048];
        buf[..COUNT_LEN].copy_from_slice(&1u32.to_be_bytes());
        let len_at = COUNT_LEN + ACCOUNT_LEN + KIND_LEN;
        buf[len_at..len_at + VALUE_LEN_LEN].copy_from_slice(&(MAX_VALUE + 1).to_be_bytes());
        assert!(
            decode(&buf).is_err(),
            "a value one past the cap fits this table and was accepted"
        );

        let mut buf = vec![0u8; 86_528];
        buf[..COUNT_LEN].copy_from_slice(&(MAX_ITEMS + 1).to_be_bytes());
        for account in 0..=u128::from(MAX_ITEMS) {
            let at = COUNT_LEN + (account as usize) * RECORD_HEAD;
            buf[at..at + ACCOUNT_LEN].copy_from_slice(&account.to_be_bytes());
            buf[at + ACCOUNT_LEN] = 1;
        }
        assert!(
            decode(&buf).is_err(),
            "a count one past the cap fits this table and was accepted"
        );
    }

    #[test]
    fn bytes_that_are_not_a_whole_number_of_buckets_are_refused() {
        assert!(decode(&[]).is_err());
        assert!(decode(&[0u8; BUCKET - 1]).is_err());
        assert!(decode(&[0u8; BUCKET + 1]).is_err());
    }

    mod properties {
        use super::*;
        use proptest::prelude::*;

        /// Tables of up to sixteen records over arbitrary account ids, both known kinds and one this
        /// build has no name for, values from empty to a few kilobytes.
        fn any_table() -> impl Strategy<Value = Table> {
            proptest::collection::btree_map(
                (
                    proptest::array::uniform16(any::<u8>()),
                    prop_oneof![Just(1u8), Just(2u8), Just(200u8)],
                ),
                proptest::collection::vec(any::<u8>(), 0..4096),
                0..16,
            )
            .prop_map(|entries| {
                entries
                    .into_iter()
                    .map(|(key, value)| (key, Zeroizing::new(value)))
                    .collect()
            })
        }

        proptest! {
            /// The pair has to agree over every shape a store can take, not only the ones a
            /// hand-written case thought of. A disagreement is a stored secret that cannot be read
            /// back.
            #[test]
            fn decoding_what_was_encoded_returns_what_went_in(table in any_table()) {
                let encoded = encode(&table).expect("encode");
                prop_assert_eq!(decode(&encoded).expect("decode"), table);
            }

            /// The claim the padding is there for: how big the file is says nothing about how much
            /// is in it, beyond which bucket it landed in.
            #[test]
            fn an_encoded_table_is_always_a_whole_number_of_buckets(table in any_table()) {
                let encoded = encode(&table).expect("encode");
                prop_assert!(encoded.len() >= BUCKET);
                prop_assert!(encoded.len().is_multiple_of(BUCKET));
            }

            /// The decoder is one of the two entry points the fuzz workspace drives, and this is the
            /// same property checked with shrinking and a committed seed: no input panics, and none
            /// makes it reserve out of a number it read.
            #[test]
            fn decoding_arbitrary_bytes_never_panics(
                bytes in proptest::collection::vec(any::<u8>(), 0..4096)
            ) {
                let _ = decode(&bytes);
            }

            /// The shape a fuzzer takes a long time to reach on its own: bytes that are already a
            /// whole number of buckets, so the length rule lets them through to the record walk.
            #[test]
            fn decoding_well_sized_arbitrary_bytes_never_panics(
                buckets in 1usize..4,
                bytes in proptest::collection::vec(any::<u8>(), 0..2048),
            ) {
                let mut padded = bytes;
                padded.resize(buckets * BUCKET, 0);
                let _ = decode(&padded);
            }
        }
    }
}

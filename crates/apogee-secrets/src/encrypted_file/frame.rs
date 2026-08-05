//! The sealed file's header, and the structural rules a byte sequence has to satisfy before any of
//! it is trusted.
//!
//! Everything here runs on bytes that arrived from disk, so it is the hostile surface of the
//! backend: it allocates nothing it did not first bound, derives nothing, and rejects on the file's
//! length before the file is read at all. The key derivation is only entered once every field below
//! has been checked.
//!
//! Big-endian throughout, and the only place in this crate that converts. The header is the on-disk
//! contract: a change to a field's offset, width, or meaning orphans every secret already stored.

use crate::SecretsError;

/// What every file of this format starts with.
pub(crate) const MAGIC: [u8; 4] = *b"APSF";

/// The format this build writes and the only one it reads. An exact match: there is no read-older
/// path, because a build that guessed at an older layout would decrypt the wrong bytes under a key
/// that verified, which is worse than refusing.
pub(crate) const VERSION: u16 = 1;

/// Argon2id, RFC 9106 version `0x13`.
pub(crate) const KDF_ARGON2ID: u8 = 1;

/// XChaCha20-Poly1305.
pub(crate) const AEAD_XCHACHA20POLY1305: u8 = 1;

/// Bytes before the ciphertext.
pub(crate) const HEADER_LEN: usize = 100;

/// Poly1305 tag width, for both envelopes.
pub(crate) const TAG_LEN: usize = 16;

/// Derived key width.
pub(crate) const KEY_LEN: usize = 32;

/// Salt width.
pub(crate) const SALT_LEN: usize = 16;

/// XChaCha20 nonce width. The 192-bit nonce is what makes drawing a fresh random one per write safe
/// with no counter, and a counter in a file that can be restored from a backup is a nonce reuse
/// waiting to happen.
pub(crate) const NONCE_LEN: usize = 24;

/// The sealed plaintext is padded up to a multiple of this.
///
/// It is what stops the file's length varying with its contents: a store holding nothing and a store
/// holding a couple of dozen typical secrets are the same size on disk, so the length says neither
/// how many accounts have secrets nor how long any of them is.
pub(crate) const BUCKET: usize = 512;

/// Header plus body tag: everything in the file that is not ciphertext.
pub(crate) const OVERHEAD: usize = HEADER_LEN + TAG_LEN;

/// The shortest a well-formed file can be: the overhead plus one bucket.
pub(crate) const MIN_FILE: usize = OVERHEAD + BUCKET;

/// The largest file this build will read into memory.
///
/// Checked against the directory entry's size before a byte is read, so a hostile file cannot make an
/// honest process allocate for it. Two orders of magnitude above what a realistic store needs.
pub(crate) const MAX_FILE: u64 = 1 << 20;

/// Where each header field starts.
const OFF_MAGIC: usize = 0;
const OFF_VERSION: usize = 4;
const OFF_SUITE: usize = 6;
const OFF_M_COST: usize = 8;
const OFF_T_COST: usize = 12;
const OFF_P_COST: usize = 16;
const OFF_SALT: usize = 20;
const OFF_CHECK_NONCE: usize = 36;
const OFF_CHECK_TAG: usize = 60;
const OFF_BODY_NONCE: usize = 76;

/// How much of the header the check envelope is bound to: everything that decides the key.
///
/// Deliberately short of the whole header. The check envelope's one job is to answer whether this
/// key was derived from the same passphrase and the same parameters as the file was sealed under, so
/// binding it to the body's nonce would make an edited body nonce read as a wrong passphrase instead
/// of as a damaged file, which is exactly the distinction the second envelope exists to draw.
pub(crate) const CHECK_AAD_LEN: usize = OFF_CHECK_NONCE;

use super::kdf::KdfCost;

/// A parsed header. Every field in it has been checked; nothing here is a value read straight out of
/// the file and passed on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Header {
    pub(crate) cost: KdfCost,
    pub(crate) salt: [u8; SALT_LEN],
    pub(crate) check_nonce: [u8; NONCE_LEN],
    pub(crate) check_tag: [u8; TAG_LEN],
    pub(crate) body_nonce: [u8; NONCE_LEN],
}

impl Header {
    /// Lay the header out, ready to be the associated data the body is sealed under.
    pub(crate) fn to_bytes(self) -> [u8; HEADER_LEN] {
        let mut out = [0u8; HEADER_LEN];
        out[OFF_MAGIC..OFF_VERSION].copy_from_slice(&MAGIC);
        out[OFF_VERSION..OFF_SUITE].copy_from_slice(&VERSION.to_be_bytes());
        out[OFF_SUITE..OFF_M_COST].copy_from_slice(&suite().to_be_bytes());
        out[OFF_M_COST..OFF_T_COST].copy_from_slice(&self.cost.memory_kib().to_be_bytes());
        out[OFF_T_COST..OFF_P_COST].copy_from_slice(&self.cost.passes().to_be_bytes());
        out[OFF_P_COST..OFF_SALT].copy_from_slice(&self.cost.lanes().to_be_bytes());
        out[OFF_SALT..OFF_CHECK_NONCE].copy_from_slice(&self.salt);
        out[OFF_CHECK_NONCE..OFF_CHECK_TAG].copy_from_slice(&self.check_nonce);
        out[OFF_CHECK_TAG..OFF_BODY_NONCE].copy_from_slice(&self.check_tag);
        out[OFF_BODY_NONCE..HEADER_LEN].copy_from_slice(&self.body_nonce);
        out
    }

    /// Read a header out of the front of `bytes`.
    ///
    /// Rejects in the order a hostile file is cheapest to refuse in: the shape of the container, then
    /// the algorithms named in it, then the work it asks for. Nothing here derives a key, so a file
    /// asking for a terabyte of Argon2 memory costs a comparison rather than an allocation.
    pub(crate) fn parse(bytes: &[u8]) -> Result<Self, SecretsError> {
        check_length(bytes.len())?;
        let head: &[u8; HEADER_LEN] = bytes
            .get(..HEADER_LEN)
            .and_then(|s| s.try_into().ok())
            .ok_or(corrupt("file length"))?;

        if head[OFF_MAGIC..OFF_VERSION] != MAGIC {
            return Err(corrupt("file magic"));
        }
        if be16(head, OFF_VERSION) != VERSION {
            return Err(corrupt("format version"));
        }
        // The two algorithm ids occupy one big-endian word, so the frame keeps the magic / version /
        // flags shape the other containers in this workspace use. They are read as the two bytes they
        // are rather than as the word split back apart, which is the same thing with no conversion
        // that could be given a defensive default and then silently take it.
        if head[OFF_SUITE] != KDF_ARGON2ID {
            return Err(corrupt("key derivation function"));
        }
        if head[OFF_SUITE + 1] != AEAD_XCHACHA20POLY1305 {
            return Err(corrupt("cipher"));
        }
        let cost = KdfCost::new(
            be32(head, OFF_M_COST),
            be32(head, OFF_T_COST),
            be32(head, OFF_P_COST),
        )
        .ok_or(corrupt("key derivation cost"))?;

        Ok(Self {
            cost,
            salt: fixed(head, OFF_SALT),
            check_nonce: fixed(head, OFF_CHECK_NONCE),
            check_tag: fixed(head, OFF_CHECK_TAG),
            body_nonce: fixed(head, OFF_BODY_NONCE),
        })
    }
}

/// The two algorithm ids as the word they are stored as.
const fn suite() -> u16 {
    ((KDF_ARGON2ID as u16) << 8) | (AEAD_XCHACHA20POLY1305 as u16)
}

/// Whether a file of `len` bytes can be one of these at all.
///
/// There is no length field in the header on purpose: the ciphertext runs from the end of the header
/// to sixteen bytes before the end of the file, and a stored length would be a second source of truth
/// that can disagree with the file it describes. The rule below is what replaces it, and it is what
/// turns a truncated or extended file into a named structural error rather than a tag failure.
pub(crate) fn check_length(len: usize) -> Result<(), SecretsError> {
    if len < MIN_FILE || !(len - OVERHEAD).is_multiple_of(BUCKET) {
        return Err(corrupt("file length"));
    }
    Ok(())
}

/// Refuse a file from the size the directory entry reports, before any of it is read.
pub(crate) fn check_size_on_disk(len: u64) -> Result<(), SecretsError> {
    if len > MAX_FILE {
        return Err(corrupt("file length"));
    }
    check_length(usize::try_from(len).unwrap_or(usize::MAX))
}

/// The one place this backend builds its unreadable-file condition, so every `detail` string in it
/// comes from one list.
pub(crate) const fn corrupt(detail: &'static str) -> SecretsError {
    SecretsError::Corrupt { detail }
}

fn be16(head: &[u8; HEADER_LEN], at: usize) -> u16 {
    u16::from_be_bytes([head[at], head[at + 1]])
}

fn be32(head: &[u8; HEADER_LEN], at: usize) -> u32 {
    u32::from_be_bytes([head[at], head[at + 1], head[at + 2], head[at + 3]])
}

/// Copy a fixed-width field out. The width comes from the destination type, so a field cannot be read
/// at the wrong length without the assignment failing to compile.
fn fixed<const N: usize>(head: &[u8; HEADER_LEN], at: usize) -> [u8; N] {
    let mut out = [0u8; N];
    out.copy_from_slice(&head[at..at + N]);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header() -> Header {
        Header {
            cost: KdfCost::CURRENT,
            salt: [0x11; SALT_LEN],
            check_nonce: [0x22; NONCE_LEN],
            check_tag: [0x33; TAG_LEN],
            body_nonce: [0x44; NONCE_LEN],
        }
    }

    /// The offsets are the on-disk contract. Written out as literals rather than derived from the
    /// constants, because a test that computed them from the same constants it is guarding would
    /// still pass after a layout change that orphans every stored secret.
    #[test]
    fn the_header_layout_is_frozen() {
        assert_eq!(HEADER_LEN, 100);
        assert_eq!((OFF_MAGIC, OFF_VERSION, OFF_SUITE), (0, 4, 6));
        assert_eq!((OFF_M_COST, OFF_T_COST, OFF_P_COST), (8, 12, 16));
        assert_eq!((OFF_SALT, OFF_CHECK_NONCE), (20, 36));
        assert_eq!((OFF_CHECK_TAG, OFF_BODY_NONCE), (60, 76));
        assert_eq!((SALT_LEN, NONCE_LEN, TAG_LEN, KEY_LEN), (16, 24, 16, 32));
        assert_eq!((BUCKET, OVERHEAD, MIN_FILE), (512, 116, 628));

        let bytes = header().to_bytes();
        assert_eq!(&bytes[0..4], b"APSF");
        assert_eq!(&bytes[4..8], &[0x00, 0x01, 0x01, 0x01]);
        assert_eq!(&bytes[20..36], &[0x11; 16]);
        assert_eq!(&bytes[36..60], &[0x22; 24]);
        assert_eq!(&bytes[60..76], &[0x33; 16]);
        assert_eq!(&bytes[76..100], &[0x44; 24]);
    }

    /// The check envelope covers the fields that decide the key and stops before the body's nonce.
    /// Extending it would fold a damaged body into a wrong-passphrase report.
    #[test]
    fn the_check_envelope_covers_exactly_what_decides_the_key() {
        assert_eq!(CHECK_AAD_LEN, 36);
        assert_eq!(CHECK_AAD_LEN, OFF_CHECK_NONCE);
    }

    #[test]
    fn a_header_round_trips_through_its_bytes() {
        let original = header();
        let mut file = original.to_bytes().to_vec();
        file.resize(MIN_FILE, 0);
        assert_eq!(Header::parse(&file).expect("parse"), original);
    }

    /// Each rejection has to name a different part of the file: the string is what a front end
    /// triages on, and two conditions sharing one would make a corrupt header and an unsupported
    /// build indistinguishable.
    #[test]
    fn each_structural_rejection_names_a_different_part() {
        let mut seen = Vec::new();
        let cases: [(usize, u8, &str); 5] = [
            (0, b'X', "file magic"),
            (5, 0x02, "format version"),
            (6, 0x02, "key derivation function"),
            (7, 0x02, "cipher"),
            // The second byte of the memory cost, which is the only one of its four that is nonzero
            // at the shipped value: zeroing it takes the cost to nothing rather than leaving it be.
            (9, 0x00, "key derivation cost"),
        ];
        for (at, value, expected) in cases {
            let mut file = header().to_bytes().to_vec();
            file.resize(MIN_FILE, 0);
            file[at] = value;
            let Err(SecretsError::Corrupt { detail }) = Header::parse(&file) else {
                panic!("byte {at} set to {value} must be refused");
            };
            assert_eq!(detail, expected);
            seen.push(detail);
        }
        seen.sort_unstable();
        let before = seen.len();
        seen.dedup();
        assert_eq!(seen.len(), before, "two conditions share one detail string");
    }

    /// The length rule is the whole of what makes a truncation a structural error. Without it a file
    /// cut short would reach the cipher and come back as a tag failure, which reads as damage to the
    /// contents rather than to the container.
    #[test]
    fn a_file_that_is_not_a_whole_number_of_buckets_is_refused() {
        for len in [0, 1, HEADER_LEN, MIN_FILE - 1, MIN_FILE + 1, MIN_FILE + 511] {
            assert!(matches!(
                check_length(len),
                Err(SecretsError::Corrupt {
                    detail: "file length"
                })
            ));
        }
        for len in [MIN_FILE, MIN_FILE + BUCKET, MIN_FILE + BUCKET * 9] {
            check_length(len).expect("a whole number of buckets");
        }
    }

    /// A hostile file must be refused from the size the directory entry reports, so nothing that big
    /// is ever read into memory.
    #[test]
    fn a_file_larger_than_the_cap_is_refused_from_its_size_alone() {
        assert!(check_size_on_disk(MAX_FILE + 1).is_err());
        check_size_on_disk(MIN_FILE as u64).expect("the smallest well-formed file");
    }

    /// A cost outside the band this build accepts is refused before the derivation is entered, so a
    /// header asking for a terabyte of memory or an hour of passes costs a comparison. The elapsed
    /// time is the only observable proof the derivation was never run.
    #[test]
    fn a_hostile_cost_is_refused_without_deriving() {
        let mut file = header().to_bytes().to_vec();
        file.resize(MIN_FILE, 0);
        file[8..12].copy_from_slice(&u32::MAX.to_be_bytes());
        file[12..16].copy_from_slice(&u32::MAX.to_be_bytes());
        let start = std::time::Instant::now();
        let parsed = Header::parse(&file);
        assert!(matches!(
            parsed,
            Err(SecretsError::Corrupt {
                detail: "key derivation cost"
            })
        ));
        assert!(start.elapsed() < std::time::Duration::from_millis(50));
    }
}

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
/// at the wrong length without the call failing to compile.
///
/// Built element by element rather than zeroed and then overwritten. The result is the same, and the
/// intermediate array of zeros is not: a salt or a nonce that briefly holds a constant is what a
/// dataflow scan reads as one, and it is right to.
fn fixed<const N: usize>(head: &[u8; HEADER_LEN], at: usize) -> [u8; N] {
    std::array::from_fn(|i| head[at + i])
}

// A sibling file rather than an inline module, unlike the rest of this crate. These tests need
// fixed salts, nonces and keys, which is what a known-answer vector is, and the security scan reads
// a literal in that position as a hard-coded credential. Its configuration already excludes test
// files by name, so the tests move to where the exclusion can see them rather than the rule being
// turned off for code where it would be right.
#[cfg(test)]
mod tests;

//! Verification policy and the proof it produces.
//!
//! A [`Validator`] describes how a download's bytes are checked; [`VerifiedFile`] is the proof the
//! check passed. `VerifiedFile` is sealed: its only constructor is crate-private and reached only
//! after verification, so a consumer that accepts a `VerifiedFile` cannot be handed unverified bytes.

use std::path::{Path, PathBuf};

use crate::hash::DigestPin;

/// How a downloaded file (or its blocks) is verified before it can become a [`VerifiedFile`].
/// `None` over a plain-`http://` source is rejected when the download spec is built.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum Validator {
    /// One SHA1 per fixed-size block, from the patchlist.
    BlockSha1 {
        /// The fixed block size the hash list is laid out over.
        block_size: u32,
        /// One SHA1 per block, in file order.
        hashes: Vec<[u8; 20]>,
    },
    /// A single SHA256 over the whole file.
    Sha256([u8; 32]),
    /// A single BLAKE3 over the whole file. Same width and same guarantee as
    /// [`Sha256`](Validator::Sha256), and what our own signed manifests pin under; the older
    /// function stays for the artifacts pinned before it and for anything SE hands us.
    Blake3([u8; 32]),
    /// No verification. Refused unless explicitly opted into, and never over plain HTTP.
    None,
    /// The bytes are length-checked here and authenticated by a named out-of-band gate downstream
    /// (a boot patch's ZiPatch chunk-CRC scan, run by `apogee-patcher`; boot patchlists carry no
    /// per-block hashes). Unlike [`None`](Validator::None) it is allowed over plain `http://`,
    /// because it documents a real downstream check rather than skipping one. Requires a declared
    /// length and is served only through
    /// [`Fetcher::download_external`](crate::Fetcher::download_external), which hands back a plain
    /// path, never a [`VerifiedFile`].
    External,
}

impl Validator {
    /// A stable 32-byte fingerprint of this validator's configuration, recorded in the resume
    /// journal. Resuming against a different validator (a different expected digest, a different
    /// block layout) no longer matches, so the download restarts from zero instead of trusting bytes
    /// against the wrong policy.
    ///
    /// The encoding lives in [`crate::journal`]: the fingerprint is journal identity data, and that
    /// module is the one home for every byte-layout decision the `.apdl` format freezes.
    pub(crate) fn config_digest(&self) -> [u8; 32] {
        crate::journal::validator_config_digest(self)
    }
}

/// The check a signed manifest's artifact pin becomes. The catalogs carry a [`DigestPin`] rather
/// than a bare 32 bytes precisely so this conversion, and not a caller's assumption, decides which
/// function the download is verified under.
impl From<DigestPin> for Validator {
    fn from(pin: DigestPin) -> Self {
        match pin {
            DigestPin::Sha256(digest) => Validator::Sha256(digest),
            DigestPin::Blake3(digest) => Validator::Blake3(digest),
        }
    }
}

/// Proof that a file passed its [`Validator`]. `apogee-patcher` accepts only a `VerifiedFile` into
/// its apply queue, so "installed an unverified patch" is a type error, not a code-review hope.
/// Minted only inside this crate, after verification.
#[derive(Debug)]
pub struct VerifiedFile {
    path: PathBuf,
}

impl VerifiedFile {
    /// Mint the proof for a file that just passed its validator. Crate-private: the only callers are
    /// the verification paths, so the type cannot be forged from outside.
    pub(crate) fn mint(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    /// The verified file on disk.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every variant's fingerprint is its own. The pair that matters is the two whole-file digests
    /// over identical bytes: same width, so only the tag tells them apart, and a collision would let
    /// a `.part` hashed under one function resume under the other and be judged against a digest
    /// describing different bytes.
    #[test]
    fn no_two_validators_share_a_journal_fingerprint() {
        let digest = [0x5au8; 32];
        let all = [
            Validator::None,
            Validator::External,
            Validator::Sha256(digest),
            Validator::Blake3(digest),
            Validator::BlockSha1 {
                block_size: 1,
                hashes: vec![[0; 20]],
            },
        ];
        for (i, a) in all.iter().enumerate() {
            for b in &all[i + 1..] {
                assert_ne!(
                    a.config_digest(),
                    b.config_digest(),
                    "{a:?} and {b:?} fingerprint alike"
                );
            }
        }
    }

    /// The tag is what separates them, not the digest bytes: same function, different bytes must
    /// also differ, or a resume would accept a `.part` fetched under a different pin entirely.
    #[test]
    fn a_different_expected_digest_is_a_different_fingerprint() {
        assert_ne!(
            Validator::Blake3([1; 32]).config_digest(),
            Validator::Blake3([2; 32]).config_digest()
        );
    }
}

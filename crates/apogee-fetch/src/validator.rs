//! Verification policy and the proof it produces.
//!
//! A [`Validator`] describes how a download's bytes are checked; [`VerifiedFile`] is the proof the
//! check passed. `VerifiedFile` is sealed: its only constructor is crate-private and reached only
//! after verification, so a consumer that accepts a `VerifiedFile` cannot be handed unverified bytes.

use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

/// How a downloaded file (or its blocks) is verified before it can become a [`VerifiedFile`].
/// `None` over a plain-`http://` source is rejected when the download spec is built.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum Validator {
    /// One SHA1 per fixed-size block, from the patchlist.
    BlockSha1 {
        block_size: u32,
        hashes: Vec<[u8; 20]>,
    },
    /// A single SHA256 over the whole file.
    Sha256([u8; 32]),
    /// No verification (refused unless explicitly opted into, never over plain HTTP).
    None,
    /// The bytes are length-checked here and authenticated by a named out-of-band gate downstream:
    /// the marker a boot patch rides, whose integrity is the patcher's ZiPatch chunk-CRC scan
    /// (boot patchlists carry no per-block hashes). Unlike [`None`](Validator::None) it is allowed
    /// over plain `http://`, because it documents a real downstream check rather than skipping one;
    /// it requires a declared length and is served only through
    /// [`Fetcher::download_external`](crate::Fetcher::download_external), which hands back a plain
    /// path, never a [`VerifiedFile`].
    External,
}

impl Validator {
    /// A stable 32-byte fingerprint of this validator's configuration, recorded in the resume
    /// journal. Resuming against a different validator (a different expected digest, a different
    /// block layout) no longer matches, so the download restarts from zero instead of trusting bytes
    /// against the wrong policy. A leading tag byte keeps the variants from colliding.
    pub(crate) fn config_digest(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        match self {
            Validator::BlockSha1 { block_size, hashes } => {
                hasher.update([0x01]);
                hasher.update(block_size.to_le_bytes());
                for hash in hashes {
                    hasher.update(hash);
                }
            }
            Validator::Sha256(digest) => {
                hasher.update([0x02]);
                hasher.update(digest);
            }
            Validator::None => hasher.update([0x00]),
            Validator::External => hasher.update([0x03]),
        }
        hasher.finalize().into()
    }
}

/// Proof that a file passed its [`Validator`]. `apogee-patcher` accepts only a `VerifiedFile` into
/// its apply queue, so "installed an unverified patch" is a type error, not a code-review hope.
/// Minted only inside this crate after verification.
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

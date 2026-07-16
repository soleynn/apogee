//! Verification policy and the proof it produces.
//!
//! A [`Validator`] describes how a download's bytes are checked; [`VerifiedFile`] is the proof the
//! check passed. `VerifiedFile` is sealed: its only constructor is crate-private and reached only
//! after verification, so a consumer that accepts a `VerifiedFile` cannot be handed unverified bytes.

use std::path::{Path, PathBuf};

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
}

/// Proof that a file passed its [`Validator`]. `apogee-patcher` accepts only a `VerifiedFile` into
/// its apply queue, so "installed an unverified patch" is a type error, not a code-review hope.
/// Minted only inside this crate after verification.
#[derive(Debug)]
pub struct VerifiedFile {
    path: PathBuf,
}

impl VerifiedFile {
    /// The verified file on disk.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }
}

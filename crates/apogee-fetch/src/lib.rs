#![forbid(unsafe_code)]
//! Resumable, verified HTTP downloads.
//!
//! STUB: public shape only (the error taxonomy, the [`Validator`] policy, the [`VerifiedFile`]
//! proof type, and the [`Fetcher`] handle + builder the composition root constructs); download and
//! verification behavior is not yet built.

use std::path::{Path, PathBuf};

use thiserror::Error;
use url::Url;

/// Download failures.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum FetchError {
    #[error("connect to {host} failed")]
    Connect {
        host: String,
        #[source]
        source: std::io::Error,
    },
    #[error("http {status} for {url}")]
    Http { status: u16, url: Url },
    #[error("server does not support byte ranges: {url}")]
    RangesUnsupported { url: Url },
    #[error("stalled at {at_bytes} bytes: {url}")]
    Stalled { url: Url, at_bytes: u64 },
    #[error("length mismatch: expected {expected}, got {got}")]
    LengthMismatch { expected: u64, got: u64 },
    #[error("server file changed mid-resume: {validator}")]
    ServerFileChanged { validator: String },
    #[error("block {block} at offset {offset} failed verification after {attempts} attempt(s)")]
    BlockVerifyFailed {
        block: u32,
        offset: u64,
        attempts: u32,
    },
    #[error("file verification failed: expected {expected}, got {got}")]
    FileVerifyFailed { expected: String, got: String },
    #[error("download journal corrupt: {path:?}")]
    JournalCorrupt { path: PathBuf },
    #[error("io error at {path:?}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("cancelled")]
    Cancelled,
}

/// How a downloaded file (or its blocks) is verified before it can become a [`VerifiedFile`].
/// `None` over a plain-`http://` source is a constructor error.
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
/// its apply queue, so "installed an unverified patch" is a type error. Minted only inside this
/// crate after verification.
#[derive(Debug)]
pub struct VerifiedFile {
    path: PathBuf,
}

impl VerifiedFile {
    /// The verified file on disk.
    pub fn path(&self) -> &Path {
        &self.path
    }
}

/// A shared speed-limit handle applied across concurrent downloads.
#[derive(Debug, Clone, Default)]
pub struct SpeedLimit;

/// Resumable, verified downloader. A cheap handle: clone it to hand to several consumers.
#[derive(Debug, Clone, Default)]
pub struct Fetcher;

impl Fetcher {
    /// Start configuring a [`Fetcher`].
    pub fn builder() -> FetcherBuilder {
        FetcherBuilder
    }
}

/// Builder for [`Fetcher`]'s concurrency and rate limits.
#[derive(Debug, Default)]
pub struct FetcherBuilder;

impl FetcherBuilder {
    pub fn max_files(self, _n: u32) -> Self {
        self
    }
    pub fn max_connections_per_file(self, _n: u32) -> Self {
        self
    }
    pub fn max_connections_total(self, _n: u32) -> Self {
        self
    }
    pub fn speed_limit(self, _limit: SpeedLimit) -> Self {
        self
    }

    /// Build the configured [`Fetcher`].
    pub fn build(self) -> Result<Fetcher, FetchError> {
        Ok(Fetcher)
    }
}

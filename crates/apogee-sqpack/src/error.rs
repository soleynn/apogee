//! The crate's error taxonomy. SqPack containers arrive from a plain-HTTP install path and may be
//! corrupt or heavily modded, so reading them yields a typed fault, never a panic. Offsets and keys
//! travel with every variant for triage.

use thiserror::Error;

/// Crate result over [`Error`].
pub type Result<T> = std::result::Result<T, Error>;

/// SqPack access failures. Offsets and keys travel with every variant for triage.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum Error {
    /// A container header did not start with `SqPack\0\0`.
    #[error("bad SqPack magic")]
    BadMagic,
    /// A recognized-but-unhandled platform byte (PS3/PS4), or an unrecognized one.
    #[error("unsupported platform")]
    UnsupportedPlatform,
    /// A header's stored SHA-1 did not match its contents (checked by the inspector, not on open).
    #[error("header hash mismatch")]
    HeaderHashMismatch,
    /// Fewer bytes were available than a structure requires.
    #[error("truncated at offset {offset}: need {needed} more byte(s)")]
    Truncated { offset: u64, needed: u64 },
    /// An index entry resolved to an offset outside its dat file.
    #[error("entry out of bounds: index_key={index_key}, offset={offset}")]
    EntryOutOfBounds { index_key: u64, offset: u64 },
    /// A compressed block's framing or payload was structurally invalid.
    #[error("block corrupt at offset {offset}: {detail}")]
    BlockCorrupt { offset: u64, detail: &'static str },
    /// A hash collision landed on a synonym entry that could not yet be resolved.
    #[error("unresolved synonym for key {key}")]
    SynonymUnresolved { key: String },
    /// A declared or decoded size exceeded the caller's [`crate::codec::Limits`].
    #[error("resource limit exceeded")]
    LimitExceeded,
    /// The archive was locked by a running game.
    #[error("archive busy")]
    Busy,
    /// An underlying I/O failure.
    #[error("io error")]
    Io(#[from] std::io::Error),
}

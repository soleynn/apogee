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
    /// An index container's header or segment table contradicted the format.
    #[error("index corrupt at offset {offset}: {detail}")]
    IndexCorrupt { offset: u64, detail: &'static str },
    /// A dat container's headers, one of its entries, or one of that entry's tables contradicted
    /// the format. Kept distinct from [`Error::BlockCorrupt`] and [`Error::IndexCorrupt`] because
    /// the three reach different callers: a block fault is the codec's, an index fault the lookup's,
    /// and this one belongs to the archive that holds the file. The dat side has one arm where the
    /// index side has one, rather than a container arm and an entry arm, because the offset every
    /// variant carries already says which of the two it is.
    #[error("dat entry corrupt at offset {offset}: {detail}")]
    EntryCorrupt { offset: u64, detail: &'static str },
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

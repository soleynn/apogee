//! The crate's error taxonomy. Patches arrive over plain HTTP and are treated as hostile: parsing
//! yields a typed fault, never a panic, and every variant carries the patch-file offset so a
//! patch-day failure reads as "chunk at offset 0x… has unknown command 'Z'" instead of a guess.

use std::path::PathBuf;

use thiserror::Error;

/// Crate result over [`Error`].
pub type Result<T> = std::result::Result<T, Error>;

/// The I/O operation in flight when an [`Error::Io`] occurred.
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub enum Op {
    Open,
    Read,
    Write,
    Truncate,
    Remove,
    MakeDir,
}

/// A bounded resource, for [`Error::LimitExceeded`].
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub enum Limit {
    /// A declared chunk payload length exceeded the parser's cap.
    ChunkSize,
    /// The whole patch declared more chunks than the parser accepts.
    ChunkCount,
    /// A target file grew past the cap.
    FileSize,
    /// A confined path nested deeper than the cap.
    PathDepth,
}

/// ZiPatch parse/apply failures. Byte offsets travel with every variant for triage.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum Error {
    #[error("io error during {during:?}")]
    Io {
        #[source]
        source: std::io::Error,
        target: Option<PathBuf>,
        during: Op,
    },
    #[error("bad patch magic")]
    BadMagic,
    #[error("unknown chunk {fourcc:?} at offset {offset}")]
    UnknownChunk { fourcc: [u8; 4], offset: u64 },
    #[error("unknown command {cmd:#x} at offset {offset}")]
    UnknownCommand { cmd: u8, offset: u64 },
    #[error("chunk crc mismatch at offset {offset}: stored {stored}, computed {computed}")]
    ChunkCrcMismatch {
        offset: u64,
        stored: u32,
        computed: u32,
    },
    #[error("truncated at offset {offset}: needed {needed} more byte(s)")]
    Truncated { offset: u64, needed: u64 },
    #[error("path escape: {raw}")]
    PathEscape { raw: String },
    #[error("limit exceeded: {what:?} value {value} exceeds max {max}")]
    LimitExceeded { what: Limit, value: u64, max: u64 },
    #[error("corrupt at offset {offset}: {detail}")]
    Corrupt { offset: u64, detail: &'static str },
    #[error("unsupported: {what}")]
    Unsupported { what: &'static str },
}

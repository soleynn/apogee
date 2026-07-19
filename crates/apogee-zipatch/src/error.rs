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
    /// A compressed block declared a decompressed size past the decode cap.
    BlockSize,
    /// An `.apzi` index body decompressed to more than the decode cap.
    IndexSize,
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
    #[error("apply cancelled")]
    Cancelled,
    #[error("bad index magic")]
    BadIndexMagic,
    #[error("unsupported index version {version}")]
    UnsupportedIndexVersion { version: u16 },
}

impl Error {
    /// An I/O fault with no specific target path, tagged with the operation in flight. The single
    /// home for the wrapper every module used to re-declare.
    pub(crate) fn io(source: std::io::Error, during: Op) -> Self {
        Error::Io {
            source,
            target: None,
            during,
        }
    }

    /// Rebase a shared-codec block-decode failure onto the patch file. The codec reports offsets
    /// relative to the block it was handed, but this crate's contract is patch-file-absolute, so add
    /// the block's own offset (`block_off`) back in. `declared`/`limit` supply the numbers a
    /// field-less codec `LimitExceeded` cannot carry itself.
    pub(crate) fn from_block(
        source: apogee_sqpack::Error,
        block_off: u64,
        declared: u32,
        limit: u32,
    ) -> Self {
        use apogee_sqpack::Error as Codec;
        match source {
            Codec::BlockCorrupt { offset, detail } => Error::Corrupt {
                offset: block_off + offset,
                detail,
            },
            Codec::Truncated { offset, needed } => Error::Truncated {
                offset: block_off + offset,
                needed,
            },
            Codec::LimitExceeded => Error::LimitExceeded {
                what: Limit::BlockSize,
                value: u64::from(declared),
                max: u64::from(limit),
            },
            Codec::Io(source) => Error::Io {
                source,
                target: None,
                during: Op::Write,
            },
            _ => Error::Corrupt {
                offset: block_off,
                detail: "block decode failed",
            },
        }
    }
}

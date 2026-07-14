#![forbid(unsafe_code)]
//! FFXIV SqPack container formats and the compressed-block codec.
//!
//! STUB: public shape only (error taxonomy + `codec` surface); behavior is not yet built. The block
//! format in [`codec`] is shared with `apogee-zipatch` to prevent drift.

use thiserror::Error;

/// Crate result over [`Error`].
pub type Result<T> = std::result::Result<T, Error>;

/// SqPack access failures. Offsets and keys travel with every variant for triage.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum Error {
    #[error("bad SqPack magic")]
    BadMagic,
    #[error("unsupported platform")]
    UnsupportedPlatform,
    #[error("header hash mismatch")]
    HeaderHashMismatch,
    #[error("entry out of bounds: index_key={index_key}, offset={offset}")]
    EntryOutOfBounds { index_key: u64, offset: u64 },
    #[error("block corrupt at offset {offset}: {detail}")]
    BlockCorrupt { offset: u64, detail: &'static str },
    #[error("unresolved synonym for key {key}")]
    SynonymUnresolved { key: String },
    #[error("resource limit exceeded")]
    LimitExceeded,
    #[error("archive busy")]
    Busy,
    #[error("io error")]
    Io(#[from] std::io::Error),
}

/// The compressed-block codec: the on-disk SqPack block format, shared with `apogee-zipatch`'s
/// `SqpkCompressedBlock` so the two never drift.
pub mod codec {
    use super::Result;
    use std::io::{Read, Write};

    /// A parsed, validated 16-byte little-endian block header.
    #[derive(Debug, Clone)]
    pub struct BlockHeader {
        pub header_size: u32,
        pub compressed_size: u32,
        pub decompressed_size: u32,
    }

    /// What [`read_block`] produced.
    #[derive(Debug, Clone)]
    pub struct BlockMeta {
        pub compressed_size: u32,
        pub decompressed_size: u32,
    }

    /// Allocation bounds enforced while decoding a block (all SqPack input is hostile).
    #[derive(Debug, Clone)]
    pub struct Limits {
        pub max_decompressed: u32,
    }

    /// Decode one block from `src` into `out`, bounded by `limits`.
    pub fn read_block(
        _src: &mut impl Read,
        _out: &mut impl Write,
        _limits: &Limits,
    ) -> Result<BlockMeta> {
        todo!("decode a compressed SqPack block")
    }

    /// Parse a 16-byte block header.
    pub fn parse_header(_bytes: &[u8; 16]) -> Result<BlockHeader> {
        todo!("parse a SqPack block header")
    }
}

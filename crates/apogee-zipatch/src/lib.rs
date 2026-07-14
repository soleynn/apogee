#![forbid(unsafe_code)]
//! ZiPatch patch-file parsing and application.
//!
//! STUB: public shape only (error taxonomy + the [`PatchSink`]/[`RangeSource`] seams this crate
//! owns); parse/apply/index behavior is not yet built. Endianness discipline (BE framing, LE
//! game-native fields) and the shared compressed-block format arrive with that behavior.

use std::ops::Range;
use std::path::{Path, PathBuf};

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
    FileSize,
    ChunkCount,
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

/// A game-root-relative path that has passed confinement; sinks accept nothing else.
/// Unconstructable outside this crate (the confinement check that mints one is not yet built).
pub struct SafePath(PathBuf);

impl SafePath {
    /// The confined relative path.
    pub fn as_path(&self) -> &Path {
        &self.0
    }
}

/// A concrete file a patch writes to.
pub struct TargetPath(PathBuf);

impl TargetPath {
    /// The target path.
    pub fn as_path(&self) -> &Path {
        &self.0
    }
}

/// Which expansion files to keep during a [`PatchSink::remove_expansion`].
#[derive(Debug, Clone, Default)]
pub struct KeepFilter {/* keep-rules not yet modeled */}

/// Identifies one source patch file to a [`RangeSource`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PatchId(pub u32);

/// Where written bytes come from: carries provenance for free.
#[derive(Debug)]
pub enum DataSource<'a> {
    Raw {
        patch_off: u64,
        bytes: &'a [u8],
    },
    Deflate {
        patch_off: u64,
        compressed_len: u32,
        decompressed_len: u32,
    },
    Zeros {
        len: u64,
    },
}

/// The apply target: every mutation a ZiPatch can make, expressed as typed calls so a sink can
/// journal, verify, or marshal them (the elevated worker is one such sink).
pub trait PatchSink {
    fn write(&mut self, target: &TargetPath, off: u64, src: DataSource<'_>) -> Result<()>;
    fn write_empty_block(&mut self, target: &TargetPath, off: u64, blocks: u32) -> Result<()>;
    fn truncate(&mut self, target: &TargetPath, len: u64) -> Result<()>;
    fn remove_file(&mut self, target: &TargetPath) -> Result<()>;
    fn remove_expansion(&mut self, expansion: u16, keep: &KeepFilter) -> Result<()>;
    fn make_dir_tree(&mut self, rel: &SafePath) -> Result<()>;
    fn remove_dir(&mut self, rel: &SafePath) -> Result<()>;
}

/// Random-access byte-range reads over one source patch file. Ranges are pre-merged and sorted by
/// the caller. The local implementor is `LocalPatchSource`; the HTTP one (`HttpRangeSource`) lives
/// in `apogee-fetch`.
pub trait RangeSource {
    fn read_ranges(
        &mut self,
        patch: PatchId,
        ranges: &[Range<u64>],
        out: &mut dyn FnMut(u64, &[u8]) -> Result<()>,
    ) -> Result<()>;
}

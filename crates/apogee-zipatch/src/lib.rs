#![forbid(unsafe_code)]
//! ZiPatch (`.patch`) parsing, and the seams for applying, indexing, and repairing FFXIV installs.
//!
//! Today this crate reads the container: [`PatchReader`] streams a patch into the typed [`Chunk`]
//! model (every chunk and SQPK command), verifying each chunk's CRC32 and treating all input as
//! hostile (bounded allocation, typed errors carrying the patch-file offset, no panics). The apply
//! engine, block index, and repair planner build on this stream; their public shape lives in
//! [`PatchSink`]/[`RangeSource`], filled in by later phases.
//!
//! Endianness is the format's foot-gun: the chunk frame and most fields are big-endian, a few are
//! little-endian. Every conversion routes through one [`bytes`] module (the audit gate enforces it),
//! and a per-field byte golden pins the layout. The compressed-block payloads inside `SQPK F:A` are
//! SqPack's native block format; when the applier decodes them it shares `apogee-sqpack`'s codec, so
//! the writer and the eventual reader cannot drift.

mod bytes;
mod chunk;
mod error;
mod parse;
mod seam;

pub use chunk::{
    AddData, ApplyFreeSpace, ApplyOption, ApplyOptionKind, Chunk, Directory, EmptyBlock,
    FileHeader, FileHeaderV3, FileOp, FileOperation, FileTarget, Header, HeaderFileKind,
    HeaderTargetKind, IndexCommand, IndexOp, MAGIC, PatchInfo, Platform, Sqpk, TargetInfo,
};
pub use error::{Error, Limit, Op, Result};
pub use parse::{DEFAULT_MAX_CHUNK_SIZE, Limits, PatchReader};
pub use seam::{DataSource, KeepFilter, PatchId, PatchSink, RangeSource, SafePath, TargetPath};

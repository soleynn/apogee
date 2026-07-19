#![forbid(unsafe_code)]
//! ZiPatch (`.patch`) parsing, and the seams for applying, indexing, and repairing FFXIV installs.
//!
//! [`PatchReader`] streams a patch into the typed [`Chunk`] model (every chunk and SQPK command),
//! verifying each chunk's CRC32 and treating all input as hostile (bounded allocation, typed errors
//! carrying the patch-file offset, no panics). [`apply`] drives that stream into a [`PatchSink`];
//! [`DiskSink`] is the sink that writes a boot patch to a game tree. The block index and repair
//! planner build on the same stream; their public shape lives in [`PatchSink`]/[`RangeSource`],
//! filled in by later phases.
//!
//! Endianness is the format's foot-gun: the chunk frame and most fields are big-endian, a few are
//! little-endian. Every conversion routes through one [`bytes`] module (the audit gate enforces it),
//! and a per-field byte golden pins the layout. The compressed-block payloads inside `SQPK F:A` are
//! SqPack's native block format; when the applier decodes them it shares `apogee-sqpack`'s codec, so
//! the writer and the eventual reader cannot drift.

mod apply;
mod bytes;
mod chunk;
mod datfile;
mod disk;
mod error;
mod index;
mod parse;
mod seam;

pub use apply::{ApplyOptions, ApplyProgress, apply, scan_crc};
pub use chunk::{
    AddData, ApplyFreeSpace, ApplyOption, ApplyOptionKind, Chunk, Directory, EmptyBlock,
    FileHeader, FileHeaderV3, FileOp, FileOperation, FileTarget, Header, HeaderFileKind,
    HeaderTargetKind, IndexCommand, IndexOp, MAGIC, PatchInfo, Platform, Sqpk, TargetInfo,
};
pub use disk::DiskSink;
pub use error::{Error, Limit, Op, Result};
pub use index::{
    Index, PartRef, SizeMismatch, StrayFile, VerifyOptions, VerifyReport, build as build_index,
};
pub use parse::{DEFAULT_MAX_CHUNK_SIZE, Limits, PatchReader};
pub use seam::{DataSource, KeepFilter, PatchId, PatchSink, RangeSource, SafePath, TargetPath};

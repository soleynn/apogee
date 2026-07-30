#![forbid(unsafe_code)]
//! FFXIV SqPack container formats and the compressed-block codec.
//!
//! This crate is the read side of FFXIV's archive format: the shared block [`codec`], the container
//! [`CommonHeader`] parse, the [`Index`] reader, the [`Dat`] reader that turns an entry back into
//! the file it holds, and [`GameData`], which puts them together over an install.
//!
//! [`integrity`] is the structural inspector built on top of them: pure checks over one container's
//! bytes, driven either one container at a time or as a sweep over a whole install. Mod detection
//! builds on these too.
//!
//! ```no_run
//! let game = apogee_sqpack::GameData::open("/path/to/game")?;
//! if let Some(bytes) = game.read("exd/root.exl")? {
//!     // Hashed, looked up in an index, decoded block by block out of a dat file.
//!     assert!(!bytes.is_empty());
//! }
//! # Ok::<(), apogee_sqpack::Error>(())
//! ```
//!
//! The block format in [`codec`] is shared with `apogee-zipatch`: its `F:A` patch payloads are SqPack
//! blocks in transit, so the one implementation lives here and both crates consume it, by
//! construction never drifting.

mod archive;
mod bytes;
pub mod codec;
mod container;
mod dat;
mod error;
#[cfg(any(test, feature = "test-fixtures"))]
pub mod fixtures;
mod game;
mod hash;
mod index;
pub mod integrity;

pub use archive::{ArchiveId, Category, PLATFORM_TAG};
pub use container::{
    COMMON_HEADER_LEN, COMMON_HEADER_MIN, CommonHeader, Platform, SQPACK_MAGIC, SqPackKind,
    parse_common_header,
};
pub use dat::{
    BlockRun, ContentType, DATA_HEADER_LEN, DATA_HEADER_OFFSET, DATA_UNIT,
    DEFAULT_MAX_ENTRY_HEADER_BYTES, DEFAULT_MAX_FILE_BYTES, Dat, DatLimits, DatSource, DataHeader,
    EMPTY_BLOCK_HEADER_LEN, ENTRY_HEADER_LEN, Entry, EntryBody, EntryHeader, FileSource,
    MIP_LEVEL_LEN, MODEL_FILE_HEADER_LEN, MODEL_LOD_COUNT, MODEL_TABLE_OFFSET, MipLevel,
    ModelSection, ModelTable, STANDARD_BLOCK_LEN, StandardBlock, TextureTable, empty_block_count,
    empty_block_header,
};
pub use error::{Error, Result};
pub use game::{ArchiveInfo, FileLocation, GameData, Repo, RepoInfo};
pub use hash::{PathHash, hash_path};
pub use index::{
    COLLISION_RECORD_LEN, CollisionRecord, DEFAULT_MAX_INDEX_BYTES, DataLocation, FOLDER_ROW_LEN,
    FolderRow, INDEX_HEADER_LEN, INDEX_HEADER_OFFSET, INDEX1_ENTRY_LEN, INDEX2_ENTRY_LEN, Index,
    IndexEntry, IndexHeader, IndexKind, IndexLimits, SEGMENT_COUNT, SegmentDescriptor,
};

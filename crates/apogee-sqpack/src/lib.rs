#![forbid(unsafe_code)]
//! FFXIV SqPack container formats and the compressed-block codec.
//!
//! This crate is the read side of FFXIV's archive format. Today it provides the shared block
//! [`codec`], the container [`CommonHeader`] parse, the [`Index`] reader, and [`GameData`] install
//! enumeration and lookup; dat-entry extraction and the integrity inspector build on top of these.
//!
//! ```no_run
//! let game = apogee_sqpack::GameData::open("/path/to/game")?;
//! if let Some(found) = game.lookup("exd/root.exl")? {
//!     // The file's bytes start at `found.offset` inside `found.dat_path`.
//!     assert_eq!(found.offset % 128, 0);
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
mod error;
mod game;
mod hash;
mod index;

pub use archive::{ArchiveId, Category, PLATFORM_TAG};
pub use container::{
    COMMON_HEADER_LEN, COMMON_HEADER_MIN, CommonHeader, Platform, SQPACK_MAGIC, SqPackKind,
    parse_common_header,
};
pub use error::{Error, Result};
pub use game::{ArchiveInfo, FileLocation, GameData, Repo, RepoInfo};
pub use hash::{PathHash, hash_path};
pub use index::{
    COLLISION_RECORD_LEN, CollisionRecord, DEFAULT_MAX_INDEX_BYTES, DataLocation, FOLDER_ROW_LEN,
    FolderRow, INDEX_HEADER_LEN, INDEX_HEADER_OFFSET, INDEX1_ENTRY_LEN, INDEX2_ENTRY_LEN, Index,
    IndexEntry, IndexHeader, IndexKind, IndexLimits, SEGMENT_COUNT, SegmentDescriptor,
};

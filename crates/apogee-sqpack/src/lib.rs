#![forbid(unsafe_code)]
//! FFXIV SqPack container formats and the compressed-block codec.
//!
//! This crate is the read side of FFXIV's archive format. Today it provides the shared block
//! [`codec`], the container [`CommonHeader`] parse, the [`Index`] reader, and [`GameData`] install
//! enumeration; dat-entry extraction and the integrity inspector build on top of these.
//!
//! The block format in [`codec`] is shared with `apogee-zipatch`: its `F:A` patch payloads are SqPack
//! blocks in transit, so the one implementation lives here and both crates consume it, by
//! construction never drifting.

mod bytes;
pub mod codec;
mod container;
mod error;
mod game;
mod hash;
mod index;

pub use container::{
    COMMON_HEADER_LEN, COMMON_HEADER_MIN, CommonHeader, Platform, SQPACK_MAGIC, SqPackKind,
    parse_common_header,
};
pub use error::{Error, Result};
pub use game::{GameData, Repo, RepoInfo};
pub use hash::{PathHash, hash_path};
pub use index::{
    COLLISION_RECORD_LEN, CollisionRecord, DEFAULT_MAX_INDEX_BYTES, DataLocation, FOLDER_ROW_LEN,
    FolderRow, INDEX_HEADER_LEN, INDEX_HEADER_OFFSET, INDEX1_ENTRY_LEN, INDEX2_ENTRY_LEN, Index,
    IndexEntry, IndexHeader, IndexKind, IndexLimits, SEGMENT_COUNT, SegmentDescriptor,
};

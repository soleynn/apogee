#![forbid(unsafe_code)]
//! FFXIV SqPack container formats and the compressed-block codec.
//!
//! This crate is the read side of FFXIV's archive format. Today it provides the shared block
//! [`codec`], the container [`CommonHeader`] parse, and [`GameData`] install enumeration; the index
//! reader, dat-entry extraction, and the integrity inspector build on top of these.
//!
//! The block format in [`codec`] is shared with `apogee-zipatch`: its `F:A` patch payloads are SqPack
//! blocks in transit, so the one implementation lives here and both crates consume it, by
//! construction never drifting.

mod bytes;
pub mod codec;
mod container;
mod error;
mod game;

pub use container::{
    COMMON_HEADER_LEN, COMMON_HEADER_MIN, CommonHeader, Platform, SQPACK_MAGIC, SqPackKind,
    parse_common_header,
};
pub use error::{Error, Result};
pub use game::{GameData, Repo, RepoInfo};

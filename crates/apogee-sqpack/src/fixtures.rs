//! Synthetic SqPack archives for tests, behind the `test-fixtures` feature.
//!
//! One archive-format authority for every test in the workspace that needs real container bytes:
//! this crate's own reader and inspector tests, and `apogee-zipatch`'s agreement suite, which lays
//! an archive down through a patch and reads it back through this crate. Keeping the builders here
//! rather than in each crate's `tests/` means the layout has a single owner and cannot drift from
//! the reader it feeds, the same argument that puts the block codec here.
//!
//! What a builder writes by default is *clean*: every entry sits on a real slot boundary, every
//! block is padded the way the format pads it, and all six digests a container carries are right.
//! A finding out of one of these is a bug in a check. Every knob past the default spells one
//! measured shape differently, so a check can be shown to fire on exactly that difference.
//!
//! This is deliberately not a write API. The crate reads archives and never writes them; nothing
//! here is reachable without the feature, and no release build compiles it.

pub use crate::dat::builder::{
    Built, DatBuilder, EntrySpec, ModelSpec, Packing, Placed, block_bytes,
};
pub use crate::integrity::fixture::{ArchiveFixture, BuiltArchive};

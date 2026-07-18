#![forbid(unsafe_code)]
//! FFXIV SqPack container formats and the compressed-block codec.
//!
//! The block [`codec`] is shared with `apogee-zipatch`: its `F:A` patch payloads are SqPack blocks in
//! transit, so the one implementation lives here and both crates consume it, by construction never
//! drifting.

mod bytes;
pub mod codec;
mod error;

pub use error::{Error, Result};

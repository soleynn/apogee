//! The seams this crate owns for the apply/repair phases: the [`PatchSink`] the one interpreter
//! drives (apply, index, or trace) and the [`RangeSource`] repair pulls bytes through. These are the
//! public shape the applier and the repair planner fill in; the parser above produces the [`Chunk`]
//! stream they consume.
//!
//! [`Chunk`]: crate::Chunk

use std::ops::Range;
use std::path::{Path, PathBuf};

use crate::error::Result;

/// A game-root-relative path that has passed confinement; sinks accept nothing else.
/// Unconstructable outside this crate (the confinement check that mints one is not yet built).
pub struct SafePath(PathBuf);

impl SafePath {
    /// The confined relative path.
    #[must_use]
    pub fn as_path(&self) -> &Path {
        &self.0
    }
}

/// A concrete file a patch writes to.
pub struct TargetPath(PathBuf);

impl TargetPath {
    /// The target path.
    #[must_use]
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

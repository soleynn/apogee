//! [`IndexSink`]: the [`PatchSink`] that records a patch's effects into the block-index model
//! instead of writing them to disk. It is the same interpreter execution the applier drives, so the
//! index it builds and the tree an apply produces cannot disagree.
//!
//! Each sink call becomes a [`TargetFile::update`] on the addressed file, tagged with the source
//! patch currently being interpreted (set by the builder before each patch). The bytes a write
//! carries are ignored here (only offsets, lengths, and provenance are recorded); the build's CRC
//! pass reads them back from the source patches afterward.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use crate::chunk::expansion_folder;
use crate::error::Result;
use crate::index::model::{Part, TargetFile};
use crate::seam::{DataSource, KeepFilter, PatchSink, SafePath, TargetPath};

/// Accumulates the block index for a patch chain. Construct with [`IndexSink::new`], point it at each
/// source patch in turn with [`IndexSink::set_source`], drive `apply` over that patch, then take the
/// finished target map with [`IndexSink::into_targets`].
pub(crate) struct IndexSink {
    targets: BTreeMap<PathBuf, TargetFile>,
    current: u16,
}

impl IndexSink {
    pub(crate) fn new() -> Self {
        Self {
            targets: BTreeMap::new(),
            current: 0,
        }
    }

    /// Tag subsequent writes with source-patch index `idx` (its position in the chain).
    pub(crate) fn set_source(&mut self, idx: u16) {
        self.current = idx;
    }

    /// The accumulated per-file tilings, keyed by confined relative path.
    pub(crate) fn into_targets(self) -> BTreeMap<PathBuf, TargetFile> {
        self.targets
    }

    fn target_mut(&mut self, path: &Path) -> &mut TargetFile {
        self.targets
            .entry(path.to_path_buf())
            .or_insert_with(|| TargetFile::new(path.to_path_buf()))
    }
}

impl PatchSink for IndexSink {
    fn write(&mut self, target: &TargetPath, off: u64, src: DataSource<'_>) -> Result<()> {
        let idx = self.current;
        let part = match src {
            DataSource::Raw { patch_off, bytes } => {
                Part::patch(off, bytes.len() as u64, idx, patch_off, false, 0, 0)
            }
            DataSource::Deflate {
                patch_off,
                compressed_len,
                decompressed_len,
                ..
            } => Part::patch(
                off,
                u64::from(decompressed_len),
                idx,
                patch_off,
                true,
                compressed_len,
                decompressed_len,
            ),
            DataSource::Zeros { len } => Part::zeros(off, len),
        };
        self.target_mut(target.as_path()).update(part);
        Ok(())
    }

    fn write_empty_block(&mut self, target: &TargetPath, off: u64, blocks: u32) -> Result<()> {
        // A `block_count == 0` empty block has zero target length, so `update` drops it; the applier
        // still stamps a 24-byte header there. That divergence is only reachable with a malformed
        // patch (real `D`/`E` carry `count >= 1`) and is documented, not worked around.
        let part = Part::empty_block(off, u64::from(blocks) << 7, blocks);
        self.target_mut(target.as_path()).update(part);
        Ok(())
    }

    fn truncate(&mut self, target: &TargetPath, len: u64) -> Result<()> {
        self.target_mut(target.as_path()).truncate(len);
        Ok(())
    }

    fn remove_file(&mut self, target: &TargetPath) -> Result<()> {
        self.targets.remove(target.as_path());
        Ok(())
    }

    fn remove_expansion(&mut self, expansion: u16, keep: &KeepFilter) -> Result<()> {
        // Match the disk sweep: immediate files of `sqpack/{folder}` and `movie/{folder}`, keeping
        // those the filter spares. The index holds only what the chain built, so dropping recorded
        // targets under those folders is exactly the final tree the applier would leave.
        let folder = expansion_folder(expansion as u8);
        let swept = [
            Path::new("sqpack").join(&folder),
            Path::new("movie").join(&folder),
        ];
        self.targets.retain(|path, _| {
            let in_sweep = path
                .parent()
                .is_some_and(|parent| swept.iter().any(|dir| parent == dir.as_path()));
            if !in_sweep {
                return true;
            }
            let name = path
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default();
            keep.is_kept(&name)
        });
        Ok(())
    }

    fn make_dir_tree(&mut self, _rel: &SafePath) -> Result<()> {
        // Directories are not indexed parts; reconstruction creates parents implicitly when it writes
        // files, and the tree-manifest compare ignores empty directories.
        Ok(())
    }

    fn remove_dir(&mut self, _rel: &SafePath) -> Result<()> {
        Ok(())
    }
}

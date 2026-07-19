//! The block-index data model: per target file, an ordered, non-overlapping list of [`Part`]s that
//! tiles `[0, final_len)`. Each patch write supersedes whatever range it overlaps, so the tiling
//! always reflects the *final* bytes after the whole chain. Two writes cannot leave the map in a
//! contradictory state, and the same execution that applies a patch builds this map, so index and
//! apply cannot drift.
//!
//! The supersession algorithm ([`TargetFile::update`]) is the block index's crux. A write does
//! `split_at(start)`, `split_at(end)`, then replaces every fully-covered part with the one new part;
//! `split_at` divides the part straddling an offset, advancing a plain part's source offset and a
//! compressed part's *decoded* offset (compressed bytes can never be sub-sliced, so both halves keep
//! the same block source and differ only in where they start reading the inflated output). This is
//! the behavior of the reference `IndexedZiPatchTargetFile`, documented and re-implemented, never
//! translated.

use std::path::PathBuf;

use crate::chunk::Platform;

/// Where a [`Part`]'s target bytes come from. The three sentinels reconstruct with no patch bytes;
/// `Unavailable` is produced only at repair time when the owning patch is absent (defined now, unused
/// until the repair phase).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Source {
    /// Bytes copied (or inflated) from source patch `idx` in the chain.
    Patch {
        /// Positional index into the index's source-patch list.
        idx: u16,
        /// Byte offset in that patch: the raw bytes for a stored write, the DEFLATE payload start for
        /// a compressed one.
        off: u64,
        /// The source is a compressed block: reconstruct = inflate the whole block, then slice from
        /// `decoded_from`.
        deflated: bool,
        /// Compressed payload length in the patch (compressed source only), so the reconstructor
        /// knows how many bytes to read before inflating.
        deflated_len: u32,
        /// The whole block's decompressed length (compressed source only). Constant across splits, so
        /// a split half inflates the same block and slices it; the shared codec needs the exact size.
        block_dlen: u32,
        /// Offset into the *inflated* block output where this part's bytes begin (advanced when a
        /// compressed part is split; `0` otherwise).
        decoded_from: u64,
    },
    /// An all-zero run.
    Zeros,
    /// A `D`/`E` empty-block region: a 24-byte header (from `block_count`) followed by zeros.
    /// `decoded_from` is the offset into that header+zeros pattern (advanced when split).
    EmptyBlock { block_count: u32, decoded_from: u64 },
    /// No source patch holds these bytes (repair-time only).
    Unavailable,
}

impl Source {
    /// The source for the right half of a part split `by` target bytes in. Only the read pointer
    /// moves: a plain patch part advances its byte offset, a compressed or empty-block part advances
    /// its decoded offset, and a position-independent source (zeros, unavailable) is unchanged.
    fn advanced(self, by: u64) -> Source {
        match self {
            Source::Patch {
                idx,
                off,
                deflated: false,
                deflated_len,
                block_dlen,
                decoded_from,
            } => Source::Patch {
                idx,
                off: off + by,
                deflated: false,
                deflated_len,
                block_dlen,
                decoded_from,
            },
            Source::Patch {
                idx,
                off,
                deflated: true,
                deflated_len,
                block_dlen,
                decoded_from,
            } => Source::Patch {
                idx,
                off,
                deflated: true,
                deflated_len,
                block_dlen,
                decoded_from: decoded_from + by,
            },
            Source::EmptyBlock {
                block_count,
                decoded_from,
            } => Source::EmptyBlock {
                block_count,
                decoded_from: decoded_from + by,
            },
            other @ (Source::Zeros | Source::Unavailable) => other,
        }
    }
}

/// One contiguous run of a target file: a target range, where its bytes come from, and (once the
/// build's CRC pass runs) the CRC32 of those final bytes. `crc_valid` is meaningful only for
/// [`Source::Patch`] parts; zeros/empty-block parts are checked structurally at verify time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Part {
    pub target_off: u64,
    pub target_len: u64,
    pub source: Source,
    pub crc32: u32,
    pub crc_valid: bool,
}

impl Part {
    /// A plain-copy or compressed patch part. For a stored source, `deflated_len`/`block_dlen` are
    /// `0`; for a compressed one they are the payload's compressed and full decompressed lengths.
    pub(crate) fn patch(
        target_off: u64,
        target_len: u64,
        idx: u16,
        off: u64,
        deflated: bool,
        deflated_len: u32,
        block_dlen: u32,
    ) -> Self {
        Self {
            target_off,
            target_len,
            source: Source::Patch {
                idx,
                off,
                deflated,
                deflated_len,
                block_dlen,
                decoded_from: 0,
            },
            crc32: 0,
            crc_valid: false,
        }
    }

    /// An all-zero run.
    pub(crate) fn zeros(target_off: u64, target_len: u64) -> Self {
        Self {
            target_off,
            target_len,
            source: Source::Zeros,
            crc32: 0,
            crc_valid: false,
        }
    }

    /// A `D`/`E` empty-block region of `target_len` bytes (`block_count` 128-byte blocks).
    pub(crate) fn empty_block(target_off: u64, target_len: u64, block_count: u32) -> Self {
        Self {
            target_off,
            target_len,
            source: Source::EmptyBlock {
                block_count,
                decoded_from: 0,
            },
            crc32: 0,
            crc_valid: false,
        }
    }

    /// One past the last target byte this part covers.
    pub(crate) fn target_end(&self) -> u64 {
        self.target_off + self.target_len
    }
}

/// One target file's tiling: a `Vec<Part>` kept sorted by `target_off`, non-overlapping, and gapless
/// (`parts[i].target_end() == parts[i+1].target_off`), so `[0, final_len)` is fully covered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TargetFile {
    pub path: PathBuf,
    pub parts: Vec<Part>,
}

impl TargetFile {
    pub(crate) fn new(path: PathBuf) -> Self {
        Self {
            path,
            parts: Vec::new(),
        }
    }

    /// The file's final length: the end of its last part (`0` when empty).
    pub(crate) fn final_len(&self) -> u64 {
        self.parts.last().map_or(0, Part::target_end)
    }

    /// Ensure a part boundary falls exactly at `off`, splitting the straddling part or filling a
    /// trailing gap with zeros. A no-op when a boundary already exists (including at `0` and at the
    /// current end). Preserves the gapless tiling: a write past the end grows the file through a zero
    /// run, exactly as a seek-and-write past EOF leaves zeros on disk.
    fn split_at(&mut self, off: u64) {
        let i = match self.parts.binary_search_by(|p| p.target_off.cmp(&off)) {
            // A part already starts at `off`.
            Ok(_) => return,
            Err(i) => i,
        };
        if i == 0 {
            // `off <= parts[0].target_off`. Zero is a natural boundary; a positive `off` can only
            // reach here with an empty list (any write mints a leading part at 0), so it is a leading
            // gap filled with zeros.
            if off != 0 {
                self.parts.insert(0, Part::zeros(0, off));
            }
            return;
        }
        let prev = self.parts[i - 1];
        let prev_end = prev.target_end();
        if prev_end == off {
            // The boundary already sits at the previous part's end.
        } else if prev_end < off {
            // A gap after the last part (the only place a gap can open in a gapless tiling): zeros.
            self.parts.insert(i, Part::zeros(prev_end, off - prev_end));
        } else {
            // `off` falls strictly inside the previous part: split it there.
            self.split_part(i - 1, off);
        }
    }

    /// Split `parts[idx]` at absolute target offset `off`, keeping the left half in place and
    /// inserting the right half after it. Only the right half's read pointer moves.
    fn split_part(&mut self, idx: usize, off: u64) {
        let whole = self.parts[idx];
        let left_len = off - whole.target_off;

        let mut left = whole;
        left.target_len = left_len;
        left.crc_valid = false;

        let mut right = whole;
        right.target_off = off;
        right.target_len = whole.target_end() - off;
        right.source = whole.source.advanced(left_len);
        right.crc_valid = false;

        self.parts[idx] = left;
        self.parts.insert(idx + 1, right);
    }

    /// Record one write: split the tiling at the write's start and end, then replace every part now
    /// fully inside `[start, end)` with the single new part. A zero-length write is a no-op (a
    /// `block_count == 0` empty block writes only its header on disk; see the crate design notes).
    pub(crate) fn update(&mut self, part: Part) {
        if part.target_len == 0 {
            return;
        }
        let start = part.target_off;
        let end = part.target_end();
        self.split_at(start);
        self.split_at(end);
        let left = self.parts.partition_point(|p| p.target_off < start);
        let right = self.parts.partition_point(|p| p.target_off < end);
        self.parts.splice(left..right, std::iter::once(part));
    }

    /// Truncate the file to `len`. `len == 0` (a fresh `F:A`) clears the tiling; a positive `len`
    /// drops parts at or beyond `len` (defensive: the interpreter only ever truncates to zero).
    pub(crate) fn truncate(&mut self, len: u64) {
        if len == 0 {
            self.parts.clear();
            return;
        }
        self.split_at(len);
        self.parts.retain(|p| p.target_off < len);
    }
}

/// A source patch the index was built from: its name and expected length, so a repair can locate and
/// length-check the file the parts point into.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SourcePatch {
    pub name: String,
    pub expected_len: u64,
}

/// A built block index: the repo version and platform it describes, the source patches its parts
/// reference, and one [`TargetFile`] per file in the final tree (sorted by path for a deterministic
/// on-disk `.apzi`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Index {
    pub(crate) repo_version: String,
    pub(crate) platform: Platform,
    pub(crate) sources: Vec<SourcePatch>,
    pub(crate) targets: Vec<TargetFile>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn patch_part(off: u64, len: u64, idx: u16, source_off: u64) -> Part {
        Part::patch(off, len, idx, source_off, false, 0, 0)
    }

    /// A helper reading back a target's parts as `(off, len, tag)` triples, where `tag` is a short
    /// source marker, for compact assertions.
    fn layout(tf: &TargetFile) -> Vec<(u64, u64, char)> {
        tf.parts
            .iter()
            .map(|p| {
                let tag = match p.source {
                    Source::Patch { .. } => 'p',
                    Source::Zeros => 'z',
                    Source::EmptyBlock { .. } => 'e',
                    Source::Unavailable => 'u',
                };
                (p.target_off, p.target_len, tag)
            })
            .collect()
    }

    #[test]
    fn a_single_write_tiles_from_zero() {
        let mut tf = TargetFile::new("a".into());
        tf.update(patch_part(0, 100, 0, 0));
        assert_eq!(layout(&tf), vec![(0, 100, 'p')]);
        assert_eq!(tf.final_len(), 100);
    }

    #[test]
    fn a_write_past_the_end_grows_through_a_zero_gap() {
        let mut tf = TargetFile::new("a".into());
        tf.update(patch_part(128, 128, 0, 0));
        // A leading zero run fills [0, 128); the write tiles [128, 256).
        assert_eq!(layout(&tf), vec![(0, 128, 'z'), (128, 128, 'p')]);
        assert_eq!(tf.final_len(), 256);
    }

    #[test]
    fn a_later_write_fully_supersedes_an_earlier_one() {
        let mut tf = TargetFile::new("a".into());
        tf.update(patch_part(0, 256, 0, 0));
        tf.update(patch_part(0, 256, 1, 500));
        // Only the newer part survives, still one tile.
        assert_eq!(layout(&tf), vec![(0, 256, 'p')]);
        match tf.parts[0].source {
            Source::Patch { idx, off, .. } => {
                assert_eq!(idx, 1);
                assert_eq!(off, 500);
            }
            other => panic!("expected patch source, got {other:?}"),
        }
    }

    #[test]
    fn an_interior_write_splits_the_neighbours_and_advances_their_offsets() {
        let mut tf = TargetFile::new("a".into());
        tf.update(patch_part(0, 384, 0, 1000)); // one big part, source_off 1000
        tf.update(patch_part(128, 128, 1, 0)); // overwrite the middle 128 bytes
        // Left keeps source_off 1000; the right remnant's source_off advanced by 256 to 1256.
        assert_eq!(
            layout(&tf),
            vec![(0, 128, 'p'), (128, 128, 'p'), (256, 128, 'p')]
        );
        let left = tf.parts[0].source;
        let right = tf.parts[2].source;
        assert!(matches!(
            left,
            Source::Patch {
                off: 1000,
                idx: 0,
                ..
            }
        ));
        assert!(matches!(
            right,
            Source::Patch {
                off: 1256,
                idx: 0,
                ..
            }
        ));
    }

    #[test]
    fn splitting_a_compressed_part_advances_the_decoded_offset_not_the_byte_offset() {
        let mut tf = TargetFile::new("a".into());
        // A compressed part: 300 decoded bytes from patch 0, DEFLATE payload at byte 2000, clen 90.
        tf.update(Part::patch(0, 300, 0, 2000, true, 90, 300));
        tf.update(patch_part(100, 50, 1, 0)); // overwrite 50 bytes in the middle
        // Left remnant [0,100): same block, decoded_from 0. Right remnant [150,300): SAME byte
        // offset 2000 (compressed bytes are never sub-sliced), decoded_from advanced to 150.
        assert_eq!(
            layout(&tf),
            vec![(0, 100, 'p'), (100, 50, 'p'), (150, 150, 'p')]
        );
        assert!(matches!(
            tf.parts[0].source,
            Source::Patch {
                off: 2000,
                deflated: true,
                decoded_from: 0,
                ..
            }
        ));
        assert!(matches!(
            tf.parts[2].source,
            Source::Patch {
                off: 2000,
                deflated: true,
                decoded_from: 150,
                ..
            }
        ));
    }

    #[test]
    fn truncate_to_zero_clears_the_tiling() {
        let mut tf = TargetFile::new("a".into());
        tf.update(patch_part(0, 256, 0, 0));
        tf.truncate(0);
        assert!(tf.parts.is_empty());
        assert_eq!(tf.final_len(), 0);
        tf.update(patch_part(0, 64, 1, 0));
        assert_eq!(layout(&tf), vec![(0, 64, 'p')]);
    }

    #[test]
    fn a_zero_length_write_is_ignored() {
        let mut tf = TargetFile::new("a".into());
        tf.update(patch_part(0, 128, 0, 0));
        tf.update(Part::empty_block(128, 0, 0)); // block_count 0 -> zero length
        assert_eq!(layout(&tf), vec![(0, 128, 'p')]);
    }

    #[test]
    fn an_empty_block_write_tiles_as_one_part() {
        let mut tf = TargetFile::new("a".into());
        tf.update(patch_part(0, 256, 0, 0));
        tf.update(Part::empty_block(128, 128, 1)); // one 128-byte empty block over the tail
        assert_eq!(layout(&tf), vec![(0, 128, 'p'), (128, 128, 'e')]);
    }

    #[test]
    fn adjacent_writes_stay_gapless_and_ordered() {
        let mut tf = TargetFile::new("a".into());
        tf.update(patch_part(0, 128, 0, 0));
        tf.update(patch_part(128, 128, 0, 128));
        tf.update(patch_part(256, 128, 0, 256));
        assert_eq!(
            layout(&tf),
            vec![(0, 128, 'p'), (128, 128, 'p'), (256, 128, 'p')]
        );
        // Contiguity invariant: each part's end is the next part's start.
        for w in tf.parts.windows(2) {
            assert_eq!(w[0].target_end(), w[1].target_off);
        }
    }
}

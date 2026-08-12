//! Block-level repair: heal a live install against the index by pulling only the broken byte ranges.
//! Verify produces a [`VerifyReport`]; the planner groups each broken part's source range per patch
//! and merges near-adjacent gaps, then [`Index::repair`] fetches those ranges through a caller-supplied
//! [`RangeSource`], reconstructs each part, and re-verifies what it wrote.
//!
//! The healed bytes come from the same [`materialize_patch`](reconstruct::materialize_patch) the
//! full-tree reconstructor uses, so a repaired byte is byte-identical to a reconstructed one by
//! construction. Only the byte *source* differs: reconstruct replays whole patch files, repair pulls
//! discrete ranges. A [`RangeBuf`] presents those ranges as a `Read + Seek` reader so the materializer
//! is reused unchanged. Zeros and empty-block parts carry no source bytes and are reconstructed
//! locally.
//!
//! Repair is single-pass and policy-free: a fetch/decode fault is a hard error (a broken source; the
//! caller's retry owns recovery), while a part that cannot be sourced (unavailable, or the fetched
//! bytes fail their CRC) is a soft skip left for the re-verify to report. Retry budget, backoff, and
//! local-then-HTTP ordering live in the caller.
//!
//! Where the bytes land is the caller's too. Every write goes through a [`RepairSink`], so the same
//! plan either lands in the tree ([`DiskRepairSink`]) or is handed to a process that may write it,
//! for an install this one has no rights to. The plan, the CRC gate and the re-verify are identical
//! either way.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs;
use std::io::{self, Read, Seek, SeekFrom};
use std::ops::Range;
use std::path::{Path, PathBuf};

use apogee_sqpack::codec;

use crate::disk::DiskRepairSink;
use crate::error::{Error, Op, Result};
use crate::index::model::{Index, Part, Source, TargetFile};
use crate::index::reconstruct::{self, MAX_BLOCK_DECOMPRESSED};
use crate::index::verify::{PartRef, VerifyOptions, VerifyReport};
use crate::seam::{PatchId, RangeSource, RepairSink, RepairWrite};

/// Two fetch ranges within this many bytes of each other merge into one request: pulling a little
/// slack across a small gap is cheaper than a second round trip. The reference used 512 B.
const GAP_MERGE: u64 = 4 << 10;

/// One source patch an [`Index`] references: its [`PatchId`] (its chain position), file name, and
/// expected length, so a caller can build a [`RangeSource`] keyed by id.
#[derive(Debug, Clone, Copy)]
pub struct SourceRef<'a> {
    pub id: PatchId,
    pub name: &'a str,
    pub expected_len: u64,
}

/// The result of one repair pass. `is_complete()` is true when nothing remains broken.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RepairOutcome {
    /// Parts (including a recreated file's parts) that verify clean after this pass.
    pub repaired: Vec<PartRef>,
    /// Parts still failing after this pass: an unsourceable part, or one the caller must retry
    /// against another source.
    pub still_broken: Vec<PartRef>,
    /// Missing files (re)created this pass.
    pub recreated: Vec<PathBuf>,
    /// Files whose on-disk length was corrected this pass.
    pub resized: Vec<PathBuf>,
    /// Bytes the source delivered: the proof a repair pulled only the broken ranges.
    pub bytes_fetched: u64,
}

impl RepairOutcome {
    /// Whether the pass left nothing broken.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.still_broken.is_empty()
    }
}

impl Index {
    /// Repair the install under `root` in a single pass, pulling only the broken byte ranges through
    /// `source`. Broken parts are rewritten in place, missing files recreated (sparsely), and
    /// wrong-length files resized; strays are left for the caller to quarantine. Retry/backoff and
    /// local-vs-HTTP ordering are the caller's, so this does one attempt and reports what remains.
    ///
    /// # Errors
    /// [`Error::Io`] on a filesystem fault, or any fetch/decode fault the `source` or a corrupt
    /// fetched block raises (a broken source; the caller retries). A part whose fetched bytes fail
    /// their CRC, or that no patch can source, is *not* an error: it lands in
    /// [`RepairOutcome::still_broken`].
    pub fn repair(
        &self,
        root: &Path,
        report: &VerifyReport,
        source: &mut dyn RangeSource,
    ) -> Result<RepairOutcome> {
        let mut sink = DiskRepairSink::new(root);
        self.repair_into(root, report, source, &mut sink)
    }

    /// [`repair`](Self::repair), with the writes going wherever `sink` puts them.
    ///
    /// `root` is still read: the plan comes from the tree as it stands and the pass ends by
    /// re-verifying what it wrote. Only the writing is the sink's, which is what lets a caller that
    /// cannot write the tree from this process hand them to one that can. The pass flushes the sink
    /// before it re-reads, so a sink that batches still has its writes counted as repaired.
    ///
    /// # Errors
    /// As [`repair`](Self::repair), plus whatever `sink` raises.
    pub fn repair_into(
        &self,
        root: &Path,
        report: &VerifyReport,
        source: &mut dyn RangeSource,
        sink: &mut dyn RepairSink,
    ) -> Result<RepairOutcome> {
        let limits = codec::Limits {
            max_decompressed: MAX_BLOCK_DECOMPRESSED,
        };
        let by_path: HashMap<&Path, &TargetFile> =
            self.targets.iter().map(|t| (t.path.as_path(), t)).collect();
        let sources_len = self.sources.len();

        // Plan the work set: every part we will try to heal (so the re-verify can classify it) and,
        // for the patch-backed ones, the source range to fetch.
        let mut attempted: Vec<PartRef> = Vec::new();
        let mut fetch: BTreeMap<u16, Vec<Range<u64>>> = BTreeMap::new();
        for pr in &report.broken {
            attempted.push(pr.clone());
            if let Some(part) = by_path
                .get(pr.path.as_path())
                .and_then(|t| find_part(t, pr))
                && let Some((idx, range)) = patch_fetch(part, sources_len)
            {
                fetch.entry(idx).or_default().push(range);
            }
        }
        for path in &report.missing_files {
            if let Some(target) = by_path.get(path.as_path()) {
                for part in &target.parts {
                    attempted.push(PartRef::of(target, part));
                    if let Some((idx, range)) = patch_fetch(part, sources_len) {
                        fetch.entry(idx).or_default().push(range);
                    }
                }
            }
        }
        for ranges in fetch.values_mut() {
            merge_ranges(ranges);
        }

        // Fetch each patch's merged ranges into its buffer, counting the bytes served. Every buffer
        // is held for the whole pass, so peak memory is the sum of the fetched broken bytes: bounded
        // by the repair size (the point of block-level repair), not the tree size. A pathological
        // many-patch repair could stream per file instead; not worth the complexity at this scale.
        let mut bufs: Vec<RangeBuf> = (0..sources_len).map(|_| RangeBuf::default()).collect();
        let mut bytes_fetched: u64 = 0;
        for (idx, ranges) in &fetch {
            let slot = *idx as usize;
            source.read_ranges(PatchId(u32::from(*idx)), ranges, &mut |off, bytes| {
                bytes_fetched = bytes_fetched.saturating_add(bytes.len() as u64);
                bufs[slot].insert(off, bytes);
                Ok(())
            })?;
        }

        let mut outcome = RepairOutcome {
            bytes_fetched,
            ..RepairOutcome::default()
        };

        // Recreate missing files whole (all their parts are legitimately needed).
        for path in &report.missing_files {
            if let Some(target) = by_path.get(path.as_path()) {
                rebuild_missing(target, &mut bufs, &limits, sources_len, sink)?;
                outcome.recreated.push(target.path.clone());
            }
        }

        // Repair existing broken files in place, correcting a wrong length first so a short file is
        // pre-sized before its tail parts are rewritten.
        let size_fix: HashMap<&Path, u64> = report
            .size_mismatches
            .iter()
            .filter_map(|m| {
                by_path
                    .get(m.path.as_path())
                    .map(|t| (m.path.as_path(), t.final_len()))
            })
            .collect();
        let mut broken_by_path: BTreeMap<&Path, Vec<&PartRef>> = BTreeMap::new();
        for pr in &report.broken {
            broken_by_path
                .entry(pr.path.as_path())
                .or_default()
                .push(pr);
        }
        let mut resized: HashSet<&Path> = HashSet::new();
        for (path, prs) in &broken_by_path {
            let Some(target) = by_path.get(path) else {
                continue;
            };
            if !still_there(root, path)? {
                continue;
            }
            if let Some(&final_len) = size_fix.get(path) {
                sink.write(path, RepairWrite::Resize { len: final_len })?;
                outcome.resized.push(target.path.clone());
                resized.insert(*path);
            }
            for pr in prs {
                if let Some(part) = find_part(target, pr) {
                    repair_in_place(path, part, &mut bufs, &limits, sources_len, sink)?;
                }
            }
        }

        // Files that are only the wrong length (over-long, no broken parts): resize them.
        for m in &report.size_mismatches {
            let path = m.path.as_path();
            if resized.contains(path) {
                continue;
            }
            let Some(target) = by_path.get(path) else {
                continue;
            };
            if !still_there(root, path)? {
                continue;
            }
            sink.write(
                path,
                RepairWrite::Resize {
                    len: target.final_len(),
                },
            )?;
            outcome.resized.push(target.path.clone());
        }

        // Land the writes before reading the tree back, or a batching sink's re-verify reports every
        // part this pass repaired as still broken.
        sink.flush()?;

        // The single source of truth: re-verify only the attempted parts (re-reads what we wrote).
        let refined = self.verify(
            root,
            &VerifyOptions {
                parallelism: None,
                refine: Some(&attempted),
            },
        )?;
        let still: HashSet<PartRef> = refined.broken.into_iter().collect();
        for pr in attempted {
            if still.contains(&pr) {
                outcome.still_broken.push(pr);
            } else {
                outcome.repaired.push(pr);
            }
        }
        Ok(outcome)
    }

    /// The source patches this index references, in chain order, each tagged with its [`PatchId`].
    #[must_use]
    pub fn source_refs(&self) -> Vec<SourceRef<'_>> {
        self.sources
            .iter()
            .enumerate()
            .map(|(i, s)| SourceRef {
                id: PatchId(i as u32),
                name: &s.name,
                expected_len: s.expected_len,
            })
            .collect()
    }
}

/// The `(patch idx, source byte range)` a patch-backed `part` must fetch, or `None` when the part
/// needs no fetch (zeros/empty-block) or cannot be sourced (unavailable, a source index past the
/// list, or an overflowing range). A `None` from a patch part means repair soft-skips it and the
/// re-verify keeps it broken.
fn patch_fetch(part: &Part, sources_len: usize) -> Option<(u16, Range<u64>)> {
    let Source::Patch {
        idx,
        off,
        deflated,
        deflated_len,
        ..
    } = part.source
    else {
        return None;
    };
    if idx as usize >= sources_len {
        return None;
    }
    let read_len = if deflated {
        u64::from(deflated_len)
    } else {
        part.target_len
    };
    let end = off.checked_add(read_len)?;
    Some((idx, off..end))
}

/// Sort and coalesce a patch's fetch ranges, merging any two whose gap is strictly less than
/// [`GAP_MERGE`] (and all overlaps). Two broken parts split from one compressed block share an
/// identical range and collapse to one fetch here.
fn merge_ranges(ranges: &mut Vec<Range<u64>>) {
    ranges.sort_by_key(|r| r.start);
    let mut merged: Vec<Range<u64>> = Vec::with_capacity(ranges.len());
    for r in ranges.drain(..) {
        match merged.last_mut() {
            Some(cur) if r.start.saturating_sub(cur.end) < GAP_MERGE => {
                cur.end = cur.end.max(r.end);
            }
            _ => merged.push(r),
        }
    }
    *ranges = merged;
}

/// Whether the target is still on disk to be repaired in place.
///
/// A file that vanished between the verify and here is left alone: the re-verify re-breaks its parts
/// and the caller's next pass rebuilds it. Only `NotFound` means that. Anything else (a directory
/// that turned unreadable, a permission fault) is a real failure, and treating it as absence would
/// silently skip the file and then report it broken with no reason.
fn still_there(root: &Path, rel: &Path) -> Result<bool> {
    match fs::symlink_metadata(root.join(rel)) {
        Ok(_) => Ok(true),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(Error::io(e, Op::Open)),
    }
}

/// Rebuild a missing file whole: size it sparsely, then lay down each part's non-zero bytes. Zeros
/// stay sparse, an unsourceable part is skipped (the re-verify reports it), and a patch part is only
/// written when its fetched bytes match the indexed CRC.
fn rebuild_missing(
    target: &TargetFile,
    bufs: &mut [RangeBuf],
    limits: &codec::Limits,
    sources_len: usize,
    sink: &mut dyn RepairSink,
) -> Result<()> {
    let rel = target.path.as_path();
    sink.write(
        rel,
        RepairWrite::Create {
            len: target.final_len(),
        },
    )?;
    for part in &target.parts {
        match part.source {
            Source::Patch { .. } => {
                write_checked_patch(rel, part, bufs, limits, sources_len, sink)?;
            }
            Source::EmptyBlock {
                block_count,
                decoded_from,
            } => {
                if let Some(header) = reconstruct::empty_block_header_slice(
                    block_count,
                    decoded_from,
                    part.target_len,
                ) {
                    sink.write(
                        rel,
                        RepairWrite::Bytes {
                            off: part.target_off,
                            bytes: &header,
                        },
                    )?;
                }
            }
            // Sparse zero run (covered by the create's length) or an unsourceable part: nothing to
            // write.
            Source::Zeros | Source::Unavailable => {}
        }
    }
    Ok(())
}

/// Rewrite one broken part of an existing file. A patch part is materialized, CRC-checked, and
/// written only if the bytes are right; a zero run is explicitly overwritten (the on-disk bytes are
/// wrong, so the sparse trick does not apply); an empty-block run is zeroed then re-stamped with its
/// header; an unsourceable part is left for the re-verify.
fn repair_in_place(
    rel: &Path,
    part: &Part,
    bufs: &mut [RangeBuf],
    limits: &codec::Limits,
    sources_len: usize,
    sink: &mut dyn RepairSink,
) -> Result<()> {
    let zeros = RepairWrite::Zeros {
        off: part.target_off,
        len: part.target_len,
    };
    match part.source {
        Source::Patch { .. } => write_checked_patch(rel, part, bufs, limits, sources_len, sink)?,
        Source::Zeros => sink.write(rel, zeros)?,
        Source::EmptyBlock {
            block_count,
            decoded_from,
        } => {
            sink.write(rel, zeros)?;
            if let Some(header) =
                reconstruct::empty_block_header_slice(block_count, decoded_from, part.target_len)
            {
                sink.write(
                    rel,
                    RepairWrite::Bytes {
                        off: part.target_off,
                        bytes: &header,
                    },
                )?;
            }
        }
        Source::Unavailable => {}
    }
    Ok(())
}

/// Materialize a patch part through the fetched buffers and write it only if its bytes match the
/// indexed CRC. An unsourceable part (bad source index / overflowing range) and a CRC mismatch are
/// both soft skips: nothing is written, so the re-verify reports the part still broken. Shared by the
/// in-place and missing-file writers.
///
/// The CRC gate is where a part's bytes become the ones the index describes, so it is also the point
/// a sink that marshals writes elsewhere may treat them as proven: nothing past here is fetched
/// bytes, it is bytes the index vouches for.
///
/// A compressed block split across several broken parts is inflated once per part here (each slices
/// its own window); the whole-block decode is bounded by [`MAX_BLOCK_DECOMPRESSED`], and the split
/// case is rare, so a shared-block inflate cache is a deliberate non-goal.
fn write_checked_patch(
    rel: &Path,
    part: &Part,
    bufs: &mut [RangeBuf],
    limits: &codec::Limits,
    sources_len: usize,
    sink: &mut dyn RepairSink,
) -> Result<()> {
    if patch_fetch(part, sources_len).is_some() {
        let bytes = reconstruct::materialize_patch(part, bufs, limits)?;
        if crc32fast::hash(&bytes) == part.crc32 {
            sink.write(
                rel,
                RepairWrite::Bytes {
                    off: part.target_off,
                    bytes: &bytes,
                },
            )?;
        }
    }
    Ok(())
}

/// The part matching `pr` in `target`, found by target offset (the tiling is sorted and unique) and
/// confirmed by length. `None` when the report references a part the index does not hold.
fn find_part<'a>(target: &'a TargetFile, pr: &PartRef) -> Option<&'a Part> {
    let i = target
        .parts
        .binary_search_by(|p| p.target_off.cmp(&pr.target_off))
        .ok()?;
    let part = &target.parts[i];
    (part.target_len == pr.target_len).then_some(part)
}

/// A sparse in-memory view of one patch's fetched ranges, presented as `Read + Seek` so the reused
/// [`materialize_patch`](reconstruct::materialize_patch) pulls from it exactly as from a patch file.
/// The planner delivers non-overlapping ranges, so `read` finds the covering span by scan regardless
/// of insertion order (no sort needed); a read in a gap returns `Ok(0)`, and because each part's span
/// sits wholly inside one contiguous span that only ever signals a genuinely unfetched byte.
#[derive(Default)]
struct RangeBuf {
    spans: Vec<(u64, Vec<u8>)>,
    cursor: u64,
}

impl RangeBuf {
    /// Store a fetched span. Order is irrelevant (`read` scans for the covering span), so this is a
    /// plain append.
    fn insert(&mut self, off: u64, bytes: &[u8]) {
        if bytes.is_empty() {
            return;
        }
        self.spans.push((off, bytes.to_vec()));
    }
}

impl Read for RangeBuf {
    fn read(&mut self, dst: &mut [u8]) -> io::Result<usize> {
        if dst.is_empty() {
            return Ok(0);
        }
        for (start, data) in &self.spans {
            let end = start.saturating_add(data.len() as u64);
            if self.cursor >= *start && self.cursor < end {
                let from = (self.cursor - start) as usize;
                let n = dst.len().min(data.len() - from);
                dst[..n].copy_from_slice(&data[from..from + n]);
                self.cursor += n as u64;
                return Ok(n);
            }
        }
        Ok(0)
    }
}

impl Seek for RangeBuf {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        let cursor = match pos {
            SeekFrom::Start(o) => o,
            SeekFrom::Current(d) => {
                let base = i128::from(self.cursor) + i128::from(d);
                if base < 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "seek before start",
                    ));
                }
                base as u64
            }
            // The materializer only ever seeks from the start; End is never needed and never panics.
            SeekFrom::End(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "range buffer has no end",
                ));
            }
        };
        self.cursor = cursor;
        Ok(cursor)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chunk::Platform;
    use crate::index::model::SourcePatch;

    /// A source that delivers nothing: the tests using it plan no fetchable ranges, so it is never
    /// actually asked for bytes.
    struct NoSource;
    impl RangeSource for NoSource {
        fn read_ranges(
            &mut self,
            _patch: PatchId,
            _ranges: &[Range<u64>],
            _out: &mut dyn FnMut(u64, &[u8]) -> Result<()>,
        ) -> Result<()> {
            Ok(())
        }
    }

    fn patch_part(idx: u16, off: u64) -> Source {
        Source::Patch {
            idx,
            off,
            deflated: false,
            deflated_len: 0,
            block_dlen: 0,
            decoded_from: 0,
        }
    }

    #[test]
    fn an_unavailable_part_stays_still_broken_and_fetches_nothing() {
        let index = Index {
            repo_version: "v".to_owned(),
            platform: Platform::Win32,
            sources: Vec::new(),
            targets: vec![TargetFile {
                path: "hole.dat".into(),
                parts: vec![Part {
                    target_off: 0,
                    target_len: 64,
                    source: Source::Unavailable,
                    crc32: 0,
                    crc_valid: false,
                }],
            }],
        };
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("hole.dat"), vec![0xAAu8; 64]).unwrap();

        let report = index.verify(dir.path(), &VerifyOptions::default()).unwrap();
        assert_eq!(report.broken.len(), 1);

        let outcome = index.repair(dir.path(), &report, &mut NoSource).unwrap();
        assert_eq!(outcome.bytes_fetched, 0);
        assert_eq!(outcome.still_broken.len(), 1);
        assert!(outcome.repaired.is_empty());
        assert!(!outcome.is_complete());
    }

    #[test]
    fn a_missing_file_with_an_unavailable_part_is_recreated_but_reports_it_broken() {
        // A missing file whose index carries a sourceless zeros part and an unavailable part: repair
        // recreates the file (sized correctly, the zeros clean) yet reports the unavailable part still
        // broken, so a partial rebuild is honest rather than silently "complete".
        let index = Index {
            repo_version: "v".to_owned(),
            platform: Platform::Win32,
            sources: Vec::new(),
            targets: vec![TargetFile {
                path: "part.dat".into(),
                parts: vec![
                    Part {
                        target_off: 0,
                        target_len: 64,
                        source: Source::Zeros,
                        crc32: 0,
                        crc_valid: false,
                    },
                    Part {
                        target_off: 64,
                        target_len: 64,
                        source: Source::Unavailable,
                        crc32: 0,
                        crc_valid: false,
                    },
                ],
            }],
        };
        let dir = tempfile::tempdir().unwrap();
        // The file is absent, so verify reports it missing.
        let report = index.verify(dir.path(), &VerifyOptions::default()).unwrap();
        assert_eq!(report.missing_files.len(), 1);

        let outcome = index.repair(dir.path(), &report, &mut NoSource).unwrap();
        assert_eq!(outcome.recreated, vec![PathBuf::from("part.dat")]);
        assert_eq!(outcome.bytes_fetched, 0);
        // The zeros part heals; the unavailable part cannot and stays broken.
        assert_eq!(outcome.repaired.len(), 1);
        assert_eq!(outcome.still_broken.len(), 1);
        assert_eq!(outcome.still_broken[0].target_off, 64);
        assert!(!outcome.is_complete());
        // The file exists at its full length.
        let meta = std::fs::metadata(dir.path().join("part.dat")).unwrap();
        assert_eq!(meta.len(), 128);
    }

    #[test]
    fn the_planner_skips_overflowing_and_out_of_range_sources_without_panicking() {
        let index = Index {
            repo_version: "v".to_owned(),
            platform: Platform::Win32,
            sources: vec![SourcePatch {
                name: "p".to_owned(),
                expected_len: 0,
            }],
            targets: vec![TargetFile {
                path: "a.dat".into(),
                parts: vec![
                    // idx 0 is in range but the range overflows u64.
                    Part {
                        target_off: 0,
                        target_len: 1,
                        source: patch_part(0, u64::MAX),
                        crc32: 0,
                        crc_valid: false,
                    },
                    // idx 9 is past the one-entry source list.
                    Part {
                        target_off: 1,
                        target_len: 1,
                        source: patch_part(9, 0),
                        crc32: 0,
                        crc_valid: false,
                    },
                ],
            }],
        };
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a.dat"), [0xAAu8, 0xBB]).unwrap();

        let report = index.verify(dir.path(), &VerifyOptions::default()).unwrap();
        assert_eq!(report.broken.len(), 2);

        let outcome = index.repair(dir.path(), &report, &mut NoSource).unwrap();
        assert_eq!(outcome.bytes_fetched, 0);
        assert_eq!(outcome.still_broken.len(), 2);
        assert!(!outcome.is_complete());
    }

    #[test]
    fn range_buf_serves_bytes_across_adjacent_spans_and_zero_in_a_gap() {
        let mut buf = RangeBuf::default();
        // Two adjacent spans that together cover [10, 30); a gap follows at 30.
        buf.insert(10, &[1u8; 10]);
        buf.insert(20, &[2u8; 10]);

        // Read the whole [10, 30) window across the span seam: exactly 20 bytes arrive.
        buf.seek(SeekFrom::Start(10)).unwrap();
        let mut out = Vec::new();
        (&mut buf).take(20).read_to_end(&mut out).unwrap();
        assert_eq!(out.len(), 20);
        assert_eq!(&out[..10], &[1u8; 10]);
        assert_eq!(&out[10..], &[2u8; 10]);

        // A read starting inside the gap yields nothing.
        buf.seek(SeekFrom::Start(30)).unwrap();
        let mut empty = [0u8; 4];
        assert_eq!(buf.read(&mut empty).unwrap(), 0);
    }

    #[test]
    fn range_buf_serves_out_of_order_and_duplicate_spans() {
        // Spans inserted out of order still serve a contiguous window (read scans, no sort needed).
        let mut buf = RangeBuf::default();
        buf.insert(20, &[2u8; 10]);
        buf.insert(10, &[1u8; 10]);
        buf.seek(SeekFrom::Start(10)).unwrap();
        let mut out = Vec::new();
        (&mut buf).take(20).read_to_end(&mut out).unwrap();
        assert_eq!(out.len(), 20);
        assert_eq!(&out[..10], &[1u8; 10]);
        assert_eq!(&out[10..], &[2u8; 10]);

        // A duplicate span does not corrupt a covered read.
        let mut dup = RangeBuf::default();
        dup.insert(0, &[7u8; 8]);
        dup.insert(0, &[7u8; 8]);
        dup.seek(SeekFrom::Start(0)).unwrap();
        let mut o = [0u8; 8];
        assert_eq!(dup.read(&mut o).unwrap(), 8);
        assert_eq!(o, [7u8; 8]);
    }

    #[test]
    fn merge_ranges_coalesces_small_gaps_and_overlaps_but_keeps_wide_gaps() {
        // Sub-4-KiB gap and an overlap collapse; a gap of exactly 4 KiB stays split (strict `<`).
        let mut close = vec![0..10, 12..20, 18..30];
        merge_ranges(&mut close);
        assert_eq!(close, vec![0..30]);

        let mut identical = vec![100..200, 100..200];
        merge_ranges(&mut identical);
        assert_eq!(identical, vec![100..200]);

        let mut just_under = vec![0..10, 10 + GAP_MERGE - 1..10 + GAP_MERGE];
        merge_ranges(&mut just_under);
        assert_eq!(just_under.len(), 1, "a gap of {} merges", GAP_MERGE - 1);

        let mut exact = vec![0..10, 10 + GAP_MERGE..20 + GAP_MERGE];
        merge_ranges(&mut exact);
        assert_eq!(exact.len(), 2, "a gap of exactly {GAP_MERGE} stays split");

        // Unsorted input is sorted before merging; a far range stays separate.
        let mut unsorted = vec![5000..6000, 0..10, 8..20];
        merge_ranges(&mut unsorted);
        assert_eq!(unsorted, vec![0..20, 5000..6000]);
    }
}

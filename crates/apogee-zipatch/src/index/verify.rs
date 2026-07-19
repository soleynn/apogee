//! Verifying a live install against a block index. A [`TargetFile`]'s parts each pin a target byte
//! range: a patch part to a CRC32 of its final bytes, a zeros part to an all-zero run, an empty-block
//! part to the 24-byte header pattern. Verify reads each installed file once and checks its parts,
//! reporting broken parts, wrong-length files, missing files, and strays (files on disk the index
//! does not explain). The CRC sweep runs across files in parallel (`rayon`); the crate only reports,
//! and the patcher decides what to re-fetch or quarantine.

use std::collections::HashSet;
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

use rayon::prelude::*;

use crate::datfile;
use crate::error::{Error, Op, Result};
use crate::index::model::{Index, Part, Source, TargetFile};

/// Filenames verify never flags as strays: version/backup markers, intro movies, and the DXVK shader
/// cache the runner writes into the tree. A stray is excused when its name ends with one of these.
const STRAY_IGNORE_SUFFIXES: &[&str] = &[".ver", ".bck", ".bk2", ".dxvk-cache"];

/// Identifies one indexed part, for reporting a break or driving a `refine` re-check.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PartRef {
    pub path: PathBuf,
    pub target_off: u64,
    pub target_len: u64,
}

/// A file whose on-disk length disagrees with the index.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SizeMismatch {
    pub path: PathBuf,
    pub expected: u64,
    pub actual: u64,
}

/// A file present in the tree that no indexed target explains and no ignore rule excuses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StrayFile {
    pub path: PathBuf,
}

/// The outcome of a verify pass. A clean install yields every field empty.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct VerifyReport {
    pub broken: Vec<PartRef>,
    pub size_mismatches: Vec<SizeMismatch>,
    pub missing_files: Vec<PathBuf>,
    pub stray_files: Vec<StrayFile>,
}

impl VerifyReport {
    /// Whether the install matches the index with nothing to repair.
    #[must_use]
    pub fn is_clean(&self) -> bool {
        self.broken.is_empty()
            && self.size_mismatches.is_empty()
            && self.missing_files.is_empty()
            && self.stray_files.is_empty()
    }
}

/// How a verify pass runs.
#[derive(Debug, Default)]
pub struct VerifyOptions<'a> {
    /// Cap the CRC sweep at this many worker threads; `None` uses `rayon`'s default pool.
    pub parallelism: Option<usize>,
    /// Re-check only these parts (the retry loop, so attempt N+1 need not re-hash a healthy tree).
    /// When set, only `broken` is populated; missing/size/stray scanning is skipped.
    pub refine: Option<&'a [PartRef]>,
}

/// One file's verification result.
#[derive(Default)]
struct FileOutcome {
    missing: bool,
    size_mismatch: Option<SizeMismatch>,
    broken: Vec<PartRef>,
}

impl Index {
    /// Verify the install under `root` against this index.
    ///
    /// # Errors
    /// [`Error::Io`] on an unexpected filesystem fault (a missing file is a report entry, not an
    /// error).
    pub fn verify(&self, root: &Path, opts: &VerifyOptions<'_>) -> Result<VerifyReport> {
        let run = || match opts.refine {
            Some(refs) => self.verify_refine(root, refs),
            None => self.verify_full(root),
        };
        match opts.parallelism {
            Some(n) => match rayon::ThreadPoolBuilder::new().num_threads(n).build() {
                Ok(pool) => pool.install(run),
                // A pool that will not build is not worth failing a verify over: fall back to global.
                Err(_) => run(),
            },
            None => run(),
        }
    }

    /// The full pass: every file's parts, plus size/missing/stray scanning.
    fn verify_full(&self, root: &Path) -> Result<VerifyReport> {
        let outcomes: Vec<FileOutcome> = self
            .targets
            .par_iter()
            .map(|target| verify_file(target, root, None))
            .collect::<Result<Vec<_>>>()?;

        let mut report = VerifyReport::default();
        for (target, outcome) in self.targets.iter().zip(outcomes) {
            if outcome.missing {
                report.missing_files.push(target.path.clone());
            }
            report.size_mismatches.extend(outcome.size_mismatch);
            report.broken.extend(outcome.broken);
        }
        report.stray_files = self.strays(root)?;
        Ok(report)
    }

    /// The refine pass: re-check only the referenced parts, reporting those still broken.
    fn verify_refine(&self, root: &Path, refs: &[PartRef]) -> Result<VerifyReport> {
        let wanted: HashSet<&PartRef> = refs.iter().collect();
        let outcomes: Vec<FileOutcome> = self
            .targets
            .par_iter()
            .filter(|t| refs.iter().any(|r| r.path == t.path))
            .map(|target| verify_file(target, root, Some(&wanted)))
            .collect::<Result<Vec<_>>>()?;
        let mut report = VerifyReport::default();
        for outcome in outcomes {
            report.broken.extend(outcome.broken);
        }
        Ok(report)
    }

    /// Files under `root` that no indexed target claims and no ignore rule excuses.
    fn strays(&self, root: &Path) -> Result<Vec<StrayFile>> {
        let indexed: HashSet<&Path> = self.targets.iter().map(|t| t.path.as_path()).collect();
        let mut strays = Vec::new();
        let mut stack = vec![root.to_path_buf()];
        while let Some(dir) = stack.pop() {
            let entries = match std::fs::read_dir(&dir) {
                Ok(e) => e,
                Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
                Err(e) => return Err(io(e, Op::Read)),
            };
            for entry in entries {
                let entry = entry.map_err(|e| io(e, Op::Read))?;
                let path = entry.path();
                let meta = std::fs::symlink_metadata(&path).map_err(|e| io(e, Op::Read))?;
                let ty = meta.file_type();
                if ty.is_dir() {
                    stack.push(path);
                } else if ty.is_file() {
                    let rel = path.strip_prefix(root).unwrap_or(&path);
                    if !indexed.contains(rel) && !is_ignored(rel) {
                        strays.push(StrayFile {
                            path: rel.to_path_buf(),
                        });
                    }
                }
                // Symlinks are neither indexed nor swept here; the applier never plants one.
            }
        }
        strays.sort_by(|a, b| a.path.cmp(&b.path));
        Ok(strays)
    }
}

/// Verify one file's parts against the tree. `refine` restricts the check to referenced parts.
fn verify_file(
    target: &TargetFile,
    root: &Path,
    refine: Option<&HashSet<&PartRef>>,
) -> Result<FileOutcome> {
    let abs = root.join(&target.path);
    let mut file = match File::open(&abs) {
        Ok(f) => f,
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            // In a refine pass a vanished file re-breaks every referenced part; in a full pass it is
            // a single missing-file entry.
            return Ok(match refine {
                Some(wanted) => FileOutcome {
                    broken: referenced_parts(target, wanted),
                    ..FileOutcome::default()
                },
                None => FileOutcome {
                    missing: true,
                    ..FileOutcome::default()
                },
            });
        }
        Err(e) => return Err(io(e, Op::Open)),
    };

    let mut outcome = FileOutcome::default();
    if refine.is_none() {
        let len = file.metadata().map_err(|e| io(e, Op::Read))?.len();
        if len != target.final_len() {
            outcome.size_mismatch = Some(SizeMismatch {
                path: target.path.clone(),
                expected: target.final_len(),
                actual: len,
            });
        }
    }

    let mut buf = vec![0u8; VERIFY_CHUNK];
    for part in &target.parts {
        if let Some(wanted) = refine
            && !wanted.contains(&part_ref(target, part))
        {
            continue;
        }
        if !verify_part(&mut file, part, &mut buf)? {
            outcome.broken.push(part_ref(target, part));
        }
    }
    Ok(outcome)
}

/// The chunk size for streaming a part through its check.
const VERIFY_CHUNK: usize = 1 << 16;

/// Check one part's on-disk bytes: CRC32 for a patch part, all-zero for a zeros part, the header
/// pattern for an empty block. Returns `false` when the bytes are wrong or the file runs short; an
/// unexpected read error propagates.
fn verify_part(file: &mut File, part: &Part, buf: &mut [u8]) -> Result<bool> {
    file.seek(SeekFrom::Start(part.target_off))
        .map_err(|e| io(e, Op::Read))?;

    match part.source {
        Source::Patch { .. } => {
            let mut hasher = crc32fast::Hasher::new();
            let ok = stream_part(file, part.target_len, buf, |chunk, _| {
                hasher.update(chunk);
                true
            })?;
            Ok(ok && hasher.finalize() == part.crc32)
        }
        Source::Zeros => stream_part(file, part.target_len, buf, |chunk, _| {
            chunk.iter().all(|&b| b == 0)
        }),
        Source::EmptyBlock {
            block_count,
            decoded_from,
        } => {
            let header = datfile::empty_block_header(block_count);
            stream_part(file, part.target_len, buf, |chunk, region_pos| {
                chunk.iter().enumerate().all(|(i, &b)| {
                    // `decoded_from` comes from a possibly-hostile index; saturate so a huge value
                    // lands past the 24-byte header (expected zero) instead of overflowing.
                    let abs = decoded_from
                        .saturating_add(region_pos)
                        .saturating_add(i as u64);
                    let expected = if abs < header.len() as u64 {
                        header[abs as usize]
                    } else {
                        0
                    };
                    b == expected
                })
            })
        }
        // A part with no known source cannot be verified; treat it as broken.
        Source::Unavailable => Ok(false),
    }
}

/// Read `len` bytes from `file` in chunks, calling `check(chunk, offset_into_part)` on each. Returns
/// `false` if a check fails or the file runs short before `len` bytes.
fn stream_part(
    file: &mut File,
    len: u64,
    buf: &mut [u8],
    mut check: impl FnMut(&[u8], u64) -> bool,
) -> Result<bool> {
    let mut remaining = len;
    let mut pos = 0u64;
    while remaining > 0 {
        let want = remaining.min(buf.len() as u64) as usize;
        match file.read(&mut buf[..want]) {
            Ok(0) => return Ok(false), // short file
            Ok(n) => {
                if !check(&buf[..n], pos) {
                    return Ok(false);
                }
                pos += n as u64;
                remaining -= n as u64;
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(io(e, Op::Read)),
        }
    }
    Ok(true)
}

fn part_ref(target: &TargetFile, part: &Part) -> PartRef {
    PartRef {
        path: target.path.clone(),
        target_off: part.target_off,
        target_len: part.target_len,
    }
}

/// Every part of `target` that the refine set references (for a file that vanished).
fn referenced_parts(target: &TargetFile, wanted: &HashSet<&PartRef>) -> Vec<PartRef> {
    target
        .parts
        .iter()
        .map(|p| part_ref(target, p))
        .filter(|r| wanted.contains(r))
        .collect()
}

/// Whether a stray filename is excused by the compiled-in ignore list.
fn is_ignored(rel: &Path) -> bool {
    rel.file_name()
        .and_then(|n| n.to_str())
        .is_some_and(|name| STRAY_IGNORE_SUFFIXES.iter().any(|s| name.ends_with(s)))
}

fn io(source: std::io::Error, during: Op) -> Error {
    Error::Io {
        source,
        target: None,
        during,
    }
}

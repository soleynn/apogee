//! [`DiskSink`]: the [`PatchSink`] that applies a patch to a game tree on disk.
//!
//! Every path a patch names is confined before it reaches here (only a [`TargetPath`]/[`SafePath`]
//! can be constructed), so this layer's remaining defense is against a symlink planted *inside* the
//! tree. Both writes and deletes descend the same way ([`ensure_dirs`]): every directory component is
//! stat'd one at a time and refused if it is a symlink or a non-directory, so a planted link can never
//! relocate an operation outside the root. Writes also strip a symlink squatting the final component;
//! `remove_dir` refuses a symlinked target so a recursive delete cannot follow it out of the tree.
//!
//! This is a lexical-then-stat confinement: a concurrent *local* writer could still race a component
//! between the stat and the following open/unlink/remove. A hostile patch cannot (no apply op plants a
//! symlink); a fully race-free descent would need `openat`-relative traversal from a root fd, deferred.
//!
//! Writes are positioned (seek + write), so re-running an interrupted apply converges. Boot patches
//! touch the same handful of files repeatedly, so open handles are held in a small LRU store rather
//! than reopened per command. Handles carry no application-level buffer, so eviction is a plain close.
//!
//! Every open here is retried for a moment while something else is holding the file ([`BUSY_CODES`]),
//! because the alternative is a patch that dies part-applied over a scanner that touched a dat for
//! fifty milliseconds.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

use apogee_sqpack::codec;

use crate::chunk::expansion_folder;
use crate::datfile;
use crate::error::{Error, Limit, Op, Result};
use crate::seam::{
    DataSource, KeepFilter, PatchSink, RepairSink, RepairWrite, SafePath, TargetPath,
};

/// How many target handles to hold open at once. Boot writes a handful of files; game patches touch
/// more, but a small cache already erases the open/close churn that dominates a naive applier.
const OPEN_HANDLE_CAP: usize = 16;

/// The decode cap for one `F:A` block. Comfortably clears real file-add blocks while still bounding a
/// hostile `decompressed_size` claim.
///
/// Deliberately looser than [`codec::DEFAULT_MAX_DECOMPRESSED`], which is the reader's bound on a
/// SqPack *data* block; this is the patch side's bound on the same format, set where no real chain
/// reaches it. It lives here, once, because every path in this crate that decodes a block has to
/// agree on it: the apply engine, the index build, the reconstruct and the repair all read this
/// constant, and a second copy would let the apply path and the repair path disagree about the same
/// bytes without anything saying so.
pub(crate) const MAX_BLOCK_DECOMPRESSED: u32 = 16 << 20;

/// The cap on a single zero-fill (an `A` delete-tail or a `D`/`E` empty-block span). It clears any
/// real dat-scale wipe or expand with room to spare while rejecting the pathological ~512 GiB span a
/// hostile `u32` block count could claim, so a corrupt length is a typed error, not a disk-filling
/// loop.
const MAX_WIPE_BYTES: u64 = 8 << 30;

/// The reused buffer size for a zero-fill: written once, reused across the run, so a large wipe is a
/// handful of large writes rather than a syscall per few kilobytes.
const WIPE_CHUNK: usize = 1 << 16;

/// The OS error codes that mean an open failed because something else is holding the file, so it is
/// worth waiting out rather than failing the run.
///
/// Windows raises `ERROR_SHARING_VIOLATION` (32) or `ERROR_LOCK_VIOLATION` (33) when the game, a
/// backup agent, or a virus scanner has a target open for the moment the applier wants it. The list
/// is empty everywhere else: no code refuses an open here for that reason, and 32 and 33 are `EPIPE`
/// and `EDOM`, so reading them as a hold would retry faults that are not one. That per-platform split
/// is why this is a table and not a match on a number.
#[cfg(windows)]
const BUSY_CODES: &[i32] = &[32, 33];
#[cfg(not(windows))]
const BUSY_CODES: &[i32] = &[];

/// How many attempts past the first an open gets while a hold refuses it.
const OPEN_RETRIES: u32 = 5;

/// The wait before the first retry; each attempt after doubles it. Five retries from 20 ms span
/// 620 ms in total, which covers the brief hold a scanner takes on a file the applier just wrote
/// without making a genuinely locked target stall the run for long.
const OPEN_BACKOFF: Duration = Duration::from_millis(20);

/// Applies a patch to a game tree rooted at a directory. Construct with [`DiskSink::new`], hand it to
/// [`crate::apply`].
pub struct DiskSink {
    root: PathBuf,
    store: HandleStore,
    limits: codec::Limits,
}

impl DiskSink {
    /// Create a sink writing under `root`, creating the root if absent.
    ///
    /// # Errors
    /// [`Error::Io`] if `root` cannot be created.
    pub fn new(root: impl Into<PathBuf>) -> Result<Self> {
        let root = root.into();
        fs::create_dir_all(&root).map_err(|e| io(e, root.clone(), Op::MakeDir))?;
        Ok(Self {
            root,
            store: HandleStore::new(OPEN_HANDLE_CAP),
            limits: codec::Limits {
                max_decompressed: MAX_BLOCK_DECOMPRESSED,
            },
        })
    }
}

impl PatchSink for DiskSink {
    fn write(&mut self, target: &TargetPath, off: u64, src: DataSource<'_>) -> Result<()> {
        let rel = target.as_path();
        let limits = self.limits;
        match src {
            DataSource::Raw { bytes, .. } => {
                let file = self.store.get(&self.root, rel)?;
                write_at(file, off, bytes, &self.root, rel)?;
            }
            DataSource::Deflate {
                bytes,
                decompressed_len,
                patch_off,
                ..
            } => {
                let file = self.store.get(&self.root, rel)?;
                seek(file, off, &self.root, rel)?;
                // inflate checks the size cap before decoding, so a hostile header never allocates.
                codec::inflate(bytes, file, decompressed_len, &limits).map_err(|e| {
                    Error::from_block(e, patch_off, decompressed_len, limits.max_decompressed)
                })?;
            }
            // An `A` command's plain delete-tail wipe: zero `len` bytes at `off`, no header.
            DataSource::Zeros { len } => {
                let file = self.store.get(&self.root, rel)?;
                write_zeros(file, off, len, &self.root, rel)?;
            }
        }
        Ok(())
    }

    fn write_empty_block(&mut self, target: &TargetPath, off: u64, blocks: u32) -> Result<()> {
        let rel = target.as_path();
        let wipe_len = u64::from(blocks) << 7;
        check_wipe(wipe_len, MAX_WIPE_BYTES)?;
        // `off` is a `u32 << 7` (≤ 2^39) and `wipe_len` a `u32 << 7` (≤ 2^39), so the span cannot
        // overflow a `u64`.
        let end = off + wipe_len;
        let file = self.store.get(&self.root, rel)?;
        let cur = file
            .metadata()
            .map_err(|e| io(e, self.root.join(rel), Op::Read))?
            .len();
        // Only the portion of the run that overlaps existing bytes must be written as explicit zeros
        // (to overwrite prior data). A tail past the current end of file is grown with a sparse
        // `set_len`: it reads back as zeros, so the file content is byte-identical to the reference's
        // explicit wipe while a large `E` expand writes no zero bytes at all.
        let overlap_end = end.min(cur);
        if overlap_end > off {
            write_zeros(file, off, overlap_end - off, &self.root, rel)?;
        }
        if end > cur {
            file.set_len(end)
                .map_err(|e| io(e, self.root.join(rel), Op::Truncate))?;
        }
        // Stamp the 24-byte header over the run's start.
        write_at(
            file,
            off,
            &datfile::empty_block_header(blocks),
            &self.root,
            rel,
        )
    }

    fn truncate(&mut self, target: &TargetPath, len: u64) -> Result<()> {
        let rel = target.as_path();
        let file = self.store.get(&self.root, rel)?;
        file.set_len(len)
            .map_err(|e| io(e, self.root.join(rel), Op::Truncate))
    }

    fn remove_file(&mut self, target: &TargetPath) -> Result<()> {
        let rel = target.as_path();
        self.store.evict(rel);
        // Refuse a symlinked ancestor before touching the tree; a missing ancestor means the target is
        // already gone. `remove_file` on the final component unlinks a symlink itself (never follows
        // it), so only the parents need the symlink check.
        if ensure_dirs(&self.root, parent_of(rel), false)?.is_none() {
            return Ok(());
        }
        let abs = self.root.join(rel);
        match fs::remove_file(&abs) {
            Ok(()) => Ok(()),
            // A delete of a file that was never created is a no-op (as `File.Delete` is), regardless
            // of any ignore-missing flag: boot patches delete files earlier links never laid down.
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(io(e, abs, Op::Remove)),
        }
    }

    fn remove_expansion(&mut self, expansion: u16, keep: &KeepFilter) -> Result<()> {
        // The reference narrows the id to a byte before naming the folder, so ids past 255 fold onto
        // the base game. Both the archive and movie subtrees are swept, immediate files only.
        let folder = expansion_folder(expansion as u8);
        for sub in ["sqpack", "movie"] {
            let dir_rel = Path::new(sub).join(&folder);
            // A missing subtree is nothing to remove; a symlinked component is refused by ensure_dirs.
            let Some(abs) = ensure_dirs(&self.root, &dir_rel, false)? else {
                continue;
            };
            let entries = fs::read_dir(&abs).map_err(|e| io(e, abs.clone(), Op::Read))?;
            for entry in entries {
                let entry = entry.map_err(|e| io(e, abs.clone(), Op::Read))?;
                let name = entry.file_name();
                let path = entry.path();
                let meta =
                    fs::symlink_metadata(&path).map_err(|e| io(e, path.clone(), Op::Read))?;
                // Non-recursive, files only: a subdirectory is left alone, matching `GetFiles`.
                if meta.is_dir() || keep.is_kept(&name.to_string_lossy()) {
                    continue;
                }
                self.store.evict(&dir_rel.join(&name));
                // Unlink the entry; a symlink is removed as the link itself, never followed.
                fs::remove_file(&path).map_err(|e| io(e, path, Op::Remove))?;
            }
        }
        Ok(())
    }

    fn make_dir_tree(&mut self, rel: &SafePath) -> Result<()> {
        ensure_dirs(&self.root, rel.as_path(), true)?;
        Ok(())
    }

    fn remove_dir(&mut self, rel: &SafePath) -> Result<()> {
        let rel = rel.as_path();
        if ensure_dirs(&self.root, parent_of(rel), false)?.is_none() {
            return Ok(());
        }
        let abs = self.root.join(rel);
        match fs::symlink_metadata(&abs) {
            // A symlinked target could redirect the recursive delete outside the tree; refuse it.
            Ok(meta) if meta.file_type().is_symlink() => Err(Error::PathEscape {
                raw: abs.display().to_string(),
            }),
            Ok(_) => match fs::remove_dir_all(&abs) {
                Ok(()) => Ok(()),
                Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
                Err(e) => Err(io(e, abs, Op::Remove)),
            },
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(io(e, abs, Op::Remove)),
        }
    }

    /// Preallocate `len` bytes for a fresh target (Linux only; the default no-op covers other
    /// targets). `KEEP_SIZE` reserves blocks without changing the logical length, so the bytes the
    /// apply writes are identical whether or not the reservation happened. A filesystem that cannot
    /// preallocate (tmpfs, some network mounts) returns an error that is deliberately ignored: a
    /// best-effort hint must never fail an otherwise-valid apply.
    #[cfg(target_os = "linux")]
    fn reserve(&mut self, target: &TargetPath, len: u64) -> Result<()> {
        let rel = target.as_path();
        let file = self.store.get(&self.root, rel)?;
        let _ = rustix::fs::fallocate(&*file, rustix::fs::FallocateFlags::KEEP_SIZE, 0, len);
        Ok(())
    }
}

/// Applies a repair's writes to a game tree on disk: the [`RepairSink`] behind
/// [`Index::repair`](crate::Index::repair).
///
/// It descends the same way [`DiskSink`] does, so the two agree about what a planted link may do: no
/// directory component may be a symlink, and a link squatting the final component is stripped before
/// a rebuild and refused before an in-place write. Refused rather than stripped there because an
/// in-place repair rewrites part of a file it is not otherwise replacing, and unlinking one to break
/// the link would throw away the bytes the repair was about to keep.
///
/// One handle is held across the writes for a file, which is all the caching the write order needs:
/// every write for a target is issued before the next target's.
pub struct DiskRepairSink {
    root: PathBuf,
    open: Option<Open>,
}

/// The target currently being written, and the handle for it.
struct Open {
    rel: PathBuf,
    file: File,
}

impl DiskRepairSink {
    /// Write repairs into the tree at `root`. The tree must already exist; a repair heals an
    /// install, it does not create one.
    #[must_use]
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self {
            root: root.into(),
            open: None,
        }
    }

    /// The handle for `rel`, opening it on a change of target. `create` distinguishes the rebuild of
    /// a missing file from a write into one that is there.
    fn handle<'a>(
        root: &Path,
        open: &'a mut Option<Open>,
        rel: &Path,
        create: bool,
    ) -> Result<&'a mut File> {
        // A rebuild always reopens: it truncates, and a cached handle from an earlier write to the
        // same path would leave the sink writing into the file it just replaced.
        if create || !open.as_ref().is_some_and(|slot| slot.rel == rel) {
            let file = if create {
                open_rebuilt(root, rel)?
            } else {
                open_existing(root, rel)?
            };
            return Ok(&mut open
                .insert(Open {
                    rel: rel.to_path_buf(),
                    file,
                })
                .file);
        }
        match open.as_mut() {
            Some(slot) => Ok(&mut slot.file),
            // Unreachable: the branch above fills the slot whenever it is empty.
            None => Err(Error::Corrupt {
                offset: 0,
                detail: "the repair sink lost its open target",
            }),
        }
    }
}

impl RepairSink for DiskRepairSink {
    fn write(&mut self, target: &Path, write: RepairWrite<'_>) -> Result<()> {
        let Self { root, open } = self;
        let create = matches!(write, RepairWrite::Create { .. });
        let file = Self::handle(root, open, target, create)?;
        match write {
            RepairWrite::Create { len } | RepairWrite::Resize { len } => file
                .set_len(len)
                .map_err(|e| io(e, root.join(target), Op::Truncate)),
            RepairWrite::Bytes { off, bytes } => write_at(file, off, bytes, root, target),
            RepairWrite::Zeros { off, len } => write_zeros(file, off, len, root, target),
        }
    }

    /// Drop the open handle. The writes themselves are already on their way to disk (nothing here
    /// buffers), so this only releases the file before the caller re-reads it.
    fn flush(&mut self) -> Result<()> {
        self.open = None;
        Ok(())
    }
}

/// Open `root/rel` for an in-place repair: parents symlink-safely, the file itself refused if it is a
/// link, and no create (a target that is gone is the caller's to notice).
fn open_existing(root: &Path, rel: &Path) -> Result<File> {
    ensure_dirs(root, parent_of(rel), false)?;
    let abs = root.join(rel);
    refuse_symlink(&abs)?;
    open_waiting(OpenOptions::new().write(true), &abs)
}

/// Open `root/rel` for a rebuild: parents created, a link at the final component stripped, and the
/// file truncated to start from nothing.
///
/// The root is created too, which the descent below cannot do: it walks the components beneath the
/// root and so can only ever start from one that is there. A repair whose whole subtree is gone
/// reports every file missing and rebuilds each one, and that is the case where the root is the
/// directory that has to be made.
fn open_rebuilt(root: &Path, rel: &Path) -> Result<File> {
    fs::create_dir_all(root).map_err(|e| io(e, root.to_path_buf(), Op::MakeDir))?;
    ensure_dirs(root, parent_of(rel), true)?;
    let abs = root.join(rel);
    unlink_if_symlink(&abs)?;
    open_waiting(
        OpenOptions::new().write(true).create(true).truncate(true),
        &abs,
    )
}

/// Whether `raw` is one of the codes in `busy`. Takes the table rather than reading [`BUSY_CODES`],
/// so the rule can be exercised against both platforms' tables wherever the tests run.
fn is_busy(busy: &[i32], raw: Option<i32>) -> bool {
    raw.is_some_and(|code| busy.contains(&code))
}

/// Run `attempt` until it stops failing with a hold, up to [`OPEN_RETRIES`] extra tries, waiting
/// `backoff` before the first retry and doubling it after each.
///
/// Anything that is not a hold returns on the first try, so on a platform whose `busy` table is empty
/// this is exactly one call to `attempt` and the behavior is unchanged. `backoff` is a parameter
/// rather than the constant so the tests can drive the loop without sleeping through it.
fn retry_while_busy<T>(
    busy: &[i32],
    backoff: Duration,
    mut attempt: impl FnMut() -> io::Result<T>,
) -> io::Result<T> {
    let mut wait = backoff;
    for _ in 0..OPEN_RETRIES {
        match attempt() {
            Err(e) if is_busy(busy, e.raw_os_error()) => {
                std::thread::sleep(wait);
                wait *= 2;
            }
            settled => return settled,
        }
    }
    // The last try's fault is the one the caller sees, hold or not.
    attempt()
}

/// Open `abs` with `opts`, waiting out a hold. The shared tail of every open in this module, so the
/// apply store and both repair opens agree about what is worth retrying.
fn open_waiting(opts: &OpenOptions, abs: &Path) -> Result<File> {
    retry_while_busy(BUSY_CODES, OPEN_BACKOFF, || opts.open(abs))
        .map_err(|e| io(e, abs.to_path_buf(), Op::Open))
}

/// Refuse `path` if it is a symlink, so an in-place write never lands through one.
fn refuse_symlink(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_symlink() => Err(Error::PathEscape {
            raw: path.display().to_string(),
        }),
        _ => Ok(()),
    }
}

/// The parent of `rel`, or the empty path (an empty component walk) when `rel` is a single component.
fn parent_of(rel: &Path) -> &Path {
    rel.parent().unwrap_or(Path::new(""))
}

/// Reject a wipe/expand span past the dat-scale cap, so a corrupt length is a typed error rather than
/// a disk-filling write (or a huge sparse extend).
fn check_wipe(len: u64, max: u64) -> Result<()> {
    if len > max {
        return Err(Error::LimitExceeded {
            what: Limit::FileSize,
            value: len,
            max,
        });
    }
    Ok(())
}

/// Write `len` zero bytes at `off`, capped by [`MAX_WIPE_BYTES`]. One [`WIPE_CHUNK`] buffer is zeroed
/// once and rewritten, so a large wipe is a few big writes, not a syscall per few kilobytes, and it
/// never allocates proportionally to `len`.
fn write_zeros(file: &mut File, off: u64, len: u64, root: &Path, rel: &Path) -> Result<()> {
    check_wipe(len, MAX_WIPE_BYTES)?;
    seek(file, off, root, rel)?;
    // Cap the buffer at the smaller of the run and the chunk; the `min` in `u64` keeps the cast safe.
    let cap = len.min(WIPE_CHUNK as u64) as usize;
    let zeros = vec![0u8; cap];
    let mut remaining = len;
    while remaining > 0 {
        let n = remaining.min(cap as u64) as usize;
        file.write_all(&zeros[..n])
            .map_err(|e| io(e, root.join(rel), Op::Write))?;
        remaining -= n as u64;
    }
    Ok(())
}

/// A bounded LRU of open target handles. The most recently used slot is at the end; a miss opens a
/// fresh handle and evicts the front when full.
struct HandleStore {
    open: Vec<Slot>,
    cap: usize,
}

struct Slot {
    rel: PathBuf,
    file: File,
}

impl HandleStore {
    fn new(cap: usize) -> Self {
        Self {
            open: Vec::new(),
            cap,
        }
    }

    /// A read/write handle for `root/rel`, opening it (parents first, symlink-safely) on a miss.
    /// Never truncates: only the explicit `truncate` op does, so a re-opened continuation keeps the
    /// bytes an earlier command wrote.
    fn get(&mut self, root: &Path, rel: &Path) -> Result<&mut File> {
        if let Some(idx) = self.open.iter().position(|s| s.rel == rel) {
            let slot = self.open.remove(idx);
            self.open.push(slot);
            let last = self.open.len() - 1;
            return Ok(&mut self.open[last].file);
        }
        let file = open_target(root, rel)?;
        if self.open.len() >= self.cap {
            self.open.remove(0);
        }
        self.open.push(Slot {
            rel: rel.to_path_buf(),
            file,
        });
        let last = self.open.len() - 1;
        Ok(&mut self.open[last].file)
    }

    /// Drop any cached handle for `rel` (before an unlink, so no open fd lingers).
    fn evict(&mut self, rel: &Path) {
        self.open.retain(|s| s.rel != rel);
    }
}

/// Open `root/rel` read/write, creating it and its parents. Never truncates.
fn open_target(root: &Path, rel: &Path) -> Result<File> {
    ensure_dirs(root, parent_of(rel), true)?;
    let abs = root.join(rel);
    unlink_if_symlink(&abs)?;
    open_waiting(
        OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            // Never truncate on open: a continuation `F:A` (offset > 0) or a re-opened evicted handle
            // must keep the bytes an earlier command wrote. Only the explicit `truncate` op clears a
            // file.
            .truncate(false),
        &abs,
    )
}

/// Walk each directory component of `dirs` under `root`, refusing any that is a symlink or a
/// non-directory (a planted link would relocate a following write or delete outside the tree). With
/// `create`, a missing component is made (the write path); without it, a missing component ends the
/// walk with `None` (the delete path, where a missing ancestor means the target is already gone).
/// `dirs` is already confined, so only `Normal` components reach here. Returns the resolved absolute
/// path on success.
fn ensure_dirs(root: &Path, dirs: &Path, create: bool) -> Result<Option<PathBuf>> {
    let mut cur = root.to_path_buf();
    for comp in dirs.components() {
        cur.push(comp.as_os_str());
        match fs::symlink_metadata(&cur) {
            Ok(meta) if meta.is_dir() => {}
            Ok(_) => {
                return Err(Error::PathEscape {
                    raw: cur.display().to_string(),
                });
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                if create {
                    fs::create_dir(&cur).map_err(|e| io(e, cur.clone(), Op::MakeDir))?;
                } else {
                    return Ok(None);
                }
            }
            Err(e) => return Err(io(e, cur, Op::MakeDir)),
        }
    }
    Ok(Some(cur))
}

/// Remove `path` if it is an existing symlink, so a write never follows a link planted at the final
/// component.
fn unlink_if_symlink(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_symlink() => {
            fs::remove_file(path).map_err(|e| io(e, path.to_path_buf(), Op::Remove))
        }
        _ => Ok(()),
    }
}

/// Seek a handle to `off`, tagging a failure with the absolute target path (computed only on error).
fn seek(file: &mut File, off: u64, root: &Path, rel: &Path) -> Result<()> {
    file.seek(SeekFrom::Start(off))
        .map(|_| ())
        .map_err(|e| io(e, root.join(rel), Op::Write))
}

/// Write `buf` at `off`.
fn write_at(file: &mut File, off: u64, buf: &[u8], root: &Path, rel: &Path) -> Result<()> {
    seek(file, off, root, rel)?;
    file.write_all(buf)
        .map_err(|e| io(e, root.join(rel), Op::Write))
}

/// Build an [`Error::Io`] carrying the target path and the operation in flight.
fn io(source: io::Error, target: PathBuf, during: Op) -> Error {
    Error::Io {
        source,
        target: Some(target),
        during,
    }
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;

    use super::*;

    /// Both platforms' tables run here whichever platform the tests run on, which is the point of
    /// passing the table in: CI never executes a Windows binary, so a rule that read the constant
    /// directly would only ever be checked on the arm where it does nothing.
    #[test]
    fn a_hold_is_a_hold_only_under_the_table_that_names_its_code() {
        let windows: &[i32] = &[32, 33];
        for code in [32, 33] {
            assert!(is_busy(windows, Some(code)));
            assert!(!is_busy(&[], Some(code)));
        }
        // 32 and 33 are `EPIPE` and `EDOM` off Windows, and this module opens paths that can be
        // pipes, so the same numbers must not read as a hold under an empty table. Permission denied
        // and a failure with no OS code behind it are never holds under either.
        for raw in [Some(5), Some(13), None] {
            assert!(!is_busy(windows, raw));
            assert!(!is_busy(&[], raw));
        }
    }

    /// The table this module actually compiles with, which is the one thing the rule above cannot
    /// check about itself.
    #[test]
    fn the_table_holds_the_codes_this_platform_refuses_an_open_with() {
        if cfg!(windows) {
            assert_eq!(BUSY_CODES, [32, 33]);
        } else {
            assert!(
                BUSY_CODES.is_empty(),
                "no code refuses an open here for a hold, and 32 and 33 are EPIPE and EDOM"
            );
        }
    }

    /// An attempt that fails `holds` times with a busy code and then succeeds, counting the calls.
    fn holding(holds: &Cell<u32>) -> impl FnMut() -> io::Result<&'static str> + '_ {
        move || match holds.get() {
            0 => Ok("open"),
            n => {
                holds.set(n - 1);
                Err(io::Error::from_raw_os_error(32))
            }
        }
    }

    #[test]
    fn an_open_a_hold_refuses_is_retried_until_it_lands() {
        let holds = Cell::new(3);
        let got = retry_while_busy(&[32], Duration::ZERO, holding(&holds));
        assert_eq!(got.expect("the fourth try opens"), "open");
        assert_eq!(holds.get(), 0, "every hold was waited out");
    }

    #[test]
    fn a_hold_that_outlives_the_budget_surfaces_as_itself() {
        let calls = Cell::new(0u32);
        let got: io::Result<()> = retry_while_busy(&[32], Duration::ZERO, || {
            calls.set(calls.get() + 1);
            Err(io::Error::from_raw_os_error(32))
        });
        assert_eq!(got.expect_err("still held").raw_os_error(), Some(32));
        // The retries plus the last try, and nothing swallowed the fault into a different one.
        assert_eq!(calls.get(), OPEN_RETRIES + 1);
    }

    #[test]
    fn a_fault_that_is_not_a_hold_is_not_retried() {
        let calls = Cell::new(0u32);
        let got: io::Result<()> = retry_while_busy(&[32], Duration::ZERO, || {
            calls.set(calls.get() + 1);
            Err(io::Error::from_raw_os_error(13)) // permission denied
        });
        assert_eq!(got.expect_err("denied").raw_os_error(), Some(13));
        assert_eq!(calls.get(), 1, "a denial is not something to wait out");
    }

    #[test]
    fn an_empty_table_makes_the_loop_one_call() {
        // The arm every non-Windows build takes: the retry is compiled in but never engages, so an
        // open costs exactly what it did before.
        let calls = Cell::new(0u32);
        let got: io::Result<()> = retry_while_busy(&[], Duration::ZERO, || {
            calls.set(calls.get() + 1);
            Err(io::Error::from_raw_os_error(32))
        });
        assert!(got.is_err());
        assert_eq!(calls.get(), 1);
    }
}

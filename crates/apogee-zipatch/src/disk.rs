//! [`DiskSink`]: the [`PatchSink`] that applies a patch to a game tree on disk.
//!
//! Every path a patch names is confined before it reaches here (only a [`TargetPath`]/[`SafePath`]
//! can be constructed), so this layer's remaining defense is against a symlink planted *inside* the
//! tree: parent directories are created one component at a time, refusing to traverse a symlink, and
//! a symlink squatting the final path component is removed before a write. Writes are positioned
//! (seek + write), so re-running an interrupted apply converges.
//!
//! Boot patches touch the same handful of files repeatedly, so open handles are held in a small LRU
//! store rather than reopened per command. Handles carry no application-level buffer, so eviction is
//! a plain close with nothing to lose.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use apogee_sqpack::codec;

use crate::error::{Error, Op, Result};
use crate::seam::{DataSource, KeepFilter, PatchSink, SafePath, TargetPath};

/// How many target handles to hold open at once. Boot writes a handful of files; game patches touch
/// more, but a small cache already erases the open/close churn that dominates a naive applier.
const OPEN_HANDLE_CAP: usize = 16;

/// The decode cap for one `F:A` block. Comfortably clears real file-add blocks while still bounding a
/// hostile `decompressed_size` claim.
const MAX_BLOCK_DECOMPRESSED: u32 = 16 << 20;

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
                write_at(file, off, bytes, rel)?;
            }
            DataSource::Deflate {
                bytes,
                decompressed_len,
                patch_off,
                ..
            } => {
                let file = self.store.get(&self.root, rel)?;
                seek(file, off, rel)?;
                // inflate checks the size cap before decoding, so a hostile header never allocates.
                codec::inflate(bytes, file, decompressed_len, &limits).map_err(|e| {
                    Error::from_block(e, patch_off, decompressed_len, limits.max_decompressed)
                })?;
            }
            DataSource::Zeros { len } => {
                let file = self.store.get(&self.root, rel)?;
                write_zeros(file, off, len, rel)?;
            }
        }
        Ok(())
    }

    fn write_empty_block(&mut self, _target: &TargetPath, _off: u64, _blocks: u32) -> Result<()> {
        Err(Error::Unsupported {
            what: "empty-block write",
        })
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
        let abs = self.root.join(rel);
        match fs::remove_file(&abs) {
            Ok(()) => Ok(()),
            // A delete of a file that was never created is a no-op (as `File.Delete` is), regardless
            // of any ignore-missing flag: boot patches delete files earlier links never laid down.
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(io(e, abs, Op::Remove)),
        }
    }

    fn remove_expansion(&mut self, _expansion: u16, _keep: &KeepFilter) -> Result<()> {
        Err(Error::Unsupported {
            what: "expansion remove-all",
        })
    }

    fn make_dir_tree(&mut self, rel: &SafePath) -> Result<()> {
        make_tree(&self.root, rel.as_path())
    }

    fn remove_dir(&mut self, rel: &SafePath) -> Result<()> {
        let abs = self.root.join(rel.as_path());
        match fs::remove_dir_all(&abs) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(io(e, abs, Op::Remove)),
        }
    }
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
    if let Some(parent) = rel.parent() {
        make_tree(root, parent)?;
    }
    let abs = root.join(rel);
    unlink_if_symlink(&abs)?;
    OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        // Never truncate on open: a continuation `F:A` (offset > 0) or a re-opened evicted handle
        // must keep the bytes an earlier command wrote. Only the explicit `truncate` op clears a file.
        .truncate(false)
        .open(&abs)
        .map_err(|e| io(e, abs, Op::Open))
}

/// Create `root/rel` and every ancestor as a real directory, refusing to traverse an existing
/// symlink or non-directory (a crafted patch could otherwise plant an in-tree link that relocates a
/// later write). `rel` is already confined, so only `Normal` components reach here.
fn make_tree(root: &Path, rel: &Path) -> Result<()> {
    let mut cur = root.to_path_buf();
    for comp in rel.components() {
        cur.push(comp.as_os_str());
        match fs::symlink_metadata(&cur) {
            Ok(meta) if meta.is_dir() => {}
            Ok(_) => {
                return Err(Error::PathEscape {
                    raw: cur.display().to_string(),
                });
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                fs::create_dir(&cur).map_err(|e| io(e, cur.clone(), Op::MakeDir))?;
            }
            Err(e) => return Err(io(e, cur, Op::MakeDir)),
        }
    }
    Ok(())
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

/// Seek a handle to `off`, tagging a failure with the target path.
fn seek(file: &mut File, off: u64, rel: &Path) -> Result<()> {
    file.seek(SeekFrom::Start(off))
        .map(|_| ())
        .map_err(|e| io(e, rel.to_path_buf(), Op::Write))
}

/// Write `buf` at `off`.
fn write_at(file: &mut File, off: u64, buf: &[u8], rel: &Path) -> Result<()> {
    seek(file, off, rel)?;
    file.write_all(buf)
        .map_err(|e| io(e, rel.to_path_buf(), Op::Write))
}

/// Write `len` zero bytes at `off`.
fn write_zeros(file: &mut File, off: u64, len: u64, rel: &Path) -> Result<()> {
    seek(file, off, rel)?;
    let zeros = [0u8; 8192];
    let mut remaining = len;
    while remaining > 0 {
        let n = remaining.min(zeros.len() as u64) as usize;
        file.write_all(&zeros[..n])
            .map_err(|e| io(e, rel.to_path_buf(), Op::Write))?;
        remaining -= n as u64;
    }
    Ok(())
}

/// Build an [`Error::Io`] carrying the target path and the operation in flight.
fn io(source: io::Error, target: PathBuf, during: Op) -> Error {
    Error::Io {
        source,
        target: Some(target),
        during,
    }
}

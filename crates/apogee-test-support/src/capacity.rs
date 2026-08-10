//! A scratch directory whose filesystem refuses an oversize reservation up front, for tests that
//! need a real `ENOSPC` out of `fallocate` without risking the host's disk.
//!
//! Only a memory-backed filesystem (tmpfs) is usable here. Its `fallocate` compares the whole
//! request against the mount's configured size and returns `ENOSPC` before reserving anything; a
//! disk-backed filesystem has no such check and allocates toward the request until the volume is
//! genuinely full. Measured on Linux 7.0 with a 15.6 GiB tmpfs and a 457 GiB ext4 volume, both asked
//! for twice their total capacity: tmpfs answered `ENOSPC` in 85 microseconds having reserved 0
//! bytes, ext4 reserved 14.4 GB within 40 milliseconds and was still climbing when the harness
//! killed it. Two further sizings are traps rather than shortcuts: asking for exactly the tmpfs
//! capacity (not more) falls past the check and allocates, and asking for a size above the mount's
//! maximum file size answers `EFBIG` instead, which is a different error wearing the same
//! `std::io::Error` clothes (ext4 answered `EFBIG` at 20 TiB).

use std::path::{Path, PathBuf};

use tempfile::{Builder, TempDir};

/// `TMPFS_MAGIC`: the `statfs` filesystem type that marks a memory-backed mount.
const TMPFS_MAGIC: rustix::fs::FsWord = 0x0102_1994;

/// Where to look for a memory-backed mount, in order. `/dev/shm` is first because Linux has it
/// essentially everywhere, including inside a container, where `$TMPDIR` and `/tmp` are usually the
/// image's own disk-backed root.
const CANDIDATES: [&str; 2] = ["/dev/shm", "/tmp"];

/// A temp directory on a memory-backed filesystem, and that filesystem's total capacity.
///
/// The directory is removed when this is dropped.
#[derive(Debug)]
pub struct MemoryBackedDir {
    dir: TempDir,
    capacity: u64,
}

impl MemoryBackedDir {
    /// The scratch directory.
    pub fn path(&self) -> &Path {
        self.dir.path()
    }

    /// The total capacity of the filesystem holding it, in bytes.
    pub fn capacity(&self) -> u64 {
        self.capacity
    }

    /// The bytes currently free on that filesystem to an unprivileged process.
    ///
    /// Read at call time and not stored beside the capacity, because the two are different kinds of
    /// number: capacity is a property of the mount, free space is a moment. A test sizing a request
    /// against free space wants the reading the code under test will take, not one from setup. This
    /// mount is usually shared (`/dev/shm`), so anything derived from a fixed fraction of
    /// [`capacity`](Self::capacity) is a guess about how busy the host is.
    ///
    /// # Errors
    /// Whatever `statvfs` raised.
    pub fn available(&self) -> std::io::Result<u64> {
        let stat = rustix::fs::statvfs(self.dir.path())?;
        Ok(stat.f_bavail.saturating_mul(stat.f_frsize))
    }

    /// A byte length this filesystem rejects with `ENOSPC` without reserving a block toward it.
    ///
    /// Twice the capacity plus a gigabyte: far enough past the mount's size that no amount of free
    /// space changes the answer, and far short of any filesystem's maximum file size, past which the
    /// kernel answers `EFBIG` instead.
    pub fn beyond_capacity(&self) -> u64 {
        self.capacity.saturating_mul(2).saturating_add(1 << 30)
    }
}

/// Make a temp directory named `prefix` on the first memory-backed filesystem found.
///
/// # Errors
/// [`std::io::ErrorKind::Unsupported`] naming the candidates when none of them is memory-backed or
/// none reports a capacity, and the underlying error when the directory cannot be created.
pub fn memory_backed_dir(prefix: &str) -> std::io::Result<MemoryBackedDir> {
    for root in candidates() {
        let Some(capacity) = memory_backed_capacity(&root) else {
            continue;
        };
        let dir = Builder::new().prefix(prefix).tempdir_in(&root)?;
        return Ok(MemoryBackedDir { dir, capacity });
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        format!(
            "no memory-backed filesystem among {:?}; a disk-full injection cannot run safely here",
            candidates(),
        ),
    ))
}

/// `$TMPDIR` ahead of the fixed candidates, so a developer who redirects temp files keeps the
/// filesystem they chose when it qualifies.
fn candidates() -> Vec<PathBuf> {
    let mut roots: Vec<PathBuf> = std::env::var_os("TMPDIR")
        .map(PathBuf::from)
        .into_iter()
        .collect();
    roots.extend(CANDIDATES.iter().map(PathBuf::from));
    roots
}

/// The total capacity of `root`'s filesystem when it is memory-backed and declares one, else `None`.
///
/// A tmpfs mounted without a size limit reports zero blocks and is refused: the kernel's up-front
/// check is against that limit, so without one an oversize request is answered by swapping instead.
fn memory_backed_capacity(root: &Path) -> Option<u64> {
    if rustix::fs::statfs(root).ok()?.f_type != TMPFS_MAGIC {
        return None;
    }
    let stat = rustix::fs::statvfs(root).ok()?;
    let capacity = stat.f_frsize.checked_mul(stat.f_blocks)?;
    (capacity > 0).then_some(capacity)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_scratch_dir_lands_on_a_sized_memory_backed_mount() {
        let dir = memory_backed_dir("apogee-capacity-").expect("memory-backed scratch");
        assert!(dir.path().is_dir());
        assert!(dir.capacity() > 0);
        assert_eq!(
            memory_backed_capacity(dir.path()),
            Some(dir.capacity()),
            "the scratch dir must sit on the mount whose capacity was measured",
        );
        // The oversize request has to clear the mount's size, or the kernel allocates toward it.
        assert!(dir.beyond_capacity() > dir.capacity());
    }

    /// A sized mount that is not memory-backed is refused, which is the whole safety guard.
    ///
    /// It is the type check and not the capacity that has to do this work: a disk-backed mount
    /// reports a capacity just as a tmpfs does, and `$TMPDIR` pointing at one is an ordinary
    /// arrangement (it is how the tests in this workspace are usually run). Handing that back is what
    /// turns a disk-full injection into an allocation storm on the host's real disk. The source tree
    /// stands in for it, which holds unless a checkout is itself on tmpfs: a wrong verdict there is a
    /// loud failure here rather than a quiet one on someone's disk.
    #[test]
    fn a_disk_backed_mount_is_refused_even_though_it_is_sized() {
        assert_eq!(
            memory_backed_capacity(Path::new(env!("CARGO_MANIFEST_DIR"))),
            None,
        );
    }
}

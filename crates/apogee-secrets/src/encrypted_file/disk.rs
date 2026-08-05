//! Getting the sealed bytes onto and off the disk without losing them.
//!
//! Three concerns live here, all of them about the file rather than about what is in it: publishing a
//! new version so that a crash leaves either the old one or the new one and never a torn one, keeping
//! two launcher processes from writing over each other, and keeping the file and its directory
//! readable by nobody else.

use std::fs::{File, OpenOptions};
use std::io::{ErrorKind, Read, Write};
use std::path::{Path, PathBuf};

use uuid::Uuid;
use zeroize::Zeroizing;

use super::frame::{check_size_on_disk, corrupt};
use crate::SecretsError;

/// Suffix of the sidecar the exclusive lock is taken on.
const LOCK_SUFFIX: &str = "lock";

/// Suffix every in-flight write carries until it is renamed into place.
const TEMP_SUFFIX: &str = "tmp";

/// Read the sealed file, or answer `None` if there is nothing at the path.
///
/// The size is checked against the cap from the directory entry, before any of the file is read, so a
/// hostile file cannot make this allocate for it.
pub(crate) fn read(path: &Path) -> Result<Option<Zeroizing<Vec<u8>>>, SecretsError> {
    let meta = match std::fs::symlink_metadata(path) {
        Ok(meta) => meta,
        Err(err) if err.kind() == ErrorKind::NotFound => return Ok(None),
        Err(err) => return Err(map_io(err)),
    };
    if !meta.is_file() {
        // A symlink or a directory at the store path. The write path replaces whatever is there by
        // rename and never follows it, so this is what stops a *read* being redirected. It is a check
        // and not a guarantee: without a platform crate there is no way to open a path and refuse a
        // symlink in the same syscall, so a swap between here and the open is not covered. Stated
        // rather than implied.
        return Err(corrupt("store path"));
    }
    check_size_on_disk(meta.len())?;

    let mut file = File::open(path).map_err(map_io)?;
    let mut bytes = Zeroizing::new(Vec::with_capacity(meta.len() as usize + 1));
    file.read_to_end(&mut bytes).map_err(map_io)?;
    // Re-checked against what was actually read: the size the directory entry reported is a fact
    // about the moment before the open, and the file may have grown since.
    check_size_on_disk(bytes.len() as u64)?;
    Ok(Some(bytes))
}

/// Replace the file at `path` with `bytes`, atomically.
///
/// The sequence is write-elsewhere, flush, rename, and it is what makes a crash leave either the
/// whole old store or the whole new one. An orphaned temp left by a crash holds ciphertext, not
/// plaintext.
pub(crate) fn publish(path: &Path, bytes: &[u8]) -> Result<(), SecretsError> {
    let temp = sibling(path, &format!("{}.{TEMP_SUFFIX}", Uuid::new_v4()));

    let mut options = OpenOptions::new();
    options.write(true);
    // Exclusive creation, so a symlink planted at the temp name is refused rather than followed, and
    // so a name a concurrent writer is already using is never taken.
    options.create_new(true);
    private_file(&mut options);
    let mut file = options.open(&temp).map_err(map_io)?;

    let written = file
        .write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(map_io);
    drop(file);
    if let Err(err) = written {
        let _ = std::fs::remove_file(&temp);
        return Err(err);
    }

    if let Err(err) = std::fs::rename(&temp, path) {
        let _ = std::fs::remove_file(&temp);
        return Err(map_io(err));
    }

    // Best effort, never an error. The rename is already atomic, so this only decides whether the
    // directory entry survives a power cut, and not every filesystem lets a directory be flushed.
    if let Some(parent) = path.parent() {
        let _ = File::open(parent).and_then(|dir| dir.sync_all());
    }
    Ok(())
}

/// Remove temp files a crashed write left behind.
///
/// Only ever called with the exclusive lock held, which is the one moment at which any temp beside
/// the store is provably not another live writer's in-flight file.
pub(crate) fn sweep_temps(path: &Path) {
    let (Some(parent), Some(name)) = (path.parent(), path.file_name().and_then(|n| n.to_str()))
    else {
        return;
    };
    let Ok(entries) = std::fs::read_dir(parent) else {
        return;
    };
    for entry in entries.flatten() {
        let Some(found) = entry.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        if found.starts_with(&format!("{name}.")) && found.ends_with(&format!(".{TEMP_SUFFIX}")) {
            let _ = std::fs::remove_file(entry.path());
        }
    }
}

/// Delete the store. Answers whether there was one.
pub(crate) fn remove(path: &Path) -> Result<bool, SecretsError> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(true),
        Err(err) if err.kind() == ErrorKind::NotFound => Ok(false),
        Err(err) => Err(map_io(err)),
    }
}

/// The exclusive lock held across a whole read-modify-write.
///
/// Taken on a sidecar rather than on the store itself, because the store is replaced by rename: a
/// lock on the file that was there protects an inode nothing will write to again. The kernel releases
/// it when this drops, including when the process dies, so there is no stale-lock heuristic and
/// nothing to clean up.
pub(crate) struct Lock {
    _file: File,
}

impl Lock {
    /// Take the lock, waiting for whoever holds it.
    ///
    /// Blocking rather than trying and failing: the alternative is a caller that has to decide how
    /// long to retry for, and the holder is another process doing a write that takes milliseconds.
    pub(crate) fn take(path: &Path) -> Result<Self, SecretsError> {
        let sidecar = sibling(path, LOCK_SUFFIX);
        let mut options = OpenOptions::new();
        options.write(true).create(true).truncate(false);
        private_file(&mut options);
        let file = options.open(&sidecar).map_err(map_io)?;
        // The sidecar is never deleted. Removing it would race the next process to acquire, which
        // would then lock a file nobody else can see and serialise against nothing.
        file.lock().map_err(|_| SecretsError::Backend {
            step: "take the secret store lock",
        })?;
        Ok(Self { _file: file })
    }
}

/// A path beside `path` with one more dotted suffix.
fn sibling(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(".");
    name.push(suffix);
    PathBuf::from(name)
}

/// Fold a filesystem failure into the taxonomy.
///
/// Permission is its own answer because it is the one a user fixes somewhere other than in this
/// launcher. The error is carried in the `Io` variant unchanged for the rest, which is safe here in a
/// way it is not for the credential stores: a filesystem error names a path, and the path is not a
/// secret.
fn map_io(err: std::io::Error) -> SecretsError {
    if err.kind() == ErrorKind::PermissionDenied {
        return SecretsError::Denied;
    }
    SecretsError::Io(err)
}

/// Make sure the directory the store lives in exists and is owner-only.
///
/// Narrows a directory an earlier build or a restore left wider, rather than only setting the mode on
/// one it creates: a store that has been readable since it was made would otherwise stay that way
/// forever, and nothing would ever say so.
#[cfg(unix)]
pub(crate) fn private_dir(path: &Path) -> Result<(), SecretsError> {
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};

    let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) else {
        return Ok(());
    };
    match std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(parent)
    {
        Ok(()) => {}
        Err(err) => return Err(map_io(err)),
    }
    // `recursive` leaves an existing directory's mode alone, which is the case this narrows.
    if let Ok(meta) = std::fs::metadata(parent) {
        let mode = meta.permissions().mode();
        if mode & 0o077 != 0 {
            let _ = std::fs::set_permissions(parent, PermissionsExt::from_mode(mode & 0o700));
        }
    }
    Ok(())
}

/// Narrow the store itself if something widened it.
///
/// The contents are sealed either way, so a wider file is not a reason to refuse the operation and
/// strand a user whose backup tool restored it with a group bit. It is a reason to put it back.
#[cfg(unix)]
pub(crate) fn narrow_file(path: &Path) {
    use std::os::unix::fs::PermissionsExt;

    if let Ok(meta) = std::fs::metadata(path) {
        let mode = meta.permissions().mode();
        if mode & 0o077 != 0 {
            let _ = std::fs::set_permissions(path, PermissionsExt::from_mode(mode & 0o700));
        }
    }
}

#[cfg(unix)]
fn private_file(options: &mut OpenOptions) {
    use std::os::unix::fs::OpenOptionsExt;

    // On the open rather than as a later chmod, so the file is never briefly readable by anyone else.
    options.mode(0o600);
}

/// On this platform the file inherits the directory's access rules, and the launcher's own directory
/// is already restricted to the user. There is no mode to set and nothing to narrow.
#[cfg(not(unix))]
pub(crate) fn private_dir(path: &Path) -> Result<(), SecretsError> {
    let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) else {
        return Ok(());
    };
    std::fs::create_dir_all(parent).map_err(map_io)
}

#[cfg(not(unix))]
pub(crate) fn narrow_file(_path: &Path) {}

#[cfg(not(unix))]
fn private_file(_options: &mut OpenOptions) {}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir() -> tempfile::TempDir {
        #[allow(clippy::expect_used)]
        tempfile::tempdir().expect("temp dir")
    }

    #[test]
    fn a_published_file_reads_back_and_an_absent_one_is_nothing() {
        let dir = temp_dir();
        let path = dir.path().join("store.apsf");
        assert!(read(&path).expect("absent").is_none());

        let bytes = vec![7u8; super::super::frame::MIN_FILE];
        publish(&path, &bytes).expect("publish");
        assert_eq!(*read(&path).expect("read").expect("present"), bytes);
    }

    /// The publish has to leave nothing behind, or a crashed write's leftovers would accumulate in a
    /// directory the user never looks at.
    #[test]
    fn a_publish_leaves_no_temp_file() {
        let dir = temp_dir();
        let path = dir.path().join("store.apsf");
        publish(&path, &vec![0u8; super::super::frame::MIN_FILE]).expect("publish");
        let strays: Vec<_> = std::fs::read_dir(dir.path())
            .expect("list")
            .flatten()
            .filter(|e| e.file_name().to_string_lossy().ends_with(".tmp"))
            .collect();
        assert!(strays.is_empty());
    }

    /// A temp left by a crashed write is another process's business until the lock is held, and then
    /// it is nobody's. The sweep must take those and leave the store and the sidecar alone.
    #[test]
    fn the_sweep_takes_only_this_store_s_leftovers() {
        let dir = temp_dir();
        let path = dir.path().join("store.apsf");
        publish(&path, &vec![0u8; super::super::frame::MIN_FILE]).expect("publish");
        let lock = Lock::take(&path).expect("lock");
        for name in [
            "store.apsf.abc.tmp",
            "store.apsf.def.tmp",
            "other.apsf.abc.tmp",
            "store.apsf.keepme",
        ] {
            std::fs::write(dir.path().join(name), b"x").expect("write");
        }
        sweep_temps(&path);
        drop(lock);

        assert!(path.exists());
        assert!(dir.path().join("store.apsf.lock").exists());
        assert!(dir.path().join("other.apsf.abc.tmp").exists());
        assert!(dir.path().join("store.apsf.keepme").exists());
        assert!(!dir.path().join("store.apsf.abc.tmp").exists());
        assert!(!dir.path().join("store.apsf.def.tmp").exists());
    }

    /// The narrowing of an existing wide *directory*, which is the one permissions path the store's
    /// own tests cannot reach: they always create their directory rather than finding one. A store
    /// made before this was owner-only, or restored by a tool that widened it, has to be put back
    /// rather than left leaking quietly for the rest of its life.
    #[cfg(unix)]
    #[test]
    fn a_directory_and_a_file_left_wider_are_narrowed() {
        use std::os::unix::fs::PermissionsExt;

        let dir = temp_dir();
        let nested = dir.path().join("nested");
        std::fs::create_dir(&nested).expect("mkdir");
        std::fs::set_permissions(&nested, PermissionsExt::from_mode(0o755)).expect("chmod");
        let path = nested.join("store.apsf");
        std::fs::write(&path, b"x").expect("write");
        std::fs::set_permissions(&path, PermissionsExt::from_mode(0o644)).expect("chmod");

        private_dir(&path).expect("directory");
        narrow_file(&path);

        assert_eq!(
            std::fs::metadata(&nested)
                .expect("stat")
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
        assert_eq!(
            std::fs::metadata(&path).expect("stat").permissions().mode() & 0o777,
            0o600
        );
    }
}

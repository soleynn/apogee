//! Eager file preallocation.
//!
//! A segmented download writes at scattered offsets into one `.part`, so the file is reserved to its
//! full length up front. `fallocate` also reserves the disk blocks, so a doomed transfer fails on a
//! full disk here, before any payload streams, rather than mid-way through gigabytes. On a filesystem
//! without `fallocate` support the length is still set (a sparse file), trading eager disk-full
//! detection for portability while keeping correctness.

use std::path::Path;

use rustix::fs::{FallocateFlags, fallocate};

use crate::error::FetchError;

/// Preallocate `path` to `len` bytes, reserving the blocks. Idempotent: an existing shorter file is
/// extended, a full-length one is left as is. `len == 0` just ensures the file exists. The blocking
/// syscalls run on a blocking-pool thread.
///
/// # Errors
/// [`FetchError::Io`] carrying the underlying [`std::io::Error`], whose `kind()` distinguishes
/// disk-full from other failures.
#[allow(dead_code)] // wired into the transfer path with the segmented engine.
pub(crate) async fn preallocate(path: &Path, len: u64) -> Result<(), FetchError> {
    let owned = path.to_owned();
    let joined = tokio::task::spawn_blocking(move || preallocate_blocking(&owned, len)).await;
    match joined {
        Ok(result) => result.map_err(|e| FetchError::io(path, e)),
        Err(join) => Err(FetchError::io(path, std::io::Error::other(join))),
    }
}

fn preallocate_blocking(path: &Path, len: u64) -> std::io::Result<()> {
    let file = std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(false)
        .open(path)?;
    if len == 0 {
        return Ok(());
    }
    match fallocate(&file, FallocateFlags::empty(), 0, len) {
        Ok(()) => Ok(()),
        // A filesystem without fallocate (or an old kernel): fall back to a plain length set. The file
        // is sparse, so eager disk-full detection is lost, but the transfer is otherwise correct.
        Err(rustix::io::Errno::OPNOTSUPP | rustix::io::Errno::NOSYS) => file.set_len(len),
        Err(e) => Err(std::io::Error::from(e)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn preallocates_to_the_requested_length() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("out.part");
        preallocate(&path, 4096).await.unwrap();
        assert_eq!(std::fs::metadata(&path).unwrap().len(), 4096);
    }

    #[tokio::test]
    async fn is_idempotent_and_never_shrinks() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("out.part");
        preallocate(&path, 8192).await.unwrap();
        // A second call at the same length leaves the file intact; a call is not a truncation.
        preallocate(&path, 8192).await.unwrap();
        assert_eq!(std::fs::metadata(&path).unwrap().len(), 8192);
    }

    #[tokio::test]
    async fn zero_length_just_creates_the_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("empty.part");
        preallocate(&path, 0).await.unwrap();
        assert_eq!(std::fs::metadata(&path).unwrap().len(), 0);
    }

    #[tokio::test]
    async fn a_failure_to_open_is_a_typed_io_error() {
        // A parent that does not exist makes the open fail; the error is surfaced as FetchError::Io,
        // not a panic.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("no-such-dir").join("out.part");
        let err = preallocate(&path, 4096).await.unwrap_err();
        assert!(matches!(err, FetchError::Io { .. }));
    }
}

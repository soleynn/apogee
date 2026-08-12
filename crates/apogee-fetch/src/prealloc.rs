//! Eager `.part` file preallocation.
//!
//! Both download engines reserve their `.part` file to its full length before any payload streams.
//! A segmented download must: it writes at scattered offsets into one file. Either benefits: with the
//! blocks reserved, a doomed transfer fails on a full disk immediately, rather than mid-way through
//! gigabytes. The length comes from wherever each engine already has it: the caller's declared length
//! on the segmented path, the first response's `Content-Length` on the streaming path; a transfer
//! with no length at all skips the reservation rather than guessing one.
//!
//! On a filesystem without `fallocate` support, the length is still set on a sparse file: eager
//! disk-full detection is lost, but correctness is not.

use std::path::Path;

use crate::error::FetchError;

/// Preallocate `path` to `len` bytes, reserving the blocks. Idempotent: an existing shorter file is
/// extended, a full-length one is left as is, and `len == 0` just ensures the file exists. Runs the
/// blocking syscalls on a blocking-pool thread.
///
/// # Errors
///
/// Returns [`FetchError::Io`] carrying the underlying [`std::io::Error`], whose `kind()`
/// distinguishes disk-full from other failures.
pub(crate) async fn preallocate(path: &Path, len: u64) -> Result<(), FetchError> {
    let owned = path.to_owned();
    let joined = tokio::task::spawn_blocking(move || preallocate_blocking(&owned, len)).await;
    match joined {
        Ok(result) => result.map_err(|e| FetchError::io(path, e)),
        Err(join) => Err(FetchError::io(path, std::io::Error::other(join))),
    }
}

/// Unix: reserve blocks with `fallocate`, so a full disk fails here. Falls back to a length set on a
/// filesystem that does not support it.
#[cfg(unix)]
fn preallocate_blocking(path: &Path, len: u64) -> std::io::Result<()> {
    use rustix::fs::{FallocateFlags, fallocate};

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

/// Off Unix (the Windows cross-build): no portable eager reservation, so set the length. The file is
/// sparse, trading eager disk-full detection for portability; the patch path itself runs on Linux.
#[cfg(not(unix))]
fn preallocate_blocking(path: &Path, len: u64) -> std::io::Result<()> {
    let file = std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(false)
        .open(path)?;
    file.set_len(len)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A fresh file is preallocated to exactly the requested length.
    #[tokio::test]
    async fn preallocates_to_the_requested_length() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("out.part");
        preallocate(&path, 4096).await.unwrap();
        assert_eq!(std::fs::metadata(&path).unwrap().len(), 4096);
    }

    /// A second call at the same length leaves an already-preallocated file intact.
    #[tokio::test]
    async fn is_idempotent_and_never_shrinks() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("out.part");
        preallocate(&path, 8192).await.unwrap();
        // A second call at the same length leaves the file intact; a call is not a truncation.
        preallocate(&path, 8192).await.unwrap();
        assert_eq!(std::fs::metadata(&path).unwrap().len(), 8192);
    }

    /// A zero length still ensures the file exists, rather than being a no-op.
    #[tokio::test]
    async fn zero_length_just_creates_the_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("empty.part");
        preallocate(&path, 0).await.unwrap();
        assert_eq!(std::fs::metadata(&path).unwrap().len(), 0);
    }

    /// A parent directory that does not exist surfaces as `FetchError::Io`, not a panic.
    #[tokio::test]
    async fn a_failure_to_open_is_a_typed_io_error() {
        // A parent that does not exist makes the open fail; the error is surfaced as FetchError::Io,
        // not a panic.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("no-such-dir").join("out.part");
        let err = preallocate(&path, 4096).await.unwrap_err();
        assert!(matches!(err, FetchError::Io { .. }));
    }

    /// A length past the filesystem's capacity fails as disk-full specifically, and reserves no
    /// blocks.
    ///
    /// Both halves are the claim: `FetchError::Io` alone would also be satisfied by a permission
    /// fault or by the `EFBIG` a request past the maximum file size returns, so the inner kind and
    /// errno are what make disk-full distinguishable; the allocated-block count is what makes it
    /// eager, since a filesystem that reserved its way to the failure would have consumed the host's
    /// disk to reach the same error.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn a_length_past_the_filesystem_capacity_is_a_distinct_disk_full_error() {
        use std::os::unix::fs::MetadataExt;

        let scratch = apogee_test_support::capacity::memory_backed_dir("apogee-prealloc-").unwrap();
        let path = scratch.path().join("out.part");

        let err = preallocate(&path, scratch.beyond_capacity())
            .await
            .unwrap_err();
        let FetchError::Io { source, .. } = &err else {
            panic!("want a typed I/O error, got {err:?}");
        };
        assert_eq!(
            source.kind(),
            std::io::ErrorKind::StorageFull,
            "want disk-full, got {source:?}",
        );
        assert_eq!(
            source.raw_os_error(),
            Some(rustix::io::Errno::NOSPC.raw_os_error()),
            "want ENOSPC and not the EFBIG of an over-large request, got {source:?}",
        );

        let meta = std::fs::metadata(&path).unwrap();
        assert_eq!(meta.blocks(), 0, "the refused reservation consumed blocks");
        assert_eq!(meta.len(), 0, "the refused reservation extended the file");
    }

    /// A filesystem with no reservation support falls back to a length set rather than failing.
    ///
    /// procfs is the one filesystem reachable without mounting one (which needs root) that refuses
    /// `fallocate` the way the fallback arm expects, verified directly here rather than assumed; this
    /// only checks that the refusal is swallowed, not that the file actually gets the sparse length
    /// set, since `/proc/self/oom_score_adj` ignores that write.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn a_filesystem_without_reservation_support_falls_back_to_a_length_set() {
        use rustix::fs::{FallocateFlags, fallocate};

        let path = Path::new("/proc/self/oom_score_adj");
        let probe = std::fs::OpenOptions::new().write(true).open(path).unwrap();
        assert_eq!(
            fallocate(&probe, FallocateFlags::empty(), 0, 4096),
            Err(rustix::io::Errno::OPNOTSUPP),
            "this path no longer stands in for a filesystem that cannot reserve",
        );
        drop(probe);

        preallocate(path, 4096).await.unwrap();
    }
}

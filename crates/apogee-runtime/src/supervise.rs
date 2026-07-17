//! Resolving and tracking the real game process through `/proc`, on stock wine/Proton.
//!
//! No `winedbg` scraping and no patched wine: the game is found by scanning `/proc` for a process
//! whose `comm` is the PE basename and whose `WINEPREFIX` (normalized for Proton's `/pfx`
//! relocation) matches the launched prefix, then watched for exit via a pidfd.

use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use rustix::process::{Pid, PidfdFlags, Signal, kill_process, pidfd_open};
use tokio::io::unix::AsyncFd;
use tokio_util::sync::CancellationToken;

use crate::error::RuntimeError;

/// Linux caps `/proc/<pid>/comm` at `TASK_COMM_LEN - 1` bytes.
const COMM_MAX: usize = 15;
/// How long to poll for the game to appear before giving up.
const RESOLVE_DEADLINE: Duration = Duration::from_secs(30);
const POLL_INTERVAL: Duration = Duration::from_millis(150);
/// SIGTERM grace before escalating to SIGKILL.
const KILL_GRACE: Duration = Duration::from_millis(100);
const KILL_ATTEMPTS: u32 = 20;

/// Poll `/proc` until a process matching `program_basename` (by `comm`) and `prefix_path` (by
/// normalized `WINEPREFIX`) appears, or the deadline passes.
pub(crate) async fn resolve_game(
    program_basename: &str,
    prefix_path: &Path,
    cancel: &CancellationToken,
) -> Result<i32, RuntimeError> {
    let target = comm_target(program_basename);
    let expected = prefix_path
        .canonicalize()
        .unwrap_or_else(|_| prefix_path.to_path_buf());
    let start = Instant::now();
    loop {
        if cancel.is_cancelled() {
            return Err(RuntimeError::GameProcessNotFound {
                waited: start.elapsed(),
            });
        }
        match scan_once(&target, &expected) {
            Ok(Some(pid)) => return Ok(pid),
            Ok(None) => {}
            Err(source) => {
                return Err(RuntimeError::Io {
                    path: PathBuf::from("/proc"),
                    source,
                });
            }
        }
        if start.elapsed() >= RESOLVE_DEADLINE {
            return Err(RuntimeError::GameProcessNotFound {
                waited: RESOLVE_DEADLINE,
            });
        }
        tokio::time::sleep(POLL_INTERVAL).await;
    }
}

/// One pass over `/proc`. A pid that races away mid-scan is skipped, not fatal.
fn scan_once(comm_target: &str, expected_prefix: &Path) -> std::io::Result<Option<i32>> {
    for entry in std::fs::read_dir("/proc")? {
        let entry = entry?;
        let name = entry.file_name();
        let Some(pid) = name.to_str().and_then(|s| s.parse::<i32>().ok()) else {
            continue;
        };
        let comm = match std::fs::read_to_string(format!("/proc/{pid}/comm")) {
            Ok(c) => c,
            Err(_) => continue,
        };
        if comm.trim_end_matches('\n') != comm_target {
            continue;
        }
        let environ = match std::fs::read(format!("/proc/{pid}/environ")) {
            Ok(e) => e,
            Err(_) => continue,
        };
        if let Some(wineprefix) = find_env(&environ, b"WINEPREFIX")
            && wineprefix_matches(&wineprefix, expected_prefix)
        {
            return Ok(Some(pid));
        }
    }
    Ok(None)
}

/// The `comm` string to match: the basename truncated to the kernel's limit (on a char boundary).
fn comm_target(basename: &str) -> String {
    let mut end = basename.len().min(COMM_MAX);
    while !basename.is_char_boundary(end) {
        end -= 1;
    }
    basename[..end].to_owned()
}

/// The value of `KEY=` in a NUL-separated `environ` blob.
fn find_env(environ: &[u8], key: &[u8]) -> Option<PathBuf> {
    let mut needle = Vec::with_capacity(key.len() + 1);
    needle.extend_from_slice(key);
    needle.push(b'=');
    environ
        .split(|&b| b == 0)
        .find(|entry| entry.starts_with(&needle))
        .map(|entry| PathBuf::from(OsStr::from_bytes(&entry[needle.len()..])))
}

/// Whether a process's `WINEPREFIX` refers to `expected`, accounting for Proton relocating the live
/// prefix to `<expected>/pfx`.
fn wineprefix_matches(found: &Path, expected: &Path) -> bool {
    let candidate = if found.file_name() == Some(OsStr::new("pfx")) {
        found.parent().unwrap_or(found)
    } else {
        found
    };
    let canonical = candidate.canonicalize();
    canonical.as_deref().unwrap_or(candidate) == expected
}

/// How a resolved process's exit is observed.
pub(crate) enum ExitWatch {
    /// A pidfd that becomes readable once, on exit (Linux >= 5.3).
    Pidfd(AsyncFd<std::os::fd::OwnedFd>),
    /// Fallback for older kernels: poll `/proc/<pid>` for disappearance.
    Poll(i32),
}

/// Begin watching `pid` for exit, preferring a pidfd.
pub(crate) fn watch_exit(pid: i32) -> ExitWatch {
    if let Some(p) = Pid::from_raw(pid)
        && let Ok(fd) = pidfd_open(p, PidfdFlags::empty())
        && let Ok(async_fd) = AsyncFd::new(fd)
    {
        return ExitWatch::Pidfd(async_fd);
    }
    ExitWatch::Poll(pid)
}

/// Resolve when the watched process exits.
pub(crate) async fn wait_exit(watch: &ExitWatch) -> Result<(), RuntimeError> {
    match watch {
        ExitWatch::Pidfd(fd) => {
            let _guard = fd.readable().await.map_err(|source| RuntimeError::Io {
                path: PathBuf::from("pidfd"),
                source,
            })?;
            Ok(())
        }
        ExitWatch::Poll(pid) => {
            while proc_exists(*pid) {
                tokio::time::sleep(Duration::from_millis(250)).await;
            }
            Ok(())
        }
    }
}

/// Whether a process still exists.
pub(crate) fn proc_exists(pid: i32) -> bool {
    Path::new(&format!("/proc/{pid}")).exists()
}

/// Signal `pid`; a process that already exited is not an error.
fn signal(pid: i32, sig: Signal) {
    if let Some(p) = Pid::from_raw(pid) {
        let _ = kill_process(p, sig);
    }
}

/// Targeted kill: SIGTERM, then SIGKILL after a grace period. Hits only `pid`.
pub(crate) async fn kill_pid(pid: i32) -> Result<(), RuntimeError> {
    signal(pid, Signal::TERM);
    for _ in 0..KILL_ATTEMPTS {
        if !proc_exists(pid) {
            return Ok(());
        }
        tokio::time::sleep(KILL_GRACE).await;
    }
    signal(pid, Signal::KILL);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn comm_target_truncates_to_the_kernel_limit() {
        assert_eq!(comm_target("ffxiv_dx11.exe"), "ffxiv_dx11.exe");
        assert_eq!(comm_target("a_very_long_process_name"), "a_very_long_pro"); // 15 bytes
    }

    #[test]
    fn find_env_reads_a_nul_separated_value() {
        let environ = b"HOME=/root\0WINEPREFIX=/prefix/pfx\0LANG=C\0";
        assert_eq!(
            find_env(environ, b"WINEPREFIX"),
            Some(PathBuf::from("/prefix/pfx"))
        );
        assert_eq!(find_env(environ, b"MISSING"), None);
    }

    #[test]
    fn wineprefix_matches_strips_the_proton_pfx_suffix() {
        let dir = tempfile::tempdir().expect("tempdir");
        let prefix = dir.path().to_path_buf();
        let expected = prefix.canonicalize().expect("canonicalize");
        // Plain wine: WINEPREFIX is the prefix itself.
        assert!(wineprefix_matches(&prefix, &expected));
        // Proton: WINEPREFIX is <prefix>/pfx.
        assert!(wineprefix_matches(&prefix.join("pfx"), &expected));
        // A different prefix does not match.
        let other = tempfile::tempdir().expect("tempdir");
        assert!(!wineprefix_matches(other.path(), &expected));
    }
}

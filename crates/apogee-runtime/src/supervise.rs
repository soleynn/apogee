//! Finding and tracking the real game process through `/proc`, on stock wine and Proton.
//!
//! No `winedbg` scraping and no patched wine: a process is a candidate when its `comm` is the PE
//! basename and when the caller's own predicate accepts it, and its exit is then watched through a
//! pidfd. `comm` is only the first 15 bytes of a name, so a candidate is a narrowing rather than an
//! identity; what says which instance was meant is the predicate, either the `WINEPREFIX` the
//! process declares for itself or the install its bytes are being read from.

use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use rustix::process::{Pid, PidfdFlags, Signal, kill_process, pidfd_open, pidfd_send_signal};
use tokio::io::unix::AsyncFd;
use tokio_util::sync::CancellationToken;

use crate::error::RuntimeError;

/// Linux caps `/proc/<pid>/comm` at `TASK_COMM_LEN - 1` bytes.
const COMM_MAX: usize = 15;
/// The game client's executable: the PE basename a live install is recognized by.
pub(crate) const GAME_EXE: &str = "ffxiv_dx11.exe";
/// How long to poll for the game to appear before giving up.
const RESOLVE_DEADLINE: Duration = Duration::from_secs(30);
/// How long to wait between `/proc` walks.
const POLL_INTERVAL: Duration = Duration::from_millis(150);
/// How long the runner's own loader must be the only match before it is accepted as the game.
///
/// Wine renames its loader (the process that was spawned) to the PE basename. For a program that
/// runs as one process that loader is the game; for one that starts a separate game process the
/// real process appears before this grace elapses.
const LOADER_STABLE_GRACE: Duration = Duration::from_secs(3);
/// How long to look for a handoff successor before concluding the game is gone. Proton adds loader
/// layers, so a game can hand off more than once.
const SUCCESSOR_GRACE: Duration = Duration::from_secs(2);
/// How long the fallback path waits between liveness checks after `SIGTERM`.
const KILL_GRACE: Duration = Duration::from_millis(100);
/// How many liveness checks the fallback path makes before it escalates to `SIGKILL`.
const KILL_ATTEMPTS: u32 = 20;
/// Total time to wait for a graceful exit before `SIGKILL`.
const KILL_TOTAL_GRACE: Duration = Duration::from_millis(2000);

/// Poll `/proc` until the game process appears, and return its pid.
///
/// A process matches when its `comm` is `program_basename` and its `WINEPREFIX`, normalized for
/// Proton's `/pfx` relocation, is `prefix_path`. `wrapper_pid` is the runner process that was
/// spawned: wine renames that loader to the PE basename and then execs the game, so a match at that
/// pid is preferred against until it has been the only match past [`LOADER_STABLE_GRACE`], which
/// lets a separate game process win when there is one.
///
/// # Errors
/// [`RuntimeError::GameWaitCancelled`] if `cancel` fired, [`RuntimeError::GameProcessNotFound`]
/// once [`RESOLVE_DEADLINE`] passes with nothing matching, and [`RuntimeError::Io`] if `/proc`
/// could not be walked. The first two are the same absence, kept apart because only a launch that
/// broke is worth reporting as one.
pub(crate) async fn resolve_game(
    program_basename: &str,
    prefix_path: &Path,
    wrapper_pid: Option<i32>,
    cancel: &CancellationToken,
) -> Result<i32, RuntimeError> {
    let target = comm_target(program_basename);
    let expected = prefix_path
        .canonicalize()
        .unwrap_or_else(|_| prefix_path.to_path_buf());
    let start = Instant::now();
    loop {
        if cancel.is_cancelled() {
            return Err(RuntimeError::GameWaitCancelled {
                program: program_basename.to_owned(),
                waited: start.elapsed(),
            });
        }
        match scan_matches(&target, &expected) {
            Ok(pids) => {
                if let Some(pid) =
                    pick_game(&pids, wrapper_pid, start.elapsed() >= LOADER_STABLE_GRACE)
                {
                    return Ok(pid);
                }
            }
            Err(source) => {
                return Err(RuntimeError::Io {
                    path: PathBuf::from("/proc"),
                    source,
                });
            }
        }
        if start.elapsed() >= RESOLVE_DEADLINE {
            return Err(RuntimeError::GameProcessNotFound {
                program: program_basename.to_owned(),
                prefix: expected,
                waited: RESOLVE_DEADLINE,
            });
        }
        tokio::time::sleep(POLL_INTERVAL).await;
    }
}

/// The successor a just-exited game process handed off to, if any.
///
/// Wine and Proton rename a loader to the PE basename, exec the game, and exit; a still-live match
/// in the same prefix that is not `prev` is that handoff. Polls for [`SUCCESSOR_GRACE`], then
/// reports `None`, which means the game is really gone.
pub(crate) async fn successor(basename: &str, prefix_path: &Path, prev: i32) -> Option<i32> {
    let target = comm_target(basename);
    let expected = prefix_path
        .canonicalize()
        .unwrap_or_else(|_| prefix_path.to_path_buf());
    let start = Instant::now();
    loop {
        if let Ok(pids) = scan_matches(&target, &expected)
            && let Some(&pid) = pids.iter().find(|&&p| p != prev)
        {
            return Some(pid);
        }
        if start.elapsed() >= SUCCESSOR_GRACE {
            return None;
        }
        tokio::time::sleep(POLL_INTERVAL).await;
    }
}

/// Targeted kill of `pid` through a fresh pidfd, falling back to the numeric signal path.
///
/// # Errors
/// None as it stands: every fallible wait inside [`terminate`] is timed out and discarded, so this
/// only ever returns `Ok`.
pub(crate) async fn terminate_pid(pid: i32) -> Result<(), RuntimeError> {
    terminate(&watch_exit(pid)).await
}

/// Choose the game process from the current matches, or `None` to keep polling.
///
/// Prefers a process that is not the runner's own loader (`wrapper_pid`), and accepts the loader
/// only once `grace_elapsed` says it has been the sole match past the grace window, so a program
/// that runs as a single process still resolves.
fn pick_game(pids: &[i32], wrapper_pid: Option<i32>, grace_elapsed: bool) -> Option<i32> {
    if let Some(&pid) = pids.iter().find(|&&p| Some(p) != wrapper_pid) {
        return Some(pid);
    }
    if grace_elapsed {
        return pids.first().copied();
    }
    None
}

/// All pids whose `comm` and `WINEPREFIX` match, in `/proc` order.
///
/// # Errors
/// Propagates the I/O error of opening or reading `/proc` itself. A pid that races away mid-scan is
/// skipped, not fatal.
pub(crate) fn scan_matches(comm_target: &str, expected_prefix: &Path) -> std::io::Result<Vec<i32>> {
    scan_comm(comm_target, |pid| in_prefix(pid, expected_prefix))
}

/// All pids whose `comm` is `comm_target` and that `belongs` accepts, in `/proc` order.
///
/// `comm` narrows first because it is one short read per pid and rejects nearly everything, but it
/// is only a 15-byte prefix of the name and so answers "which program", never "which instance".
/// `belongs` is what says which instance was meant, from whichever part of `/proc/<pid>` carries
/// its own notion of one.
///
/// # Errors
/// Propagates the I/O error of opening or reading `/proc` itself. A pid that races away mid-scan is
/// skipped, not fatal.
pub(crate) fn scan_comm(
    comm_target: &str,
    belongs: impl Fn(i32) -> bool,
) -> std::io::Result<Vec<i32>> {
    let mut matches = Vec::new();
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
        if belongs(pid) {
            matches.push(pid);
        }
    }
    Ok(matches)
}

/// Whether `pid` declares `expected` as its own `WINEPREFIX`.
///
/// The kernel restricts `environ` to the user who owns the process, so a process this one cannot
/// read is not a match.
fn in_prefix(pid: i32, expected: &Path) -> bool {
    let Ok(environ) = std::fs::read(format!("/proc/{pid}/environ")) else {
        return false;
    };
    find_env(&environ, b"WINEPREFIX").is_some_and(|found| wineprefix_matches(&found, expected))
}

/// Whether the game client is live in the install rooted at `game_root`.
///
/// The same `comm` narrowing the session scanner uses, over a different notion of "which instance":
/// not the prefix a process was launched into but the install its bytes are being read from, which
/// is what a caller about to rewrite those bytes is asking about. The two do not coincide, since one
/// prefix launches whichever install it is pointed at.
///
/// # Errors
/// Propagates the I/O error of opening or reading `/proc` itself.
pub(crate) fn running_in_install(game_root: &Path) -> std::io::Result<bool> {
    let roots = install_roots(game_root);
    let live = scan_comm(&comm_target(GAME_EXE), |pid| in_install(pid, &roots))?;
    Ok(!live.is_empty())
}

/// The forms of `game_root` a process path can be written in: the one the caller passed and, when
/// it differs, the one it canonicalizes to.
///
/// Both are kept because the two `/proc` files are written differently: a `cwd` link is already
/// resolved by the kernel, while argv holds whatever string the launcher was given, symlinks and
/// all.
fn install_roots(game_root: &Path) -> Vec<PathBuf> {
    let mut roots = vec![game_root.to_path_buf()];
    if let Ok(canonical) = game_root.canonicalize()
        && canonical != game_root
    {
        roots.push(canonical);
    }
    roots
}

/// Whether `pid` is working in, or was launched from, one of `roots`.
///
/// Either one is enough. The client runs with the install's `game/` directory as its cwd and is
/// launched by path, so a client started elsewhere matches neither and a second install running
/// from another directory is not mistaken for this one. Both files are restricted to the user who
/// owns the process, so one that cannot be read is not a match.
fn in_install(pid: i32, roots: &[PathBuf]) -> bool {
    // Reading both is what covers the launchers that differ: the cwd link is resolved by the kernel
    // and survives a launcher that passes a wine drive path, while argv survives a launcher that
    // leaves the cwd somewhere else.
    if let Ok(cwd) = std::fs::read_link(format!("/proc/{pid}/cwd"))
        && under_any(&cwd, roots)
    {
        return true;
    }
    let Ok(cmdline) = std::fs::read(format!("/proc/{pid}/cmdline")) else {
        return false;
    };
    cmdline
        .split(|&b| b == 0)
        .any(|arg| under_any(Path::new(OsStr::from_bytes(arg)), roots))
}

/// Whether `path` lies in one of `roots`, compared by whole path component.
///
/// A sibling install whose directory name merely starts with the same characters is not inside it.
fn under_any(path: &Path, roots: &[PathBuf]) -> bool {
    roots.iter().any(|root| path.starts_with(root))
}

/// The `comm` string to match: `basename` truncated to [`COMM_MAX`], on a char boundary.
///
/// Two programs whose names share those first bytes produce the same target and both come back from
/// a scan, so what this yields is a candidate set for the caller to narrow.
pub(crate) fn comm_target(basename: &str) -> String {
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

/// Whether a process's `WINEPREFIX` refers to `expected`.
///
/// Matches the raw path, which is what plain wine sets, or the `pfx`-stripped parent, which is
/// where Proton relocates the live prefix to. Raw first, so a plain-wine prefix whose own directory
/// is named `pfx` still matches.
fn wineprefix_matches(found: &Path, expected: &Path) -> bool {
    if canonical_eq(found, expected) {
        return true;
    }
    if found.file_name() == Some(OsStr::new("pfx"))
        && let Some(parent) = found.parent()
    {
        return canonical_eq(parent, expected);
    }
    false
}

/// Whether `path` canonicalizes to `expected`, comparing literally when it cannot be canonicalized
/// (it no longer exists, say).
fn canonical_eq(path: &Path, expected: &Path) -> bool {
    path.canonicalize().as_deref().unwrap_or(path) == expected
}

/// How a resolved process's exit is observed.
pub(crate) enum ExitWatch {
    /// A pidfd that becomes readable once, on exit (Linux 5.3 and later).
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
///
/// # Errors
/// [`RuntimeError::Io`] if the pidfd could not be polled for readiness. The fallback arm cannot
/// fail.
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

/// Targeted kill: `SIGTERM`, then `SIGKILL` once the grace period has passed.
///
/// A signal sent through a held pidfd hits exactly the process that was resolved and can never
/// reach a recycled pid; the numeric fallback is used only when no pidfd could be opened.
///
/// # Errors
/// None as it stands: the signal sends and the waits are all discarded, so this only ever returns
/// `Ok`.
pub(crate) async fn terminate(watch: &ExitWatch) -> Result<(), RuntimeError> {
    match watch {
        ExitWatch::Pidfd(fd) => {
            let _ = pidfd_send_signal(fd.get_ref(), Signal::TERM);
            // Wait for a graceful exit (the pidfd goes readable) before escalating to SIGKILL.
            if tokio::time::timeout(KILL_TOTAL_GRACE, wait_exit(watch))
                .await
                .is_err()
            {
                // SIGKILL is uncatchable, so wait for the confirmed termination too.
                let _ = pidfd_send_signal(fd.get_ref(), Signal::KILL);
                let _ = tokio::time::timeout(KILL_TOTAL_GRACE, wait_exit(watch)).await;
            }
        }
        ExitWatch::Poll(pid) => {
            signal(*pid, Signal::TERM);
            for _ in 0..KILL_ATTEMPTS {
                if !proc_exists(*pid) {
                    return Ok(());
                }
                tokio::time::sleep(KILL_GRACE).await;
            }
            signal(*pid, Signal::KILL);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;

    use super::*;
    use crate::shim::PROBE;

    /// A stopped wait is its own error, not a game that never appeared. Half a minute passes between
    /// the spawn and the game showing up in `/proc`, which is long enough for a user to think better
    /// of it, and reported as an absence a deliberate stop looks exactly like a broken launch.
    #[tokio::test]
    async fn a_wait_the_token_ended_is_a_cancellation_not_a_process_that_never_appeared() {
        let cancel = CancellationToken::new();
        cancel.cancel();

        let err = resolve_game(
            "ffxiv_dx11.exe",
            Path::new("/nonexistent-prefix"),
            None,
            &cancel,
        )
        .await
        .expect_err("a wait that was stopped resolved no game");
        assert!(err.is_cancellation(), "{err:?}");
        // Which launch was stopped, not just that one was: a consumer logging the stop has nothing
        // else to name it by, the scan having produced no pid.
        let RuntimeError::GameWaitCancelled { program, .. } = &err else {
            panic!("a stopped wait is its own variant, got {err:?}");
        };
        assert_eq!(program, "ffxiv_dx11.exe");
    }

    /// A launch that resolves nothing carries the basename and the prefix it scanned for, which is
    /// where the answer usually is and is not recoverable from a duration. Constructed rather than
    /// waited for: what is pinned is the triage the variant carries, not the polling that reaches it.
    #[test]
    fn a_game_that_never_appeared_names_what_was_scanned_for() {
        let err = RuntimeError::GameProcessNotFound {
            program: "ffxiv_dx11.exe".to_owned(),
            prefix: PathBuf::from("/prefixes/default"),
            waited: RESOLVE_DEADLINE,
        };
        let message = err.to_string();
        assert!(message.contains("ffxiv_dx11.exe"), "{message}");
        assert!(message.contains("/prefixes/default"), "{message}");
        // Not a cancellation: nothing was found either way, and only this one is worth reporting.
        assert!(!err.is_cancellation(), "{err:?}");
    }

    /// The match target is the first 15 bytes the kernel keeps, so any two programs sharing that
    /// prefix scan as the same one and the caller has to narrow.
    #[test]
    fn comm_target_truncates_to_the_kernel_limit() {
        assert_eq!(comm_target("ffxiv_dx11.exe"), "ffxiv_dx11.exe");
        assert_eq!(comm_target("a_very_long_process_name"), "a_very_long_pro"); // 15 bytes
    }

    /// The runner's own loader, which wears the same name, never wins over a second match, and on
    /// its own before the grace it resolves nothing rather than being locked onto.
    #[test]
    fn pick_game_prefers_the_real_process_over_the_loader() {
        // Wine renames the loader (the spawned wrapper) to the PE basename, then execs the game.
        // While only the loader is visible, keep waiting rather than lock onto the transient.
        assert_eq!(pick_game(&[10], Some(10), false), None);
        // The real game appears alongside (or after) the loader: prefer it.
        assert_eq!(pick_game(&[10, 42], Some(10), false), Some(42));
        assert_eq!(pick_game(&[42], Some(10), false), Some(42));
    }

    /// A program that runs as one process still resolves: past the grace the loader is the game.
    /// An empty scan resolves nothing either way.
    #[test]
    fn pick_game_accepts_the_loader_once_stable() {
        // A single-process program: the loader is the game and never hands off, so accept it after
        // the grace window.
        assert_eq!(pick_game(&[10], Some(10), true), Some(10));
        // Nothing to pick yet, grace or not.
        assert_eq!(pick_game(&[], Some(10), true), None);
        assert_eq!(pick_game(&[], Some(10), false), None);
    }

    /// With no wrapper pid to prefer against there is nothing to exclude, so the first match wins.
    #[test]
    fn pick_game_without_a_known_wrapper_takes_the_first_match() {
        assert_eq!(pick_game(&[42], None, false), Some(42));
    }

    /// `environ` is NUL-separated `KEY=value` records, and a key that is not there reads as absent
    /// rather than as an empty value.
    #[test]
    fn find_env_reads_a_nul_separated_value() {
        let environ = b"HOME=/root\0WINEPREFIX=/prefix/pfx\0LANG=C\0";
        assert_eq!(
            find_env(environ, b"WINEPREFIX"),
            Some(PathBuf::from("/prefix/pfx"))
        );
        assert_eq!(find_env(environ, b"MISSING"), None);
    }

    /// Both runners are recognized from the one prefix path: plain wine declares the prefix itself,
    /// Proton declares the `pfx` directory it relocates into. A different prefix matches neither.
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

    /// The Proton normalization must not eat a plain-wine prefix whose own directory is literally
    /// `pfx`: the raw path is compared first, so it matches itself rather than its parent.
    #[test]
    fn wineprefix_matches_a_plain_wine_prefix_named_pfx() {
        let dir = tempfile::tempdir().expect("tempdir");
        let prefix = dir.path().join("pfx");
        std::fs::create_dir(&prefix).expect("mkdir pfx");
        let expected = prefix.canonicalize().expect("canonicalize");
        // A plain-wine prefix whose own directory is literally `pfx` must match via the raw path.
        assert!(wineprefix_matches(&prefix, &expected));
    }

    /// Containment is by path component, which a string prefix would get wrong: a second install
    /// whose directory name merely begins with the first one's would guard the wrong tree.
    #[test]
    fn under_any_compares_whole_components() {
        let roots = vec![PathBuf::from("/games/ffxiv")];
        assert!(under_any(Path::new("/games/ffxiv/game"), &roots));
        assert!(under_any(Path::new("/games/ffxiv"), &roots));
        // The failure a string prefix would produce: a second install whose directory name merely
        // begins with the first one's would guard the wrong tree.
        assert!(!under_any(Path::new("/games/ffxiv-ps4/game"), &roots));
        assert!(!under_any(Path::new("/games"), &roots));
        // An argv entry that is not a path at all (the client is passed its own options too).
        assert!(!under_any(Path::new(""), &roots));
    }

    /// A launcher handed a symlink writes the link into argv while the kernel resolves the same
    /// process's cwd to the real path, so the guard has to hold both forms. A path already canonical
    /// contributes one root, not the same one twice.
    #[test]
    fn install_roots_keeps_the_path_as_passed_beside_the_resolved_one() {
        let dir = tempfile::tempdir().expect("tempdir");
        let real = dir.path().join("install");
        std::fs::create_dir(&real).expect("mkdir install");
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&real, &link).expect("symlink");

        // A launcher handed the link writes the link into argv, while the kernel resolves the same
        // process's cwd to the real path: the guard has to recognize its install in both.
        let roots = install_roots(&link);
        assert!(under_any(&link.join("game"), &roots));
        assert!(under_any(&real.join("game"), &roots));

        // A path already canonical contributes one root, not the same one twice.
        let canonical = real.canonicalize().expect("canonicalize");
        assert_eq!(install_roots(&canonical), vec![canonical]);
    }

    /// The whole scan against a live process, the only way to prove the `/proc` reads agree with
    /// what the kernel publishes.
    ///
    /// A script exec'd by path is named by its own basename in `comm`, and its cwd link resolves
    /// under the install. A shell script stands in for the client because what is matched is a name
    /// and a directory, neither of which needs a game.
    ///
    /// The client runs in the install whose directory name *extends* the guarded one's, the
    /// arrangement that separates a component compare from a string compare. Named the other way
    /// round the test passes either way.
    #[test]
    fn a_client_in_the_install_is_live_and_the_same_client_elsewhere_is_not() {
        let dir = tempfile::tempdir().expect("tempdir");
        // The install about to be patched: nothing is running in it.
        let install = dir.path().join("FFXIV");
        // The install the client is actually running in.
        let other = dir.path().join("FFXIV-second");
        let game_dir = other.join("game");
        std::fs::create_dir_all(&game_dir).expect("mkdir game");
        std::fs::create_dir_all(&install).expect("mkdir the guarded install");

        let exe = game_dir.join(GAME_EXE);
        // Blocks on a pipe nothing is written to, so the process lives exactly as long as the test
        // holds its stdin and leaves no descendant behind when it goes.
        std::fs::write(
            &exe,
            format!("#!/bin/sh\n[ \"$1\" = {PROBE} ] && exit 0\nread line\n"),
        )
        .expect("write client");
        std::fs::set_permissions(&exe, std::fs::Permissions::from_mode(0o755)).expect("chmod");
        crate::shim::wait_until_runnable(&exe);

        let mut child = std::process::Command::new(&exe)
            .current_dir(&game_dir)
            .stdin(std::process::Stdio::piped())
            .spawn()
            .expect("spawn the stand-in client");

        // The spawn returns before the child has exec'd, so its name in `/proc` is still the parent's
        // for a moment.
        let seen = (0..RUNNING_POLLS).any(|_| {
            if running_in_install(&other).expect("scan /proc") {
                return true;
            }
            std::thread::sleep(RUNNING_POLL_INTERVAL);
            false
        });
        assert!(seen, "a client running in the install was not seen");
        assert!(
            !running_in_install(&install).expect("scan /proc"),
            "a client running in another install was taken for this one",
        );

        let _ = child.kill();
        let _ = child.wait();
        assert!(
            !running_in_install(&other).expect("scan /proc"),
            "the install still reads as running after the client exited",
        );
    }

    /// How many polls the stand-in client is given to reach its `execve`.
    ///
    /// A spawn returns before the child has exec'd, so its `comm` is still the parent's for a
    /// moment, and calling the scan wrong before then would be calling it wrong too early.
    const RUNNING_POLLS: u32 = 200;
    /// How long each of those polls waits.
    const RUNNING_POLL_INTERVAL: Duration = Duration::from_millis(10);
}

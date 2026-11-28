//! The game session a launch leaves behind it, found and ended by its process tree.
//!
//! A companion that outlives its game, or a launcher that dies mid-session, can leave the game's
//! container running. Asking wine to end it is not enough: `wineboot -k` closes ordinary windows but
//! not every program, and under umu each container has a private `/tmp`, so a second launch cannot
//! even reach the first one's wine server and starts another on the same prefix. What every
//! namespace can see is the process tree (parent links in `/proc/<pid>/stat` are world-readable) and
//! what the kernel lets one user do to their own processes anywhere (signal them). So each launch
//! records the root of the game's tree, with its start time so a reused pid is never mistaken for it,
//! and the next launch ends that tree when it is still alive and the game is not.

use std::path::{Path, PathBuf};
use std::time::Duration;

fn record_path(prefix: &Path) -> PathBuf {
    prefix.join("apogee-session")
}

/// The fields of `/proc/<pid>/stat` after the command name, which may itself hold spaces and parens.
fn stat_fields(pid: i32) -> Option<Vec<String>> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let rest = stat.get(stat.rfind(')')? + 1..)?;
    Some(rest.split_whitespace().map(str::to_owned).collect())
}

fn parent(pid: i32) -> Option<i32> {
    stat_fields(pid)?.get(1)?.parse().ok()
}

/// When the process started, in clock ticks since boot: with the pid, an identity no reuse can fake.
fn start_time(pid: i32) -> Option<u64> {
    stat_fields(pid)?.get(19)?.parse().ok()
}

/// The ancestor of `game_pid` this launcher spawned: the root of everything the launch started.
fn launch_root(game_pid: i32, launcher_pid: i32) -> Option<i32> {
    let mut current = game_pid;
    for _ in 0..64 {
        let up = parent(current)?;
        if up == launcher_pid {
            return Some(current);
        }
        if up <= 1 {
            return None;
        }
        current = up;
    }
    None
}

/// Record the root of the launch that started `game_pid` in `prefix`. Best effort: without a record
/// the next launch falls back to asking wine.
pub(crate) fn record(prefix: &Path, game_pid: i32) {
    let Some(root) = launch_root(game_pid, std::process::id().cast_signed()) else {
        return;
    };
    let Some(started) = start_time(root) else {
        return;
    };
    if let Err(error) = std::fs::write(record_path(prefix), format!("{root} {started}\n")) {
        tracing::warn!(%error, "the game session was not recorded");
    }
}

/// The recorded root, when it is still the same live process.
fn live_root(prefix: &Path) -> Option<i32> {
    let text = std::fs::read_to_string(record_path(prefix)).ok()?;
    let mut parts = text.split_whitespace();
    let pid: i32 = parts.next()?.parse().ok()?;
    let started: u64 = parts.next()?.parse().ok()?;
    // A zombie has ended; it only waits for its parent to collect it.
    let running = stat_fields(pid).is_some_and(|f| f.first().is_some_and(|state| state != "Z"));
    (pid > 1 && running && start_time(pid) == Some(started)).then_some(pid)
}

/// `root` and every process below it.
fn tree(root: i32) -> Vec<i32> {
    let mut parents: Vec<(i32, i32)> = Vec::new();
    if let Ok(entries) = std::fs::read_dir("/proc") {
        for entry in entries.flatten() {
            if let Some(pid) = entry
                .file_name()
                .to_str()
                .and_then(|s| s.parse::<i32>().ok())
                && let Some(up) = parent(pid)
            {
                parents.push((pid, up));
            }
        }
    }
    let mut found = vec![root];
    let mut index = 0;
    while let Some(&current) = found.get(index) {
        found.extend(
            parents
                .iter()
                .filter(|&&(_, up)| up == current)
                .map(|&(pid, _)| pid),
        );
        index += 1;
    }
    found
}

fn signal(pids: &[i32], signal: rustix::process::Signal) {
    for &pid in pids {
        if let Some(pid) = rustix::process::Pid::from_raw(pid) {
            let _ = rustix::process::kill_process(pid, signal);
        }
    }
}

/// End the recorded session in `prefix`, when it is still running. Returns whether there was one.
///
/// The caller has already established that the game is not running; this never looks for it.
pub(crate) async fn end_recorded(prefix: &Path) -> bool {
    let Some(root) = live_root(prefix) else {
        return false;
    };
    tracing::info!(root, "ending the session a previous launch left running");
    signal(&tree(root), rustix::process::Signal::TERM);
    for _ in 0..10 {
        tokio::time::sleep(Duration::from_millis(500)).await;
        if live_root(prefix).is_none() {
            return true;
        }
    }
    signal(&tree(root), rustix::process::Signal::KILL);
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A recorded session is ended with everything under it, and a record naming a process that has
    /// since gone, or a reused pid, ends nothing.
    #[tokio::test]
    async fn a_recorded_tree_is_ended_and_a_stale_record_is_ignored() {
        let dir = tempfile::tempdir().unwrap();
        // A root with a child of its own, standing in for umu and the programs under it.
        let mut root = std::process::Command::new("sh")
            .args(["-c", "sleep 30 & wait"])
            .spawn()
            .unwrap();
        let root_pid = root.id().cast_signed();
        tokio::time::sleep(Duration::from_millis(200)).await;
        let started = start_time(root_pid).unwrap();
        std::fs::write(record_path(dir.path()), format!("{root_pid} {started}\n")).unwrap();
        let below = tree(root_pid);
        assert!(below.len() >= 2, "{below:?}");

        assert!(end_recorded(dir.path()).await);
        let _ = root.wait();
        let running =
            |pid: i32| stat_fields(pid).is_some_and(|f| f.first().is_some_and(|s| s != "Z"));
        assert!(below.iter().all(|&pid| !running(pid)), "{below:?}");
        assert!(live_root(dir.path()).is_none());

        // The same pid with a different start time is someone else's process now.
        std::fs::write(
            record_path(dir.path()),
            format!("{} 1\n", std::process::id()),
        )
        .unwrap();
        assert!(!end_recorded(dir.path()).await);
    }
}

//! Recognizing a companion that is already running.
//!
//! The point of this check is the tool the user opened themselves, or left over from the last
//! session, so it has to look at the machine rather than at a list of what this launcher started.
//! What it must not do is collapse different tools together: matching on a bare file name means an
//! unrelated `updater.exe` anywhere on the box suppresses yours, and two tools with the same name in
//! different directories become one.
//!
//! So identity is the whole program. For a host tool that is the executable behind `/proc`, or the
//! script an interpreter was handed. For a prefix tool the process table can only be searched by a
//! name the kernel truncates to 15 bytes, so that search is a candidate set and the full path in the
//! process's own arguments is what narrows it.
//!
//! Every check is scoped to processes the launching user owns. Process arguments are world-readable,
//! so without that a second account on the machine could suppress a tool permanently by running
//! anything with the right path in its command line.
//!
//! The check fails open. When nothing can be established the companion starts: a duplicate is a
//! smaller harm than a tool that silently never runs, and these tools are usually singletons anyway.

use std::path::Path;
#[cfg(target_os = "linux")]
use std::path::PathBuf;

use apogee_runtime::Prefix;

/// A process that appears to be this program already running.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Running {
    /// The process id that matched.
    pub pid: i32,
}

/// Whether `pid` belongs to the user running this launcher.
///
/// The command-line check below reads a world-readable file, so this is what keeps another local
/// account from suppressing a companion by running something with a matching argument.
#[cfg(target_os = "linux")]
fn owned_by_us(pid: i32) -> bool {
    use std::os::unix::fs::MetadataExt;
    std::fs::metadata(format!("/proc/{pid}"))
        .map(|m| m.uid() == rustix::process::geteuid().as_raw())
        .unwrap_or(false)
}

/// The argument vector of `pid`, split on the separator the kernel uses.
#[cfg(target_os = "linux")]
fn argv(pid: i32) -> Vec<String> {
    std::fs::read(format!("/proc/{pid}/cmdline"))
        .map(|raw| {
            raw.split(|&b| b == 0)
                .filter(|part| !part.is_empty())
                .map(|part| String::from_utf8_lossy(part).into_owned())
                .collect()
        })
        .unwrap_or_default()
}

/// The executable behind `pid`, if it can be read.
#[cfg(target_os = "linux")]
fn exe(pid: i32) -> Option<PathBuf> {
    std::fs::read_link(format!("/proc/{pid}/exe")).ok()
}

/// Whether two host paths name the same file, resolving links where possible.
#[cfg(target_os = "linux")]
fn same_file(a: &Path, b: &Path) -> bool {
    let left = a.canonicalize().unwrap_or_else(|_| a.to_path_buf());
    let right = b.canonicalize().unwrap_or_else(|_| b.to_path_buf());
    left == right
}

/// Whether a host process is this program.
///
/// Either the process *is* the program, or an interpreter was handed the program as its first
/// argument. Restricting the second to that one position is what keeps `grep pat /path/tool.sh`, a
/// backup reading the file, and a second launcher invocation naming it from counting as the tool
/// already running.
#[cfg(target_os = "linux")]
fn host_process_matches(pid: i32, program: &Path) -> bool {
    if let Some(found) = exe(pid) {
        if same_file(&found, program) {
            return true;
        }
        // Not the program itself, so the only other shape that counts is an interpreter running it.
        let args = argv(pid);
        return args
            .get(1)
            .is_some_and(|script| same_file(Path::new(script), program));
    }
    false
}

/// Find a host companion that is already running.
#[cfg(target_os = "linux")]
pub(crate) fn find_host(program: &Path) -> Option<Running> {
    let me = std::process::id().cast_signed();
    let entries = std::fs::read_dir("/proc").ok()?;
    for entry in entries.flatten() {
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|name| name.parse::<i32>().ok())
        else {
            continue;
        };
        if pid == me || !owned_by_us(pid) {
            continue;
        }
        if host_process_matches(pid, program) {
            return Some(Running { pid });
        }
    }
    None
}

/// Whether a candidate found by name is really this program, by looking for its full path in the
/// process's own arguments.
///
/// Two spellings count, because both were observed from real runners: the host path, which plain
/// wine passes through, and the prefix's own Windows path, which the Proton loader rewrites it into.
/// Separators and case are folded, since the Windows form uses backslashes and is case-insensitive.
#[cfg_attr(
    not(target_os = "linux"),
    expect(dead_code, reason = "only the process probe calls this")
)]
pub(crate) fn prefix_argv_matches(argv0: &str, program: &Path, windows: Option<&str>) -> bool {
    let normalize = |s: &str| s.replace('\\', "/").to_lowercase();
    let found = normalize(argv0);
    if found == normalize(&program.to_string_lossy()) {
        return true;
    }
    windows.is_some_and(|w| found == normalize(w))
}

/// Find a prefix companion that is already running, narrowing `candidates` to this exact program.
///
/// `candidates` come from a search keyed on a name the kernel truncates, so without this narrowing
/// two tools whose names agree for 15 bytes collapse into one and the game itself can match.
#[cfg(target_os = "linux")]
pub(crate) fn find_in_prefix(
    candidates: &[i32],
    program: &Path,
    prefix: &Prefix,
    game_pid: i32,
) -> Option<Running> {
    let windows = prefix
        .drive_map()
        .ok()
        .and_then(|m| m.to_windows(program).ok());
    candidates
        .iter()
        .copied()
        .filter(|pid| *pid != game_pid && owned_by_us(*pid))
        .find(|pid| {
            argv(*pid)
                .first()
                .is_some_and(|argv0| prefix_argv_matches(argv0, program, windows.as_deref()))
        })
        .map(|pid| Running { pid })
}

#[cfg(not(target_os = "linux"))]
pub(crate) fn find_host(_program: &Path) -> Option<Running> {
    None
}

#[cfg(not(target_os = "linux"))]
pub(crate) fn find_in_prefix(
    _candidates: &[i32],
    _program: &Path,
    _prefix: &Prefix,
    _game_pid: i32,
) -> Option<Running> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Both spellings of the same program count, because the runner decides which one appears and
    /// the two observed runners disagree.
    #[test]
    fn either_spelling_of_the_program_path_identifies_it() {
        let program = Path::new("/home/u/tools/ACT/Advanced Combat Tracker.exe");
        let windows = Some(r"Z:\home\u\tools\ACT\Advanced Combat Tracker.exe");

        assert!(prefix_argv_matches(
            "/home/u/tools/ACT/Advanced Combat Tracker.exe",
            program,
            windows
        ));
        assert!(prefix_argv_matches(
            r"Z:\home\u\tools\ACT\Advanced Combat Tracker.exe",
            program,
            windows
        ));
        // Case folds, because the Windows form is case-insensitive.
        assert!(prefix_argv_matches(
            r"z:\HOME\u\tools\act\ADVANCED COMBAT TRACKER.EXE",
            program,
            windows
        ));
    }

    /// The narrowing exists so that names sharing the kernel's 15-byte limit stay distinct. Without
    /// it these two are one tool.
    #[test]
    fn programs_that_agree_for_the_first_fifteen_bytes_stay_distinct() {
        let thirty_two = Path::new("/opt/xa/XIVAlexanderLoader32.exe");
        let sixty_four = Path::new("/opt/xa/XIVAlexanderLoader64.exe");
        // Both truncate to the same kernel-visible name, so both arrive as candidates.
        assert_eq!(
            &"XIVAlexanderLoader32.exe"[..15],
            &"XIVAlexanderLoader64.exe"[..15]
        );
        assert!(prefix_argv_matches(
            "/opt/xa/XIVAlexanderLoader32.exe",
            thirty_two,
            None
        ));
        assert!(!prefix_argv_matches(
            "/opt/xa/XIVAlexanderLoader32.exe",
            sixty_four,
            None
        ));
    }

    /// An unrelated tool with a common name does not suppress ours.
    #[test]
    fn a_different_program_with_the_same_name_does_not_match() {
        let ours = Path::new("/opt/mine/updater.exe");
        assert!(!prefix_argv_matches("/opt/theirs/updater.exe", ours, None));
    }

    /// The running launcher must never see itself as the tool it is about to start.
    #[cfg(target_os = "linux")]
    #[test]
    fn the_search_skips_our_own_process() {
        let me = std::env::current_exe().expect("current exe");
        // The test binary is running right now, so a search for it must not find this process.
        assert_ne!(
            find_host(&me).map(|r| r.pid),
            Some(std::process::id().cast_signed())
        );
    }

    /// A real running process is found by its own executable path.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_running_program_is_found_by_its_path() {
        let mut child = std::process::Command::new("/bin/sleep")
            .arg("2")
            .spawn()
            .expect("spawn");
        // Give it a moment to appear in the process table.
        std::thread::sleep(std::time::Duration::from_millis(100));

        let found = find_host(Path::new("/bin/sleep"));
        let _ = child.kill();
        let _ = child.wait();
        assert!(found.is_some(), "a running program was not recognized");
    }
}

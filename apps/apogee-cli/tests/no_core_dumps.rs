#![cfg(target_os = "linux")]
//! The launcher's memory must not reach disk when it dies.
//!
//! The sealed secret file derives its key once and holds it for the run, so a dump taken while the
//! store is open carries the key, and the key plus the file beside it is every stored password. The
//! three assertions below are the mechanism (the dumpable flag, the core limit) and the outcome (a
//! real `SIGABRT` that writes nothing), because the mechanism alone can be right on this host and
//! wrong on another, and the outcome alone is silently satisfied on a host that already forbids
//! dumps.

use std::io::Read;
use std::os::unix::fs::MetadataExt;
use std::os::unix::process::ExitStatusExt;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use tempfile::TempDir;

/// Long enough for a debug binary to reach the top of `main` on a loaded machine.
const STARTUP: Duration = Duration::from_secs(20);

/// Start the binary on a verb that blocks reading stdin, so it stays alive to be inspected.
///
/// `secrets backend --to file` prints what a sealed file costs and then waits for a typed
/// confirmation. Its stdin is a pipe this test never writes to and never closes.
fn blocked_launcher(home: &Path) -> std::io::Result<Child> {
    Command::new(env!("CARGO_BIN_EXE_apogee-cli"))
        .args(["secrets", "backend", "--to", "file"])
        .env("HOME", home)
        .env("XDG_CONFIG_HOME", home.join("config"))
        .env("XDG_DATA_HOME", home.join("data"))
        .env("XDG_CACHE_HOME", home.join("cache"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
}

/// Wait until `pid` has hardened itself, or give up.
///
/// `/proc/<pid>` is owned by the running user while the process is dumpable and by root once it is
/// not, and `execve` resets the flag to dumpable, so root here is this process's own doing and
/// cannot have been inherited from the test harness.
fn wait_until_undumpable(pid: u32) -> bool {
    let deadline = Instant::now() + STARTUP;
    while Instant::now() < deadline {
        if std::fs::metadata(format!("/proc/{pid}/status")).is_ok_and(|m| m.uid() == 0) {
            return true;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    false
}

/// The soft and hard `RLIMIT_CORE` of `pid`, as `/proc` renders them.
fn core_limit(pid: u32) -> std::io::Result<String> {
    let limits = std::fs::read_to_string(format!("/proc/{pid}/limits"))?;
    Ok(limits
        .lines()
        .find(|line| line.starts_with("Max core file size"))
        .unwrap_or_default()
        .split_whitespace()
        .rev()
        .skip(1)
        .take(2)
        .collect::<Vec<_>>()
        .join(" "))
}

#[test]
fn a_launcher_that_dies_writes_no_core_dump() -> std::io::Result<()> {
    let home = TempDir::new()?;
    let mut child = blocked_launcher(home.path())?;
    let pid = child.id();

    assert!(
        wait_until_undumpable(pid),
        "the launcher stayed dumpable: /proc/{pid} is not root-owned"
    );
    assert_eq!(core_limit(pid)?, "0 0", "the core size limit is not zero");

    // The outcome the two flags exist for: a signal whose default action is to dump, and a wait
    // status that says nothing was written.
    let Some(target) = rustix::process::Pid::from_raw(i32::try_from(pid).unwrap_or_default())
    else {
        return Err(std::io::Error::other("the child's pid is out of range"));
    };
    rustix::process::kill_process(target, rustix::process::Signal::ABORT)?;
    let status = child.wait()?;
    assert_eq!(
        status.signal(),
        Some(rustix::process::Signal::ABORT.as_raw()),
        "the launcher did not die of the signal it was sent"
    );
    assert!(
        !status.core_dumped(),
        "the launcher's memory was written to disk"
    );

    // Nothing here should have leaked the reason it was inspectable at all.
    let mut stderr = String::new();
    if let Some(pipe) = child.stderr.as_mut() {
        pipe.read_to_string(&mut stderr)?;
    }
    assert!(
        !stderr.contains("warning:"),
        "the hardening did not take: {stderr}"
    );
    Ok(())
}

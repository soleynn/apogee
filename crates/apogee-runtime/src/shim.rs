//! A prefix whose "runner" is a shell script standing in for `wine`, so the spawn paths can be
//! exercised without one.
//!
//! Writing an executable and then running it races the rest of the test binary. Every sibling thread
//! is forking children of its own, and a fork that lands while this file is still open for writing
//! gives that child a copy of the descriptor. Until the child reaches its own `execve` the kernel
//! refuses to run the script, so the spawn fails with `ETXTBSY` and the test reports whatever its
//! subject was as broken. It is worse than noise in the tests that assert something is *not* a
//! cancellation, because a spawn failure is not one either, so they pass for the wrong reason.
//!
//! The window closes on its own once every child that inherited the descriptor has exec'd, so the
//! shim answers a probe argument before it does anything else and [`scripted_prefix`] runs that
//! probe until it succeeds. By the time a prefix is handed back, the script is known to be runnable.

use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use crate::catalog::RunnerKind;
use crate::plan::{Prefix, RunnerHandle};

/// The argument a shim answers before running its body. Passed only by [`wait_until_runnable`].
pub(crate) const PROBE: &str = "--shim-probe";

/// How many times a probe may come back `ETXTBSY` before the helper gives up.
///
/// Each inheriting child clears the descriptor as it execs, so this drains in microseconds in
/// practice; the ceiling exists so a genuinely unrunnable script fails as itself rather than
/// hanging the suite.
const PROBE_ATTEMPTS: u32 = 500;

/// A prefix whose runner is `body` wrapped in a shell script.
///
/// The script sees the composed argv (`wine reg add ...`) as its own, so a test reads back exactly
/// what the spawn path passed, and exits with whatever status the body asks for. The returned
/// directory owns the prefix: keep it alive for as long as the prefix is used.
pub(crate) fn scripted_prefix(body: &str) -> (tempfile::TempDir, Prefix) {
    let dir = tempfile::tempdir().expect("tempdir");
    let runner_dir = dir.path().join("runner");
    std::fs::create_dir_all(runner_dir.join("bin")).expect("bin");
    let wine = runner_dir.join("bin/wine");
    std::fs::write(
        &wine,
        format!("#!/bin/sh\n[ \"$1\" = {PROBE} ] && exit 0\n{body}\n"),
    )
    .expect("write shim");
    std::fs::set_permissions(&wine, std::fs::Permissions::from_mode(0o755)).expect("chmod");
    wait_until_runnable(&wine);

    let handle = RunnerHandle::for_test(runner_dir, RunnerKind::Wine, "shim", "custom");
    let prefix = Prefix::new(dir.path().join("prefix"), handle);
    (dir, prefix)
}

/// Run the shim's probe until it starts, so no descriptor a sibling's fork inherited is still open
/// against it when the test spawns for real.
///
/// Panics if the script cannot be run at all, or is still busy after [`PROBE_ATTEMPTS`] probes.
pub(crate) fn wait_until_runnable(shim: &Path) {
    for _ in 0..PROBE_ATTEMPTS {
        match std::process::Command::new(shim).arg(PROBE).status() {
            Ok(_) => return,
            Err(e) if e.kind() == std::io::ErrorKind::ExecutableFileBusy => {
                std::thread::yield_now();
            }
            Err(e) => panic!("the shim is not runnable at all: {e}"),
        }
    }
    panic!("the shim stayed busy for {PROBE_ATTEMPTS} probes");
}

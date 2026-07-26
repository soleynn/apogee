//! A companion program run alongside the game: a native tool on the host, or a Windows one run
//! inside a prefix through the runner.
//!
//! The game is supervised by scanning `/proc` for the process the runner renamed itself into
//! ([`crate::GameSession`]); a companion is not, because it is an ordinary child with an ordinary
//! exit status. What it does need is a stop that reaches the tool a launcher script backgrounded,
//! so every companion leads its own process group and the stop signals the group.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use rustix::process::{Pid, Signal, kill_process_group};
use tokio::process::{Child, Command};

use crate::error::RuntimeError;
use crate::plan::Prefix;
use crate::spawn::{prefix_env, prefix_launcher, resolve_umu};
use crate::supervise::{ExitWatch, wait_exit, watch_exit};

/// What to run and where.
#[derive(Debug, Clone)]
pub struct CompanionSpec {
    program: PathBuf,
    args: Vec<String>,
    prefix: Option<Prefix>,
    env: BTreeMap<String, String>,
    working_dir: Option<PathBuf>,
}

impl CompanionSpec {
    /// A companion run directly on the host: a native binary, invoked with an argv list that is
    /// passed through verbatim (no shell, so no quoting rules and no word splitting).
    #[must_use]
    pub fn host(program: impl Into<PathBuf>, args: Vec<String>) -> Self {
        Self {
            program: program.into(),
            args,
            prefix: None,
            env: BTreeMap::new(),
            working_dir: None,
        }
    }

    /// A companion run inside `prefix` through its runner, for a Windows executable.
    #[must_use]
    pub fn in_prefix(program: impl Into<PathBuf>, args: Vec<String>, prefix: &Prefix) -> Self {
        Self {
            prefix: Some(prefix.clone()),
            ..Self::host(program, args)
        }
    }

    /// Add environment variables for the child. Merged after the prefix variables, so a caller can
    /// override them.
    #[must_use]
    pub fn env(mut self, env: BTreeMap<String, String>) -> Self {
        self.env = env;
        self
    }

    /// Set the child's working directory.
    #[must_use]
    pub fn working_dir(mut self, dir: impl Into<PathBuf>) -> Self {
        self.working_dir = Some(dir.into());
        self
    }

    /// The prefix this companion runs in, if it is not a host tool.
    #[must_use]
    pub fn prefix_ref(&self) -> Option<&Prefix> {
        self.prefix.as_ref()
    }
}

/// How a companion process ended.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct CompanionExit {
    /// The exit status, or `None` when the process was ended by a signal.
    pub code: Option<i32>,
}

/// A running companion process and its process group.
#[derive(Debug)]
pub struct Companion {
    child: Child,
    pid: i32,
    name: String,
}

impl Companion {
    /// The unix PID of the spawned process, which is also its process-group id.
    #[must_use]
    pub fn pid(&self) -> i32 {
        self.pid
    }

    /// Wait for the companion to exit and reap it.
    ///
    /// # Errors
    /// [`RuntimeError::Spawn`] if the process could not be waited on.
    pub async fn wait(&mut self) -> Result<CompanionExit, RuntimeError> {
        let status = self
            .child
            .wait()
            .await
            .map_err(|source| RuntimeError::Spawn {
                runner: self.name.clone(),
                source,
            })?;
        Ok(CompanionExit {
            code: status.code(),
        })
    }

    /// Stop the companion and everything it started: `SIGTERM` to its process group, then `SIGKILL`
    /// to the group once `grace` has elapsed or the leader has exited.
    ///
    /// The leader is watched through a pidfd rather than reaped, so it stays a zombie for the whole
    /// sequence. That matters twice: it anchors the group id, so the final `SIGKILL` cannot land on
    /// a recycled one, and it means a launcher script that exits immediately after backgrounding the
    /// real tool does not end the sequence early. The group is signalled either way, so the
    /// backgrounded tool is reached rather than orphaned.
    ///
    /// # Errors
    /// [`RuntimeError::Spawn`] if the process could not be reaped after being signalled.
    pub async fn stop(&mut self, grace: Duration) -> Result<(), RuntimeError> {
        let Some(pid) = Pid::from_raw(self.pid) else {
            return self.reap().await;
        };
        // Opened before the first signal, so the exit cannot be missed between signalling and
        // watching.
        let watch = watch_exit(self.pid);
        let _ = kill_process_group(pid, Signal::TERM);
        if matches!(watch, ExitWatch::Pidfd(_)) {
            let _ = tokio::time::timeout(grace, wait_exit(&watch)).await;
        } else {
            // No pidfd: the leader cannot be watched without reaping it, so wait out the grace.
            tokio::time::sleep(grace).await;
        }
        // Unconditional: the group holds at most the zombie leader by now, and signalling a zombie
        // is a no-op, so this costs nothing when the companion stopped cleanly.
        let _ = kill_process_group(pid, Signal::KILL);
        self.reap().await
    }

    /// Reap the leader, discarding its status.
    async fn reap(&mut self) -> Result<(), RuntimeError> {
        self.child
            .wait()
            .await
            .map_err(|source| RuntimeError::Spawn {
                runner: self.name.clone(),
                source,
            })?;
        Ok(())
    }
}

/// Spawn `spec`, resolving the runner launcher for a prefix companion from `tools_dir`.
pub(crate) fn spawn(spec: &CompanionSpec, tools_dir: &Path) -> Result<Companion, RuntimeError> {
    let name = spec
        .program
        .file_name()
        .map_or_else(|| spec.program.to_string_lossy(), |n| n.to_string_lossy())
        .into_owned();

    let mut command = match spec.prefix.as_ref() {
        Some(prefix) => {
            let umu = resolve_umu(tools_dir);
            let launcher = prefix_launcher(prefix, umu.as_deref())?;
            let mut command = Command::new(launcher);
            command.arg(&spec.program);
            prefix_env(&mut command, prefix);
            command
        }
        None => Command::new(&spec.program),
    };
    command.args(&spec.args);
    for (key, value) in &spec.env {
        command.env(key, value);
    }
    if let Some(dir) = &spec.working_dir {
        command.current_dir(dir);
    }
    // A companion is not the user's terminal session: its output would otherwise interleave with the
    // launcher's own, and a prompt on inherited stdin would block the launch.
    command.stdin(Stdio::null());
    command.stdout(Stdio::null());
    command.stderr(Stdio::null());
    // Its own group, so the stop reaches descendants and can never reach the game or another
    // companion. Zero means "use the child's own pid", which is what makes it the leader.
    command.process_group(0);
    // The handle owns the stop; dropping it must not kill a companion the caller still expects to
    // be running.
    command.kill_on_drop(false);

    let child = command.spawn().map_err(|source| RuntimeError::Spawn {
        runner: name.clone(),
        source,
    })?;
    let pid = child
        .id()
        .ok_or(RuntimeError::InvalidLaunchPlan {
            reason: "companion exited before its pid could be read",
        })?
        .cast_signed();

    Ok(Companion { child, pid, name })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The group stop must reach a process the companion backgrounded and left behind. A shell that
    /// starts a sleeper and exits immediately is the shim shape that orphans a descendant when the
    /// stop only follows the direct child.
    #[tokio::test]
    async fn stopping_a_companion_reaches_a_process_it_backgrounded() {
        let dir = tempfile::tempdir().expect("tempdir");
        let marker = dir.path().join("alive");
        // The leader backgrounds a loop that keeps recreating the marker, then exits at once.
        let spec = CompanionSpec::host(
            "/bin/sh",
            vec![
                "-c".into(),
                format!(
                    "while :; do : > {}; sleep 0.05; done & exit 0",
                    marker.display()
                ),
            ],
        );
        let mut companion = spawn(&spec, dir.path()).expect("spawn");

        // The leader exits at once; the backgrounded loop keeps refreshing the marker.
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert!(marker.exists(), "the backgrounded process ran");

        companion
            .stop(Duration::from_millis(100))
            .await
            .expect("stop");
        std::fs::remove_file(&marker).expect("clear the marker");
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert!(
            !marker.exists(),
            "the backgrounded process was stopped with the group, not orphaned"
        );
    }

    /// A companion that ignores `SIGTERM` must still be stopped once the grace expires.
    #[tokio::test]
    async fn a_companion_that_ignores_the_first_signal_is_killed_after_the_grace() {
        let dir = tempfile::tempdir().expect("tempdir");
        let spec = CompanionSpec::host(
            "/bin/sh",
            vec![
                "-c".into(),
                "trap '' TERM; while :; do sleep 0.05; done".into(),
            ],
        );
        let mut companion = spawn(&spec, dir.path()).expect("spawn");
        let pid = companion.pid();

        companion
            .stop(Duration::from_millis(150))
            .await
            .expect("stop");
        assert!(
            !Path::new(&format!("/proc/{pid}")).exists(),
            "the companion was killed after ignoring the graceful stop"
        );
    }

    /// The exit status is the companion's own, which the game supervision path cannot report.
    #[tokio::test]
    async fn a_companion_reports_its_exit_status() {
        let dir = tempfile::tempdir().expect("tempdir");
        let spec = CompanionSpec::host("/bin/sh", vec!["-c".into(), "exit 3".into()]);
        let mut companion = spawn(&spec, dir.path()).expect("spawn");
        assert_eq!(companion.wait().await.expect("wait").code, Some(3));
    }

    /// Arguments reach the child verbatim: no shell, so a value with spaces or quotes stays one
    /// argument instead of being re-split on the way through.
    #[tokio::test]
    async fn arguments_are_passed_without_shell_splitting() {
        let dir = tempfile::tempdir().expect("tempdir");
        let out = dir.path().join("argv");
        let spec = CompanionSpec::host(
            "/bin/sh",
            vec![
                "-c".into(),
                format!("printf '%s\\n' \"$1\" > {}", out.display()),
                "sh".into(),
                "one two \"three\"".into(),
            ],
        );
        let mut companion = spawn(&spec, dir.path()).expect("spawn");
        companion.wait().await.expect("wait");
        assert_eq!(
            std::fs::read_to_string(&out).expect("argv"),
            "one two \"three\"\n"
        );
    }
}

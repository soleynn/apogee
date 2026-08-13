//! A companion program run alongside the game: a native tool on the host, or a Windows one run
//! inside a prefix through the runner.
//!
//! The game is supervised by scanning `/proc` for the process the runner renamed itself into
//! ([`crate::GameSession`]); a companion is not, because it is an ordinary child with an ordinary
//! exit status. What it does need is a stop that reaches the tool a launcher script backgrounded,
//! so every companion leads its own process group and the stop signals the group.
//!
//! Inside a Flatpak sandbox a host companion is relayed out through `flatpak-spawn`
//! ([`crate::flatpak`]), and the group stops being the whole story: the group then holds the relay
//! rather than the tool. What survives is measured in that module, and it is the graceful half.
//! `SIGTERM` is forwarded across the boundary, so an ordinary stop still reaches the tool and its
//! exit status still comes back; the `SIGKILL` that follows a grace reaches only the relay, so a
//! host tool that ignores `SIGTERM` outlives it, and a stopped launcher cannot see whatever the tool
//! backgrounded.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use rustix::process::{Pid, Signal, kill_process_group, test_kill_process_group};
use tokio::process::{Child, Command};

use crate::error::RuntimeError;
use crate::flatpak::{Confinement, Invocation, host_arguments};
use crate::plan::Prefix;
use crate::spawn::{prefix_env, prefix_launcher, resolve_umu};
use crate::supervise::{ExitWatch, wait_exit, watch_exit};

/// How often a process group is re-probed once its leader has gone.
const GROUP_POLL: Duration = Duration::from_millis(50);

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

    /// The companion's exit if it has already ended, without waiting. Reaps it when it has.
    ///
    /// # Errors
    /// [`RuntimeError::Spawn`] if the process could not be waited on.
    pub fn try_wait(&mut self) -> Result<Option<CompanionExit>, RuntimeError> {
        let status = self
            .child
            .try_wait()
            .map_err(|source| RuntimeError::Spawn {
                runner: self.name.clone(),
                source,
            })?;
        Ok(status.map(|status| CompanionExit {
            code: status.code(),
        }))
    }

    /// Resolve once the companion and everything it started have exited: the leader is reaped for its
    /// status, then its process group is polled until nothing is left in it.
    ///
    /// A launcher script that backgrounds the real work and returns immediately would otherwise be
    /// reported as finished while the tool it started is still running. The group's surviving members
    /// hold the group id open, so a recycled pid cannot be mistaken for the group still being alive.
    ///
    /// # Errors
    /// [`RuntimeError::Spawn`] if the leader could not be reaped.
    pub async fn wait_group(&mut self) -> Result<CompanionExit, RuntimeError> {
        let exit = self.wait().await?;
        if let Some(pid) = Pid::from_raw(self.pid) {
            // Asks only whether the group still has a member to deliver to, without signalling it.
            while test_kill_process_group(pid).is_ok() {
                tokio::time::sleep(GROUP_POLL).await;
            }
        }
        Ok(exit)
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
///
/// # Errors
/// [`RuntimeError::MissingHostTool`] if a prefix companion has no resolvable runner launcher, or if
/// a host companion is being started from a sandbox that carries no `flatpak-spawn`, and
/// [`RuntimeError::Spawn`] if the process could not be started.
pub(crate) fn spawn(
    spec: &CompanionSpec,
    tools_dir: &Path,
    confinement: &Confinement,
) -> Result<Companion, RuntimeError> {
    let name = spec
        .program
        .file_name()
        .map_or_else(|| spec.program.to_string_lossy(), |n| n.to_string_lossy())
        .into_owned();

    let mut command = compose(spec, tools_dir, confinement)?;
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

/// The command that starts `spec`, on whichever side of a sandbox boundary it belongs to.
///
/// A companion that runs inside a prefix goes through the runner and stays where the prefix is. A
/// host companion is the one invocation in this crate that is a host one by definition: the user
/// points at a program on their own machine, which a sandbox neither installed nor can see, so
/// under confinement it is relayed out through `flatpak-spawn` ([`crate::flatpak`]).
fn compose(
    spec: &CompanionSpec,
    tools_dir: &Path,
    confinement: &Confinement,
) -> Result<Command, RuntimeError> {
    if let Some(prefix) = spec.prefix.as_ref() {
        let umu = resolve_umu(tools_dir);
        let launcher = prefix_launcher(prefix, umu.as_deref())?;
        let mut command = Command::new(launcher);
        command.arg(&spec.program);
        prefix_env(&mut command, prefix);
        inline_tail(&mut command, spec);
        return Ok(command);
    }
    if !confinement.runs_on_host(Invocation::HostTool) {
        let mut command = Command::new(&spec.program);
        inline_tail(&mut command, spec);
        return Ok(command);
    }
    // Nothing is set on this command beyond the argv: across the boundary the environment is not
    // inherited and the working directory is a flag, so both travel inside `host_arguments`.
    let mut command = Command::new(confinement.require_host_spawn()?);
    command.args(host_arguments(
        &spec.program,
        &spec.args,
        &spec.env,
        spec.working_dir.as_deref(),
    ));
    Ok(command)
}

/// The part of a command that is the same wherever it runs: its arguments, the caller's environment
/// and its working directory, all inherited by an ordinary child.
fn inline_tail(command: &mut Command, spec: &CompanionSpec) {
    command.args(&spec.args);
    for (key, value) in &spec.env {
        command.env(key, value);
    }
    if let Some(dir) = &spec.working_dir {
        command.current_dir(dir);
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;

    use super::*;
    use crate::error::HostTool;
    use crate::shim::{PROBE, scripted_prefix, wait_until_runnable};

    /// A process that is not sandboxed, which is what every test here but the Flatpak ones composes
    /// for.
    fn unconfined() -> Confinement {
        Confinement::default()
    }

    /// A stand-in for `flatpak-spawn` that writes the argv it was handed, one token per line, and
    /// then stops. It does not relay anything: what a test needs to read is exactly what crossed the
    /// boundary, and a real relay is the thing being stood in for.
    ///
    /// Written and then probed until it runs, because a sibling thread's fork can inherit the
    /// descriptor this file is still open on and make the first exec fail with `ETXTBSY`
    /// ([`crate::shim`]).
    fn fake_host_spawn(dir: &Path, record: &Path) -> PathBuf {
        let path = dir.join("flatpak-spawn");
        std::fs::write(
            &path,
            format!(
                "#!/bin/sh\n[ \"$1\" = {PROBE} ] && exit 0\nprintf '%s\\n' \"$@\" > \"{}\"\n",
                record.display()
            ),
        )
        .expect("write the relay");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).expect("chmod");
        wait_until_runnable(&path);
        path
    }

    /// A sandbox whose way out is `spawn`.
    fn confined(spawn: PathBuf) -> Confinement {
        Confinement {
            flatpak: true,
            host_spawn: Some(spawn),
        }
    }

    /// The tokens the relay recorded, or nothing if it was never run.
    fn recorded(record: &Path) -> Option<Vec<String>> {
        let text = std::fs::read_to_string(record).ok()?;
        Some(text.lines().map(str::to_owned).collect())
    }

    /// A host companion started from inside a sandbox goes out through the relay, and everything the
    /// caller set travels as an argument rather than as inherited state: measured on flatpak 1.16.6,
    /// a host command gets the host session's environment and none of the sandbox's, so a variable
    /// merely set on the child is a variable the tool never sees.
    #[tokio::test]
    async fn a_host_companion_under_confinement_is_relayed_with_its_environment_named() {
        let dir = tempfile::tempdir().expect("tempdir");
        let record = dir.path().join("argv");
        let relay = fake_host_spawn(dir.path(), &record);

        let mut env = BTreeMap::new();
        env.insert("APOGEE_GAME_PID".to_owned(), "4242".to_owned());
        let spec = CompanionSpec::host("/opt/overlay/tool", vec!["--attach".to_owned()])
            .env(env)
            .working_dir("/opt/overlay");

        let mut companion = spawn(&spec, dir.path(), &confined(relay)).expect("spawn");
        companion.wait().await.expect("wait");

        assert_eq!(
            recorded(&record).expect("the relay ran"),
            [
                "--host",
                "--directory=/opt/overlay",
                "--env=APOGEE_GAME_PID=4242",
                "--",
                "/opt/overlay/tool",
                "--attach",
            ]
        );
    }

    /// The other half of the matrix. A companion that runs inside a prefix goes through the runner
    /// wherever the launcher is, because the prefix and the wine processes it holds are the
    /// sandbox's; relaying it out would start a second wine against a prefix nothing else can see.
    #[tokio::test]
    async fn an_in_prefix_companion_is_not_relayed_out_of_the_sandbox() {
        let dir = tempfile::tempdir().expect("tempdir");
        let record = dir.path().join("argv");
        let relay = fake_host_spawn(dir.path(), &record);
        let (_runner_dir, prefix) = scripted_prefix("exit 0");

        let spec = CompanionSpec::in_prefix("overlay.exe", Vec::new(), &prefix);
        let mut companion = spawn(&spec, dir.path(), &confined(relay)).expect("spawn");
        companion.wait().await.expect("wait");

        assert!(
            recorded(&record).is_none(),
            "a program that belongs in the prefix was sent to the host"
        );
    }

    /// A sandbox with no relay cannot start a host tool. Reported rather than fallen back on: run
    /// inside the sandbox instead, the tool is missing from a runtime that never had it, and the
    /// failure would read as the user's own program being broken.
    #[test]
    fn a_confined_host_companion_with_no_relay_is_a_typed_failure() {
        let dir = tempfile::tempdir().expect("tempdir");
        let stranded = Confinement {
            flatpak: true,
            host_spawn: None,
        };
        let spec = CompanionSpec::host("/opt/overlay/tool", Vec::new());
        let err = spawn(&spec, dir.path(), &stranded).expect_err("there is no way out");
        assert!(
            matches!(
                err,
                RuntimeError::MissingHostTool {
                    tool: HostTool::FlatpakSpawn
                }
            ),
            "{err:?}"
        );
    }

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
        let mut companion = spawn(&spec, dir.path(), &unconfined()).expect("spawn");

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
        let mut companion = spawn(&spec, dir.path(), &unconfined()).expect("spawn");
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
        let mut companion = spawn(&spec, dir.path(), &unconfined()).expect("spawn");
        assert_eq!(companion.wait().await.expect("wait").code, Some(3));
    }

    /// A leader that backgrounds the real work and returns is the shape that makes waiting on the
    /// child alone report finished while the tool is still running.
    #[tokio::test]
    async fn waiting_on_the_group_outlasts_a_leader_that_returns_early() {
        let dir = tempfile::tempdir().expect("tempdir");
        let marker = dir.path().join("done");
        let spec = CompanionSpec::host(
            "/bin/sh",
            vec![
                "-c".into(),
                format!("(sleep 0.4; : > {}) & exit 0", marker.display()),
            ],
        );
        let mut companion = spawn(&spec, dir.path(), &unconfined()).expect("spawn");

        companion.wait_group().await.expect("wait_group");
        assert!(
            marker.exists(),
            "the group was reported done while its work was still running"
        );
    }

    /// Asking without waiting is what lets a caller notice a companion that quit on its own.
    #[tokio::test]
    async fn a_companion_still_running_reports_no_exit_yet() {
        let dir = tempfile::tempdir().expect("tempdir");
        let spec = CompanionSpec::host("/bin/sh", vec!["-c".into(), "sleep 0.2".into()]);
        let mut companion = spawn(&spec, dir.path(), &unconfined()).expect("spawn");

        assert_eq!(companion.try_wait().expect("try_wait"), None);
        tokio::time::sleep(Duration::from_millis(400)).await;
        assert_eq!(
            companion.try_wait().expect("try_wait"),
            Some(CompanionExit { code: Some(0) })
        );
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
        let mut companion = spawn(&spec, dir.path(), &unconfined()).expect("spawn");
        companion.wait().await.expect("wait");
        assert_eq!(
            std::fs::read_to_string(&out).expect("argv"),
            "one two \"three\"\n"
        );
    }
}

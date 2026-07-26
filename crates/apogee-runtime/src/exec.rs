//! Running one program inside a prefix and waiting for it to finish.
//!
//! This is the primitive the component layer builds prefix setup on: `reg` for a registry tweak, an
//! installer for a redistributable. It differs from both of the other spawn paths on purpose. The game
//! ([`crate::GameSession`]) is resolved through `/proc` and detached, so it reports no status; a
//! companion ([`crate::Companion`]) is held for its whole life and stopped by the caller. A setup
//! program is neither: it is short, it is expected to end, and its exit status is the answer.
//!
//! Output is captured for diagnostics and is never parsed. Wine's console programs write through the
//! console API and fall back to the console codepage when redirected, so the bytes on a pipe are not a
//! stable interface across wine versions or locales. Every decision this crate makes about a setup
//! program reads its exit status instead.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::Duration;

// Composing and describing a run is pure, so it compiles anywhere; performing one needs the spawn
// path, which is Linux-only like the rest of the runner surface.
#[cfg(target_os = "linux")]
use std::path::Path;
#[cfg(target_os = "linux")]
use std::process::Stdio;

#[cfg(target_os = "linux")]
use tokio::process::Command;
#[cfg(target_os = "linux")]
use tokio_util::sync::CancellationToken;

#[cfg(target_os = "linux")]
use crate::error::RuntimeError;
#[cfg(target_os = "linux")]
use crate::plan::Prefix;
#[cfg(target_os = "linux")]
use crate::spawn::{prefix_env, prefix_launcher};

/// How long a setup program runs before it is treated as hung. A registry write is milliseconds; the
/// budget is sized for an installer that unpacks, and a caller with a slower one sets its own.
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(120);

/// Retained bytes per output stream. The pipes are drained either way; this bounds only what travels
/// back in a report or an error message, so a chatty installer cannot turn one line of diagnosis into
/// megabytes.
const MAX_CAPTURED: usize = 8 * 1024;

/// A program to run inside a prefix.
///
/// `program` is resolved by the runner, not by this crate: a bare name is a program the prefix knows
/// (`reg`, `cmd`), and a path is handed through as written. Arguments are an argv, passed verbatim, so
/// there is no shell and no quoting dialect.
#[derive(Debug, Clone)]
pub struct ProgramInPrefix {
    program: String,
    args: Vec<String>,
    env: BTreeMap<String, String>,
    working_dir: Option<PathBuf>,
    timeout: Duration,
}

impl ProgramInPrefix {
    /// A program and its arguments, with the default time budget.
    #[must_use]
    pub fn new(program: impl Into<String>, args: Vec<String>) -> Self {
        Self {
            program: program.into(),
            args,
            env: BTreeMap::new(),
            working_dir: None,
            timeout: DEFAULT_TIMEOUT,
        }
    }

    /// Extra environment for the child, merged after the prefix variables so a caller can override
    /// them.
    #[must_use]
    pub fn env(mut self, env: BTreeMap<String, String>) -> Self {
        self.env = env;
        self
    }

    /// The child's working directory on the host side.
    #[must_use]
    pub fn working_dir(mut self, dir: impl Into<PathBuf>) -> Self {
        self.working_dir = Some(dir.into());
        self
    }

    /// Override the time budget.
    #[must_use]
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// The program name or path, as the runner will see it.
    #[must_use]
    pub fn program(&self) -> &str {
        &self.program
    }

    /// The argument vector, as the program will see it.
    #[must_use]
    pub fn args(&self) -> &[String] {
        &self.args
    }
}

/// How a program run inside a prefix ended.
///
/// `stdout` and `stderr` are lossily decoded and truncated: they exist to put in an error message, not
/// to branch on (see the module note on wine's redirected-output encoding).
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct PrefixRun {
    /// The exit status, or `None` when the program was ended by a signal.
    pub code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
}

impl PrefixRun {
    /// Whether the program exited cleanly.
    #[must_use]
    pub fn ok(&self) -> bool {
        self.code == Some(0)
    }

    /// The captured output, for an error message. Prefers stderr, since that is where a wine program
    /// puts its complaint, and falls back to stdout so a program that only writes there is not
    /// reported as having said nothing.
    #[must_use]
    pub fn diagnostic(&self) -> &str {
        let stderr = self.stderr.trim();
        if stderr.is_empty() {
            self.stdout.trim()
        } else {
            stderr
        }
    }
}

/// Decode one captured stream, keeping the tail: a program that fails says why last.
fn capture(bytes: &[u8]) -> String {
    let tail = &bytes[bytes.len().saturating_sub(MAX_CAPTURED)..];
    String::from_utf8_lossy(tail).into_owned()
}

/// Run `program` inside `prefix` through its runner and wait for it.
///
/// A non-zero exit is not an error here: it is a fact in the returned [`PrefixRun`], because what a
/// non-zero status means is the caller's rule. Only failing to run it, running past the budget, or
/// cancellation are errors.
#[cfg(target_os = "linux")]
pub(crate) async fn run(
    prefix: &Prefix,
    program: &ProgramInPrefix,
    umu: Option<&Path>,
    cancel: &CancellationToken,
) -> Result<PrefixRun, RuntimeError> {
    let launcher = prefix_launcher(prefix, umu)?;
    let mut command = Command::new(launcher);
    command.arg(&program.program);
    command.args(&program.args);
    prefix_env(&mut command, prefix);
    // Wine's own chatter would otherwise dominate the captured diagnostic, which is the only thing
    // the capture is for.
    command.env("WINEDEBUG", "-all");
    for (key, value) in &program.env {
        command.env(key, value);
    }
    if let Some(dir) = &program.working_dir {
        command.current_dir(dir);
    }
    // A setup program is never interactive: an installer that prompts must fail the budget rather than
    // block the launcher on a question nobody can see.
    command.stdin(Stdio::null());
    command.stdout(Stdio::piped());
    command.stderr(Stdio::piped());
    // The caller owns no handle to this child, so the drop on the timeout and cancel paths is the only
    // thing that can end it.
    command.kill_on_drop(true);

    let name = program.program.clone();
    let child = command.spawn().map_err(|source| RuntimeError::Spawn {
        runner: name.clone(),
        source,
    })?;

    // `wait_with_output` consumes the child and drives both pipes, so it is moved into the race. On
    // either losing branch the future is dropped, which drops the child, which kills it.
    let waited = tokio::time::timeout(program.timeout, async move {
        tokio::select! {
            output = child.wait_with_output() => Some(output),
            () = cancel.cancelled() => None,
        }
    })
    .await;

    match waited {
        Ok(Some(Ok(output))) => Ok(PrefixRun {
            code: output.status.code(),
            stdout: capture(&output.stdout),
            stderr: capture(&output.stderr),
        }),
        Ok(Some(Err(source))) => Err(RuntimeError::Spawn {
            runner: name,
            source,
        }),
        Ok(None) => Err(RuntimeError::InPrefixIncomplete {
            program: name,
            reason: "cancelled",
        }),
        Err(_elapsed) => Err(RuntimeError::InPrefixIncomplete {
            program: name,
            reason: "ran past its time budget",
        }),
    }
}

#[cfg(target_os = "linux")]
#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;

    use super::*;
    use crate::catalog::RunnerKind;
    use crate::plan::RunnerHandle;

    /// A prefix whose "runner" is a shell script standing in for `wine`, so the spawn path can be
    /// exercised without one. The script echoes its arguments and exits with the status the first one
    /// asks for, which is enough to check the parts this module owns: the argv it composes, the
    /// capture, and the budget.
    fn scripted_prefix(body: &str) -> (tempfile::TempDir, Prefix) {
        let dir = tempfile::tempdir().expect("tempdir");
        let runner_dir = dir.path().join("runner");
        std::fs::create_dir_all(runner_dir.join("bin")).expect("bin");
        let wine = runner_dir.join("bin/wine");
        std::fs::write(&wine, format!("#!/bin/sh\n{body}\n")).expect("write shim");
        std::fs::set_permissions(&wine, std::fs::Permissions::from_mode(0o755)).expect("chmod");
        let handle = RunnerHandle::for_test(runner_dir, RunnerKind::Wine, "shim", "custom");
        let prefix = Prefix::new(dir.path().join("prefix"), handle);
        (dir, prefix)
    }

    /// The program name and its arguments reach the runner as an argv, in order, with no shell in
    /// between: a value with spaces stays one argument.
    #[tokio::test]
    async fn the_program_and_its_arguments_reach_the_runner_verbatim() {
        let (_dir, prefix) = scripted_prefix("printf '%s\\n' \"$@\"");
        let program = ProgramInPrefix::new(
            "reg",
            vec![
                "add".into(),
                r"HKCU\Software\Wine".into(),
                "/d".into(),
                "one two".into(),
            ],
        );
        let run = run(&prefix, &program, None, &CancellationToken::new())
            .await
            .expect("run");

        assert!(run.ok());
        assert_eq!(
            run.stdout.lines().collect::<Vec<_>>(),
            ["reg", "add", r"HKCU\Software\Wine", "/d", "one two"]
        );
    }

    /// A non-zero exit is a fact, not an error: what it means belongs to the caller, and the captured
    /// output is what makes its message useful.
    #[tokio::test]
    async fn a_failing_program_reports_its_status_and_output() {
        let (_dir, prefix) = scripted_prefix("echo 'nope' >&2; exit 5");
        let run = run(
            &prefix,
            &ProgramInPrefix::new("reg", Vec::new()),
            None,
            &CancellationToken::new(),
        )
        .await
        .expect("the run itself succeeded");

        assert_eq!(run.code, Some(5));
        assert!(!run.ok());
        assert_eq!(run.diagnostic(), "nope");
    }

    /// A hung setup program must not hang the launcher, and must not be left running either.
    #[tokio::test]
    async fn a_program_that_never_finishes_fails_the_budget() {
        let (_dir, prefix) = scripted_prefix("sleep 30");
        let program = ProgramInPrefix::new("cmd", Vec::new()).timeout(Duration::from_millis(100));
        let err = run(&prefix, &program, None, &CancellationToken::new())
            .await
            .expect_err("must not wait 30 seconds");

        assert!(matches!(
            err,
            RuntimeError::InPrefixIncomplete {
                reason: "ran past its time budget",
                ..
            }
        ));
    }

    #[tokio::test]
    async fn cancelling_stops_waiting() {
        let (_dir, prefix) = scripted_prefix("sleep 30");
        let cancel = CancellationToken::new();
        cancel.cancel();
        let err = run(
            &prefix,
            &ProgramInPrefix::new("cmd", Vec::new()),
            None,
            &cancel,
        )
        .await
        .expect_err("cancelled");

        assert!(matches!(
            err,
            RuntimeError::InPrefixIncomplete {
                reason: "cancelled",
                ..
            }
        ));
    }

    /// A wall of output is bounded to what a message can use, and the tail is what is kept because a
    /// program that fails says why at the end.
    #[test]
    fn a_long_stream_keeps_its_tail() {
        let mut bytes = vec![b'x'; MAX_CAPTURED * 2];
        bytes.extend_from_slice(b"the reason");
        let captured = capture(&bytes);
        assert_eq!(captured.len(), MAX_CAPTURED);
        assert!(captured.ends_with("the reason"));
    }
}

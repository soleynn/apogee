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

/// What the child branch of the race means once the token is taken into account.
///
/// `select!` picks pseudo-randomly among branches that are ready together, so a program that ends in
/// the same instant the token fires wins the race about half the time and would come back as a run that
/// succeeded. Callers record a completed step, which is exactly the thing a stopped run must not leave
/// behind, so the token outranks the child: cancelled is cancelled whichever branch the race went to.
///
/// The token is consulted before the wait's own result, so an io error draining the pipes is read the
/// same way. Killing a child to stop it is a routine way for that read to fail, and reporting it as a
/// spawn failure narrates a run the user stopped as a broken install.
#[cfg(target_os = "linux")]
fn completed(
    name: String,
    waited: std::io::Result<std::process::Output>,
    cancelled: bool,
) -> Result<PrefixRun, RuntimeError> {
    if cancelled {
        return Err(RuntimeError::InPrefixIncomplete {
            program: name,
            reason: crate::error::CANCELLED_REASON,
        });
    }
    let output = waited.map_err(|source| RuntimeError::Spawn {
        runner: name,
        source,
    })?;
    Ok(PrefixRun {
        code: output.status.code(),
        stdout: capture(&output.stdout),
        stderr: capture(&output.stderr),
    })
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
        Ok(Some(result)) => completed(name, result, cancel.is_cancelled()),
        Ok(None) => Err(RuntimeError::InPrefixIncomplete {
            program: name,
            reason: crate::error::CANCELLED_REASON,
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
    use super::*;
    use crate::shim::scripted_prefix;

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

    /// The tie the race itself cannot settle: the child finished and the token fired together, and
    /// `select!` hands the win to either one. Reported as a completed run, the caller records a step it
    /// performed after the run was stopped, so the token is what decides.
    ///
    /// Both readings of that branch are held to it. A wait that ended in an io error rather than a
    /// status is the same run from the user's side, and reported as a spawn failure it is a stop
    /// narrated as a broken install.
    #[test]
    fn a_child_that_finishes_as_the_token_fires_is_still_a_cancelled_run() {
        use std::os::unix::process::ExitStatusExt;

        let output = std::process::Output {
            status: std::process::ExitStatus::from_raw(0),
            stdout: b"installed".to_vec(),
            stderr: Vec::new(),
        };
        let err = completed("setup.exe".to_owned(), Ok(output), true)
            .expect_err("a run the token stopped is not a run that succeeded");
        assert!(err.is_cancellation(), "{err:?}");
        assert!(matches!(
            err,
            RuntimeError::InPrefixIncomplete {
                reason: "cancelled",
                ..
            }
        ));

        let drained = completed(
            "setup.exe".to_owned(),
            Err(std::io::Error::from(std::io::ErrorKind::BrokenPipe)),
            true,
        )
        .expect_err("a stopped run whose pipes failed is still a stopped run");
        assert!(
            drained.is_cancellation(),
            "a pipe that broke because the child was killed to stop it is not a spawn failure: {drained:?}"
        );

        let broken = completed(
            "setup.exe".to_owned(),
            Err(std::io::Error::from(std::io::ErrorKind::BrokenPipe)),
            false,
        )
        .expect_err("an io error with no cancellation is still a failure");
        assert!(matches!(broken, RuntimeError::Spawn { .. }), "{broken:?}");
    }

    /// A run the user stopped and a program that hung are the same variant, and a shell has to tell
    /// them apart: one is a disposition to narrate, the other a failure to report. Read off the variant
    /// alone, Ctrl-C is a failed install.
    #[tokio::test]
    async fn a_run_the_token_stopped_reads_as_a_cancellation_and_an_overrun_does_not() {
        let (_dir, prefix) = scripted_prefix("sleep 30");
        let cancel = CancellationToken::new();
        cancel.cancel();
        let stopped = run(
            &prefix,
            &ProgramInPrefix::new("cmd", Vec::new()),
            None,
            &cancel,
        )
        .await
        .expect_err("a stopped run did not finish");
        assert!(stopped.is_cancellation(), "{stopped:?}");

        let overran = run(
            &prefix,
            &ProgramInPrefix::new("cmd", Vec::new()).timeout(Duration::from_millis(100)),
            None,
            &CancellationToken::new(),
        )
        .await
        .expect_err("a program that outran its budget did not finish either");
        assert!(
            !overran.is_cancellation(),
            "a hung installer is a failure, not a cancellation: {overran:?}"
        );
    }

    /// A script that records its own pid and then hangs, so a test can check what became of it.
    fn hanging_prefix() -> (tempfile::TempDir, Prefix, PathBuf) {
        let (dir, prefix) = scripted_prefix("echo $$ > \"$APOGEE_TEST_PID_FILE\"; sleep 30");
        let pid_file = dir.path().join("child.pid");
        (dir, prefix, pid_file)
    }

    fn with_pid_file(program: ProgramInPrefix, pid_file: &Path) -> ProgramInPrefix {
        let mut env = BTreeMap::new();
        env.insert(
            "APOGEE_TEST_PID_FILE".to_owned(),
            pid_file.display().to_string(),
        );
        program.env(env)
    }

    /// The pid the script recorded, or `None` if it never got far enough to record one. Absent is not
    /// an error here: under a time budget the shell can be killed before it writes, and a test that
    /// panicked on that would be blaming the child for its own timing.
    fn recorded_pid(pid_file: &Path) -> Option<i32> {
        std::fs::read_to_string(pid_file)
            .ok()
            .and_then(|text| text.trim().parse().ok())
    }

    /// Wait for the process the script recorded to go away.
    ///
    /// The signal lands when the handle drops and the process stays a zombie, with `/proc/<pid>` still
    /// present, until tokio's orphan reaper collects it. So this polls for the fact rather than
    /// sleeping a fixed span and asserting: the span would be measuring how loaded the machine is.
    /// The ceiling only exists so a program that genuinely survives fails as itself.
    async fn wait_until_gone(pid_file: &Path) {
        let pid = recorded_pid(pid_file).expect("the child recorded its pid before it was stopped");
        for _ in 0..600 {
            if !Path::new(&format!("/proc/{pid}")).exists() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("the program was left running: /proc/{pid} is still there");
    }

    /// A hung setup program must not hang the launcher, and must not be left running either. The second
    /// half has exactly one line of code behind it, so it gets an assertion of its own rather than
    /// riding on the returned error.
    #[tokio::test]
    async fn a_program_that_never_finishes_fails_the_budget_and_is_killed() {
        let (_dir, prefix, pid_file) = hanging_prefix();
        let program = with_pid_file(
            ProgramInPrefix::new("cmd", Vec::new()).timeout(Duration::from_millis(300)),
            &pid_file,
        );
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
        wait_until_gone(&pid_file).await;
    }

    #[tokio::test]
    async fn cancelling_stops_waiting_and_kills_the_program() {
        let (_dir, prefix, pid_file) = hanging_prefix();
        let cancel = CancellationToken::new();
        let program = with_pid_file(ProgramInPrefix::new("cmd", Vec::new()), &pid_file);
        // Cancelled after it is up, so the race the select exists to win is the one exercised.
        let signal = cancel.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(300)).await;
            signal.cancel();
        });
        let err = run(&prefix, &program, None, &cancel)
            .await
            .expect_err("cancelled");

        assert!(matches!(
            err,
            RuntimeError::InPrefixIncomplete {
                reason: "cancelled",
                ..
            }
        ));
        wait_until_gone(&pid_file).await;
    }

    /// The same tie through the real spawn path, which is what the check in [`run`] answers for. The
    /// test above holds [`completed`] to it, and that passes whether or not anything ever passes it a
    /// cancelled token, so it says nothing about the branch the `select!` actually took.
    ///
    /// Staged rather than hoped for. One poll spawns the child and registers its pipes; parking the
    /// runtime on a sleep lets the io driver mark them readable after the child has exited, with
    /// nothing polling the run; the token then fires. The next poll therefore finds both branches
    /// ready, and `select!` hands the win to either. Repeated a few times because the pick is
    /// pseudo-random, so one pass says nothing about the branch that loses.
    ///
    /// The assertion is only ever about the outcome. How many of the passes were genuinely tied is a
    /// property of the scheduler, not of this crate, so counting them would be a test that fails on a
    /// slow machine and never on a regression.
    #[tokio::test]
    async fn a_child_that_wins_the_race_against_a_fired_token_still_reports_a_cancelled_run() {
        let (_dir, prefix) = scripted_prefix("sleep 0.01; echo done");
        for _ in 0..8 {
            let cancel = CancellationToken::new();
            let program = ProgramInPrefix::new("cmd", Vec::new());
            let running = run(&prefix, &program, None, &cancel);
            tokio::pin!(running);
            // Enough to spawn and register, not enough to finish. A pass that somehow did finish is
            // not a tie and proves nothing either way.
            if tokio::time::timeout(Duration::from_millis(1), &mut running)
                .await
                .is_ok()
            {
                continue;
            }
            tokio::time::sleep(Duration::from_millis(30)).await;
            cancel.cancel();
            assert!(
                running.await.is_err(),
                "a run the token stopped came back as a run that succeeded"
            );
        }
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

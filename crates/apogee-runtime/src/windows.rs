//! The Windows launch arm: the game is spawned directly, with no prefix and no runner.
//!
//! Everything the Linux path builds around wine is absent here, and what is left is a process the
//! launcher started: the argument string reaches the game as its own single token, the environment is
//! the plan's plus the compatibility layers below, and supervision is the child handle the operating
//! system already hands back. There is no `/proc` scan and nothing to resolve, because the process
//! that was spawned *is* the game.

use std::sync::Arc;

use tokio::process::{Child, Command};
use tokio::sync::{Notify, watch};

use crate::error::RuntimeError;
use crate::plan::LaunchPlan;
use crate::progress::{Progress, RuntimeEvent};

/// The variable the Windows application-compatibility engine reads its layers out of. Both layers a
/// launch applies travel in this one variable, space-separated.
const COMPAT_LAYER: &str = "__COMPAT_LAYER";

/// Runs the game on the launcher's own token rather than letting it ask for one of its own, so a game
/// started from an un-elevated launcher cannot silently elevate itself. It does not de-elevate a
/// launcher that is already elevated: that half is the user's to get right by not starting the
/// launcher as an administrator.
const RUN_AS_INVOKER: &str = "RunAsInvoker";

/// The game declares its own DPI awareness to Windows and is left to scale itself.
const HIGH_DPI_AWARE: &str = "HighDPIAware";

/// Windows scales the game's output for it. Named explicitly rather than left out, because with no DPI
/// layer at all the executable's manifest decides, which is a third behaviour and not what asking for
/// an unaware launch means.
const DPI_UNAWARE: &str = "DPIUnaware";

/// The compatibility layers a launch runs under: the privilege one always, then the DPI one `plan`
/// selected.
fn compat_layers(dpi_aware: bool) -> String {
    let dpi = if dpi_aware {
        HIGH_DPI_AWARE
    } else {
        DPI_UNAWARE
    };
    format!("{RUN_AS_INVOKER} {dpi}")
}

/// Build the process command for `plan`.
///
/// The argument string is one argv token, as it is on the Linux path: the game parses that string
/// itself, so anything an injectable inserted goes ahead of it rather than appended to it.
///
/// # Errors
/// [`RuntimeError::InvalidLaunchPlan`] for a plan this arm cannot honour: one carrying wrappers, or one
/// naming another process to supervise.
pub(crate) fn build_command(plan: &LaunchPlan) -> Result<Command, RuntimeError> {
    // Wrappers compose *around* the launch, which would make the spawned process something other than
    // the game. Supervision here is the child handle, so accepting one would mean reporting a wrapper's
    // exit as the game's. The two wrappers this launcher composes (gamescope, gamemode) are Linux
    // programs besides.
    if !plan.wrappers().is_empty() {
        return Err(RuntimeError::InvalidLaunchPlan {
            reason: "launch wrappers cannot be composed around a direct spawn",
        });
    }
    // A plan that names another process to supervise is one something redirected through a loader, and
    // the loader starts the game and exits. The child handle would then be the loader's, and its exit
    // would be read as the end of a session that is still running. Refused rather than mis-supervised:
    // following that handoff is a Windows process-table walk nothing here does.
    if plan.supervised().is_some() {
        return Err(RuntimeError::InvalidLaunchPlan {
            reason: "supervising a process other than the one spawned is not supported here",
        });
    }

    let mut command = Command::new(plan.program());
    command.args(plan.inserted_args());
    if !plan.args().is_empty() {
        command.arg(plan.args());
    }
    // Set before the plan's own variables, on the same terms as the prefix variables on the Linux path:
    // what the caller hands in is merged last and wins.
    command.env(COMPAT_LAYER, compat_layers(plan.is_dpi_aware()));
    for (key, value) in plan.env() {
        command.env(key, value);
    }
    if let Some(working_dir) = plan.working_dir() {
        command.current_dir(working_dir);
    }
    // The session owns the stop. Dropping the handle, or the runtime it was spawned on going away, must
    // not take the game with it.
    command.kill_on_drop(false);
    Ok(command)
}

/// Spawn `plan` and supervise the process it started.
///
/// # Errors
/// [`RuntimeError::Spawn`] if the process could not be started, plus what [`build_command`] raises.
pub(crate) fn launch(plan: &LaunchPlan, progress: &Progress) -> Result<GameSession, RuntimeError> {
    let mut command = build_command(plan)?;
    let program = plan.program().to_owned();
    let child = command.spawn().map_err(|source| RuntimeError::Spawn {
        runner: program.clone(),
        source,
    })?;
    let pid = child
        .id()
        .ok_or(RuntimeError::InvalidLaunchPlan {
            reason: "the game exited before its process id could be read",
        })?
        .cast_signed();
    progress.emit(RuntimeEvent::GameResolved { pid });
    Ok(GameSession::supervising(child, program, pid))
}

/// An opaque marker that the game process exited. Opaque on both platforms: the Linux path cannot reap
/// a status at all, and a launcher that reported one here and nothing there would be describing its own
/// implementation rather than the game.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct GameExit {}

/// A running game process.
///
/// The child handle it was spawned with lives in a task rather than in this struct, because both verbs
/// take `&self` and both need the handle: a shared lock would have `kill` waiting on the `wait` that is
/// holding it. The task owns the handle, [`kill`](Self::kill) asks it to stop the process, and
/// [`wait`](Self::wait) reads the answer it publishes.
pub struct GameSession {
    pid: i32,
    program: String,
    /// Raised once, by `kill`; the task consumes it and terminates the process.
    stop: Arc<Notify>,
    /// `true` once the process has been reaped. Watched rather than awaited, so any number of callers
    /// can wait and a caller that arrives late still sees it.
    exited: watch::Receiver<bool>,
}

impl GameSession {
    /// Take ownership of `child` in a supervising task.
    fn supervising(child: Child, program: String, pid: i32) -> Self {
        let stop = Arc::new(Notify::new());
        let (done, exited) = watch::channel(false);
        tokio::spawn(reap(child, program.clone(), Arc::clone(&stop), done));
        Self {
            pid,
            program,
            stop,
            exited,
        }
    }

    /// The process id of the game.
    #[must_use]
    pub fn game_pid(&self) -> i32 {
        self.pid
    }

    /// Resolve when the game process exits.
    ///
    /// # Errors
    /// [`RuntimeError::SupervisionLost`] if the supervising task ended without reaping the process,
    /// which is the async runtime it was spawned on going away.
    pub async fn wait(&self) -> Result<GameExit, RuntimeError> {
        let mut exited = self.exited.clone();
        exited
            .wait_for(|done| *done)
            .await
            .map_err(|_| RuntimeError::SupervisionLost {
                program: self.program.clone(),
            })?;
        Ok(GameExit {})
    }

    /// Stop the game process, resolving once it is gone. A process that has already exited is not an
    /// error: the request is dropped and the exit that already happened is what comes back.
    ///
    /// Unlike the Linux path's targeted signal this reaches only the process that was spawned. Nothing
    /// else was: there is no prefix here, so there is no wineserver and no second process holding the
    /// session open.
    ///
    /// # Errors
    /// As [`Self::wait`].
    pub async fn kill(&self) -> Result<(), RuntimeError> {
        // A permit rather than a wake: the task may not be parked on the request yet, and a wake nobody
        // was waiting for would leave the process running with the caller waiting for it to stop.
        self.stop.notify_one();
        self.wait().await?;
        Ok(())
    }
}

impl std::fmt::Debug for GameSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GameSession")
            .field("game_pid", &self.pid)
            .field("program", &self.program)
            .finish_non_exhaustive()
    }
}

/// Own the child handle: reap it, stopping it first if asked, and publish that it is gone.
async fn reap(mut child: Child, program: String, stop: Arc<Notify>, done: watch::Sender<bool>) {
    let reaped = loop {
        tokio::select! {
            reaped = child.wait() => break reaped,
            // Re-armed rather than final, so a stop that the operating system refuses does not leave
            // the process unsupervised and a second request unheard.
            () = stop.notified() => {
                if let Err(source) = child.start_kill() {
                    tracing::warn!(program, %source, "the game process could not be stopped");
                }
            }
        }
    };
    match reaped {
        Ok(status) => tracing::debug!(program, code = status.code(), "the game process exited"),
        Err(source) => tracing::warn!(program, %source, "the game process could not be reaped"),
    }
    // Sent whichever way the wait ended: a process that cannot be reaped is one nothing further will
    // ever learn about, and holding every waiter open for it would hang the launch instead.
    let _ = done.send(true);
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;

    /// The value of `key` in the command's environment, or `None` if it sets no such variable.
    fn env_of(command: &Command, key: &str) -> Option<String> {
        command
            .as_std()
            .get_envs()
            .find(|(name, _)| *name == key)
            .and_then(|(_, value)| value)
            .map(|value| value.to_string_lossy().into_owned())
    }

    fn plan() -> LaunchPlan {
        LaunchPlan::new(
            r"C:\games\FINAL FANTASY XIV\game\ffxiv_dx11.exe",
            "//**sqex0003redacted**//",
            BTreeMap::new(),
        )
    }

    /// Both layers travel in the one variable: the privilege one that keeps the game on the launcher's
    /// token, and the DPI one the plan selected.
    #[test]
    fn a_launch_carries_both_compatibility_layers() {
        let command = build_command(&plan()).expect("build");
        assert_eq!(
            env_of(&command, "__COMPAT_LAYER").as_deref(),
            Some("RunAsInvoker HighDPIAware")
        );
    }

    /// Turning DPI awareness off names the unaware layer rather than dropping the token: with neither
    /// named the executable's manifest decides, which is not what off means.
    #[test]
    fn an_unaware_launch_names_the_unaware_layer() {
        let command = build_command(&plan().dpi_aware(false)).expect("build");
        assert_eq!(
            env_of(&command, "__COMPAT_LAYER").as_deref(),
            Some("RunAsInvoker DPIUnaware")
        );
    }

    /// There is no prefix on this platform, so nothing that places a program in one may be set: a
    /// `WINEPREFIX` a launch inherited from somewhere would be a lie about where the game is running.
    #[test]
    fn no_prefix_variables_reach_the_game() {
        let command = build_command(&plan()).expect("build");
        for variable in ["WINEPREFIX", "GAMEID", "PROTONPATH"] {
            assert_eq!(
                env_of(&command, variable),
                None,
                "{variable} has no meaning without a prefix"
            );
        }
    }

    /// The plan's own environment reaches the game, and it is merged after the layers, so a caller that
    /// sets the variable itself is the one that decides. Same rule as the prefix variables on the Linux
    /// path: what the caller hands in wins.
    #[test]
    fn the_callers_environment_is_merged_last() {
        let mut env = BTreeMap::new();
        env.insert("FFXIV_LANGUAGE".to_owned(), "1".to_owned());
        env.insert("__COMPAT_LAYER".to_owned(), "RunAsInvoker".to_owned());
        let command = build_command(&LaunchPlan::new("ffxiv_dx11.exe", "", env)).expect("build");

        assert_eq!(env_of(&command, "FFXIV_LANGUAGE").as_deref(), Some("1"));
        assert_eq!(
            env_of(&command, "__COMPAT_LAYER").as_deref(),
            Some("RunAsInvoker")
        );
    }

    /// The program is spawned as itself, with a loader's flags ahead of the argument string the game
    /// parses on its own.
    #[test]
    fn the_argument_string_stays_one_token_after_the_inserted_flags() {
        let mut plan = plan();
        plan.set_inserted_args(vec!["--mode=inject".to_owned()]);
        let command = build_command(&plan).expect("build");

        assert_eq!(
            command.as_std().get_program(),
            r"C:\games\FINAL FANTASY XIV\game\ffxiv_dx11.exe"
        );
        let args: Vec<_> = command.as_std().get_args().collect();
        assert_eq!(args, ["--mode=inject", "//**sqex0003redacted**//"]);
    }

    /// The game runs from its own install directory, so it resolves its data paths relative to the exe.
    #[test]
    fn the_working_directory_is_the_plans() {
        let command =
            build_command(&plan().in_directory(r"C:\games\FINAL FANTASY XIV\game")).expect("build");
        assert_eq!(
            command.as_std().get_current_dir(),
            Some(std::path::Path::new(r"C:\games\FINAL FANTASY XIV\game"))
        );
    }

    /// A wrapper would make the spawned process something other than the game, and the spawned process
    /// is the whole of the supervision here.
    #[test]
    fn a_wrapped_launch_is_refused() {
        let plan = plan().with_wrappers(vec!["gamemoderun".to_owned()]);
        assert!(matches!(
            build_command(&plan),
            Err(RuntimeError::InvalidLaunchPlan { .. })
        ));
    }

    /// A redirected launch names the game as the process to supervise while spawning the loader that
    /// starts it. Tracking the loader would report the session as over seconds after it began.
    #[test]
    fn a_redirected_launch_is_refused() {
        let mut plan = plan();
        plan.set_supervised("ffxiv_dx11.exe");
        assert!(matches!(
            build_command(&plan),
            Err(RuntimeError::InvalidLaunchPlan { .. })
        ));
    }
}

//! A supervised, running game process.

use std::fmt;

use crate::error::RuntimeError;
use crate::plan::Prefix;
use crate::supervise::{ExitWatch, kill_pid, wait_exit, watch_exit};

/// An opaque marker that the game process exited. The game is a non-child descendant of the runner,
/// so no exit code can be reaped; this signals exit, not status.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct GameExit {}

/// A resolved, running game process, handed to injectables' `attach`.
pub struct GameSession {
    game_pid: i32,
    prefix: Prefix,
    exit: ExitWatch,
}

impl GameSession {
    pub(crate) fn new(game_pid: i32, prefix: Prefix) -> Self {
        let exit = watch_exit(game_pid);
        Self {
            game_pid,
            prefix,
            exit,
        }
    }

    /// The unix PID of the real game process.
    #[must_use]
    pub fn game_pid(&self) -> i32 {
        self.game_pid
    }

    /// The prefix the game is running in.
    #[must_use]
    pub fn prefix(&self) -> &Prefix {
        &self.prefix
    }

    /// Resolve when the game process exits (not when the runner wrapper does).
    pub async fn wait(&self) -> Result<GameExit, RuntimeError> {
        wait_exit(&self.exit).await?;
        Ok(GameExit {})
    }

    /// Targeted kill of the game process only. The broad prefix stop is the separate, explicit
    /// [`Runtime::kill_prefix`](crate::Runtime::kill_prefix).
    pub async fn kill(&self) -> Result<(), RuntimeError> {
        kill_pid(self.game_pid).await
    }
}

impl fmt::Debug for GameSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GameSession")
            .field("game_pid", &self.game_pid)
            .field("prefix", &self.prefix)
            .finish_non_exhaustive()
    }
}

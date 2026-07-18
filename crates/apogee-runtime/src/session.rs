//! A supervised, running game process.

use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicI32, Ordering};

use crate::error::RuntimeError;
use crate::plan::Prefix;
use crate::supervise::{successor, terminate_pid, wait_exit, watch_exit};

/// An opaque marker that the game process exited. The game is a non-child descendant of the runner,
/// so no exit code can be reaped; this signals exit, not status.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct GameExit {}

/// A resolved, running game process, handed to injectables' `attach`.
pub struct GameSession {
    /// The currently-tracked pid. Wine and Proton rename a short-lived loader to the PE basename, run
    /// the game, and exit; `wait` follows that handoff so the tracked pid advances from a loader to
    /// the real process. Shared so `kill` and `game_pid` observe the current process.
    current: Arc<AtomicI32>,
    basename: String,
    prefix: Prefix,
}

impl GameSession {
    pub(crate) fn new(game_pid: i32, basename: String, prefix: Prefix) -> Self {
        Self {
            current: Arc::new(AtomicI32::new(game_pid)),
            basename,
            prefix,
        }
    }

    /// The unix PID of the game process currently being tracked (the latest in a loader handoff).
    #[must_use]
    pub fn game_pid(&self) -> i32 {
        self.current.load(Ordering::SeqCst)
    }

    /// The prefix the game is running in.
    #[must_use]
    pub fn prefix(&self) -> &Prefix {
        &self.prefix
    }

    /// Resolve when the game process exits (not when a loader does). Wine and Proton rename a loader
    /// to the PE basename, exec the game, and exit; each time the tracked process exits this looks for
    /// the successor it handed off to, advancing the tracked pid, and only returns once no matching
    /// process remains in the prefix.
    pub async fn wait(&self) -> Result<GameExit, RuntimeError> {
        loop {
            let pid = self.current.load(Ordering::SeqCst);
            wait_exit(&watch_exit(pid)).await?;
            match successor(&self.basename, self.prefix.path(), pid).await {
                Some(next) => self.current.store(next, Ordering::SeqCst),
                None => return Ok(GameExit {}),
            }
        }
    }

    /// Targeted kill of the current game process only, delivered through its pidfd. The broad prefix
    /// stop is the separate, explicit [`Runtime::kill_prefix`](crate::Runtime::kill_prefix).
    pub async fn kill(&self) -> Result<(), RuntimeError> {
        terminate_pid(self.current.load(Ordering::SeqCst)).await
    }
}

impl fmt::Debug for GameSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GameSession")
            .field("game_pid", &self.game_pid())
            .field("prefix", &self.prefix)
            .finish_non_exhaustive()
    }
}

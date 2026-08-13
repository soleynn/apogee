//! The Linux handle on a supervised, running game process.
//!
//! The game is not a child of this process: it is found by scanning `/proc` and watched through a
//! pidfd, so its exit is observable and its exit status is not.

use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicI32, Ordering};

use crate::error::RuntimeError;
use crate::plan::Prefix;
use crate::supervise::{successor, terminate_pid, wait_exit, watch_exit};

/// An opaque marker that the game process exited.
///
/// The game is a non-child descendant of the runner, so no exit code can be reaped: this signals
/// exit, not status.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct GameExit {}

/// A resolved, running game process.
///
/// # Examples
///
/// ```
/// # use apogee_runtime::{GameSession, RuntimeError};
/// # async fn demo(session: &GameSession) -> Result<(), RuntimeError> {
/// let pid = session.game_pid();
/// let exit = session.wait().await?;
/// # let _ = (pid, exit);
/// # Ok(())
/// # }
/// ```
pub struct GameSession {
    /// The currently-tracked pid. Wine and Proton rename a short-lived loader to the PE basename,
    /// run the game, and exit, so [`GameSession::wait`] advances this from a loader to the real
    /// process. Shared, so `kill` and `game_pid` observe the current one.
    current: Arc<AtomicI32>,
    basename: String,
    prefix: Prefix,
}

impl GameSession {
    /// Track `game_pid` as the game, following handoffs to another `basename` in `prefix`.
    pub(crate) fn new(game_pid: i32, basename: String, prefix: Prefix) -> Self {
        Self {
            current: Arc::new(AtomicI32::new(game_pid)),
            basename,
            prefix,
        }
    }

    /// The unix pid currently being tracked, which is the latest in a loader handoff.
    #[must_use]
    pub fn game_pid(&self) -> i32 {
        self.current.load(Ordering::SeqCst)
    }

    /// The prefix the game is running in.
    #[must_use]
    pub fn prefix(&self) -> &Prefix {
        &self.prefix
    }

    /// Resolve when the game exits, which is not when a loader does.
    ///
    /// Wine and Proton rename a loader to the PE basename, exec the game, and exit. Each time the
    /// tracked process goes, this looks for the successor it handed off to and advances the tracked
    /// pid, returning only once no matching process is left in the prefix.
    ///
    /// # Errors
    /// [`RuntimeError::Io`] if the pidfd of a tracked process could not be polled for readiness.
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

    /// Kill the current game process only, delivered through its pidfd where one could be opened
    /// and by pid otherwise.
    ///
    /// Nothing else in the prefix is touched; the broad stop is the separate, explicit
    /// [`Runtime::kill_prefix`](crate::Runtime::kill_prefix).
    ///
    /// # Errors
    /// None as it stands: the signal sends and the waits behind them are all discarded, so a
    /// process that was already gone still reports `Ok`.
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

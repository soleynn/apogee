//! The companions one launch started, and what happens to them when the game exits.
//!
//! Two things have to hold. The teardown must run at most once, which [`AddonSession`] gets by
//! consuming itself. And it must run at least once, which consuming cannot give: an early return
//! between starting and stopping would drop the handle and leave every companion running with
//! nothing left that knows about them. So the drop is a backstop that signals each group it was
//! going to stop anyway.

use std::time::Duration;

use apogee_runtime::{Companion, Runtime};
use tokio_util::sync::CancellationToken;

use super::addon::{ExternalAddon, Trigger};
use super::event::{AddonEvent, AddonEvents};

/// How long a companion is given to stop on its own before it is ended.
pub(super) const STOP_GRACE: Duration = Duration::from_secs(5);

/// What became of one entry.
///
/// # Examples
///
/// ```
/// use apogee_addons::Outcome;
///
/// // Printable without the caller owning a rule for what each arm means.
/// assert_eq!(Outcome::Disabled.to_string(), "switched off");
/// assert_eq!(Outcome::Cancelled.to_string(), "cancelled");
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Outcome {
    /// Started, and running under the given process id.
    #[non_exhaustive]
    Started {
        /// The process id it was started under.
        pid: i32,
    },
    /// Not started because it was already running, under the given process id.
    ///
    /// Whoever started it owns it: a launch that finds a companion it did not start never stops it.
    #[non_exhaustive]
    AlreadyRunning {
        /// The process id of the copy that was found.
        pid: i32,
    },
    /// Not started because the entry is switched off.
    Disabled,
    /// Ran after the game exited and finished with this status.
    #[non_exhaustive]
    Completed {
        /// Its exit code, or `None` when a signal ended it.
        code: Option<i32>,
    },
    /// Stopped, or never started, because the teardown was cancelled.
    ///
    /// Its own outcome rather than a failure: nothing went wrong, somebody quit. A shell counting
    /// failures would act on it.
    Cancelled,
    /// Could not be run. The rest of the launch is unaffected.
    #[non_exhaustive]
    Failed {
        /// The failure and its causes, as one line.
        reason: String,
    },
}

impl std::fmt::Display for Outcome {
    /// One clause each, so a shell can print an outcome without a rule of its own for what each arm
    /// means. The arms carry process ids and exit statuses, which is what a user reports back.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Started { pid } => write!(f, "started as process {pid}"),
            Self::AlreadyRunning { pid } => write!(f, "already running as process {pid}"),
            Self::Disabled => f.write_str("switched off"),
            Self::Completed { code: Some(code) } => write!(f, "exited with status {code}"),
            Self::Completed { code: None } => f.write_str("exited"),
            Self::Cancelled => f.write_str("cancelled"),
            Self::Failed { reason } => write!(f, "failed: {reason}"),
        }
    }
}

/// One entry and what became of it.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct AddonOutcome {
    /// Its position in the configured list, so a message can point at the entry.
    pub index: usize,
    /// The program it names.
    pub program: std::path::PathBuf,
    /// What happened.
    pub outcome: Outcome,
}

/// Everything that happened to a launch's companions.
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct AddonReport {
    /// One per configured entry, in order.
    pub outcomes: Vec<AddonOutcome>,
}

impl AddonReport {
    /// Whether any entry failed. A caller decides what that is worth; nothing here interrupts a
    /// launch over a helper tool.
    ///
    /// # Examples
    ///
    /// ```
    /// use apogee_addons::AddonReport;
    ///
    /// // A launch that configured no companions has nothing to report and nothing to blame.
    /// assert!(!AddonReport::default().any_failed());
    /// ```
    #[must_use]
    pub fn any_failed(&self) -> bool {
        self.outcomes
            .iter()
            .any(|o| matches!(o.outcome, Outcome::Failed { .. }))
    }
}

/// A companion this launch started and is responsible for stopping.
pub(super) struct Held {
    pub(super) index: usize,
    pub(super) program: std::path::PathBuf,
    pub(super) companion: Companion,
    /// Taken from the trigger at start, so the stop policy travels with the process rather than
    /// being looked up again from a record that may have been edited since.
    pub(super) keep_after_close: bool,
}

impl Held {
    /// Hold a started companion, reading its stop policy out of `trigger` once.
    pub(super) const fn new(
        index: usize,
        program: std::path::PathBuf,
        companion: Companion,
        trigger: Trigger,
    ) -> Self {
        Self {
            index,
            program,
            companion,
            keep_after_close: matches!(
                trigger,
                Trigger::WithGame {
                    keep_after_close: true
                }
            ),
        }
    }
}

/// The companions one launch started.
///
/// Dropping this without calling [`Self::game_closed`] or [`Self::abandon`] stops the companions it
/// was going to stop, so an early return cannot leave them running with nobody to end them. The drop
/// backstop runs no queued after-game tool.
///
/// # Examples
///
/// ```
/// # use apogee_addons::{AddonEvents, AddonReport, AddonSession};
/// # use tokio_util::sync::CancellationToken;
/// # async fn demo(
/// #     session: AddonSession,
/// #     game_ran: bool,
/// #     cancel: &CancellationToken,
/// #     events: &AddonEvents,
/// # ) -> AddonReport {
/// if game_ran {
///     // Stop the held tools, then run the ones that wait for the game.
///     session.game_closed(cancel, events).await
/// } else {
///     // The launch itself failed: stop what started and run nothing further.
///     session.abandon(cancel, events).await
/// }
/// # }
/// ```
#[must_use = "a launch's companions need either game_closed or abandon, or they are stopped on drop"]
pub struct AddonSession {
    /// Cloned rather than borrowed so the session outlives the call that made it, which it must: the
    /// after-game tools run once the launch is already unwinding.
    runtime: Runtime,
    /// The prefix the launch used, carried so an after-game tool can be told which config tree it is
    /// working on. The game's process id deliberately does not travel here: by the time these run it
    /// names a process that has exited, and a wrapper that signalled it could reach a recycled one.
    game_prefix: Option<std::path::PathBuf>,
    held: Vec<Held>,
    on_close: Vec<(usize, ExternalAddon)>,
    report: AddonReport,
}

impl AddonSession {
    /// Take ownership of what one launch started.
    pub(super) const fn new(
        runtime: Runtime,
        game_prefix: Option<std::path::PathBuf>,
        held: Vec<Held>,
        on_close: Vec<(usize, ExternalAddon)>,
        report: AddonReport,
    ) -> Self {
        Self {
            runtime,
            game_prefix,
            held,
            on_close,
            report,
        }
    }

    /// What happened when the companions started.
    #[must_use]
    pub const fn report(&self) -> &AddonReport {
        &self.report
    }

    /// Whether anything remains to do when the game exits. A launcher that would otherwise detach
    /// after starting the game has to stay for this.
    #[must_use]
    pub fn has_work(&self) -> bool {
        !self.on_close.is_empty() || self.held.iter().any(|h| !h.keep_after_close)
    }

    /// The game has exited: stop the companions that go with it, then run the ones that wait for it.
    ///
    /// Consuming `self` is what makes this happen at most once. The order matters: a tool that syncs
    /// what the game wrote should see a stopped game and stopped siblings.
    ///
    /// `cancel` bounds the waiting, never the stopping. An after-game tool is somebody else's
    /// program and may never exit, so without a token this waits forever and the launcher looks hung
    /// with no way out; skipping the stopping instead is the leak this type exists to prevent, and
    /// each stop is bounded by a five-second grace anyway.
    ///
    /// Never fails as a whole. A companion that could not be stopped or run is an
    /// [`Outcome::Failed`] in the returned report: a helper tool does not fail a launch that already
    /// succeeded.
    pub async fn game_closed(
        mut self,
        cancel: &CancellationToken,
        events: &AddonEvents,
    ) -> AddonReport {
        for held in std::mem::take(&mut self.held) {
            Self::stop_one(held, events, &mut self.report).await;
        }
        for (index, addon) in std::mem::take(&mut self.on_close) {
            // Checked before each one rather than only inside the wait: a cancelled teardown must not
            // start the tools it has not reached yet, and one that runs in a millisecond would slip
            // past a token that is only consulted while waiting.
            let outcome = if cancel.is_cancelled() {
                Outcome::Cancelled
            } else {
                super::run_to_completion(
                    &self.runtime,
                    self.game_prefix.as_deref(),
                    &addon,
                    cancel,
                    events,
                )
                .await
            };
            events.emit(AddonEvent::Finished {
                program: addon.program().to_path_buf(),
                outcome: outcome.clone(),
            });
            self.report.outcomes.push(AddonOutcome {
                index,
                program: addon.program().to_path_buf(),
                outcome,
            });
        }
        std::mem::take(&mut self.report)
    }

    /// Give up on the launch: stop what this session started and run nothing further.
    ///
    /// For a launch that itself failed, where running a tool that expects the game to have been
    /// played would be wrong.
    ///
    /// `cancel` is taken and not consulted, which is the honest signature rather than an oversight:
    /// this path runs nothing that could go on indefinitely, and stopping is what a cancelled
    /// teardown still has to do. Taking it keeps both teardowns callable through one seam.
    pub async fn abandon(
        mut self,
        cancel: &CancellationToken,
        events: &AddonEvents,
    ) -> AddonReport {
        let _ = cancel;
        for held in std::mem::take(&mut self.held) {
            Self::stop_one(held, events, &mut self.report).await;
        }
        self.on_close.clear();
        std::mem::take(&mut self.report)
    }

    /// Stop one held companion and record what that came to, unless its policy is to stay.
    async fn stop_one(mut held: Held, events: &AddonEvents, report: &mut AddonReport) {
        if held.keep_after_close {
            return;
        }
        let outcome = match held.companion.stop(STOP_GRACE).await {
            Ok(()) => Outcome::Completed { code: None },
            Err(err) => Outcome::Failed {
                reason: crate::chain_of(&err),
            },
        };
        events.emit(AddonEvent::Stopped {
            program: held.program.clone(),
            pid: held.companion.pid(),
        });
        report.outcomes.push(AddonOutcome {
            index: held.index,
            program: held.program,
            outcome,
        });
    }
}

impl Drop for AddonSession {
    /// The backstop. Consuming the handle guarantees the teardown runs at most once; nothing
    /// guarantees it runs at all, because an error between starting and stopping drops this instead.
    /// Signalling each group here is a plain syscall, so it is safe from a drop, and it turns that
    /// case into "stopped" rather than "leaked with nobody watching". No queued after-game tool runs
    /// from here.
    fn drop(&mut self) {
        for held in &self.held {
            if held.keep_after_close {
                continue;
            }
            #[cfg(target_os = "linux")]
            if let Some(pid) = rustix::process::Pid::from_raw(held.companion.pid()) {
                let _ = rustix::process::kill_process_group(pid, rustix::process::Signal::TERM);
            }
        }
    }
}

// Deliberately partial: counts rather than contents, since a session also holds a runtime handle and
// other people's programs, neither of which reads as anything useful in a log line.
#[allow(clippy::missing_fields_in_debug)]
impl std::fmt::Debug for AddonSession {
    /// Counts rather than contents: a session holds a runtime handle and other people's programs,
    /// neither of which reads as anything useful in a log line.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AddonSession")
            .field("running", &self.held.len())
            .field("pending_on_close", &self.on_close.len())
            .finish()
    }
}

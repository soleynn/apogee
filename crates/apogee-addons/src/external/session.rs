//! The companions one launch started, and what happens to them when the game exits.
//!
//! Two things have to hold. The teardown must run at most once, which the type gets by consuming
//! itself. And it must run at least once, which consuming cannot give: an early return between
//! starting and stopping would drop the handle and leave every companion running under a name the
//! user never chose, with nothing left that knows about them. So the drop is a backstop that signals
//! each group it was going to stop anyway.

use std::time::Duration;

use apogee_runtime::{Companion, Runtime};

use super::addon::{ExternalAddon, Trigger};
use super::event::{AddonEvent, AddonEvents};

/// How long a companion is given to stop on its own before it is ended.
const STOP_GRACE: Duration = Duration::from_secs(5);

/// What became of one entry.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Outcome {
    /// Started, and running under the given process id.
    Started { pid: i32 },
    /// Not started because it was already running, under the given process id.
    ///
    /// Whoever started it owns it: a launch that finds a companion it did not start never stops it.
    AlreadyRunning { pid: i32 },
    /// Not started because the entry is switched off.
    Disabled,
    /// Ran after the game exited and finished with this status.
    Completed { code: Option<i32> },
    /// Could not be run. The rest of the launch is unaffected.
    Failed { reason: String },
}

/// One entry and what became of it.
#[derive(Debug, Clone)]
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
pub struct AddonReport {
    /// One per configured entry, in order.
    pub outcomes: Vec<AddonOutcome>,
}

impl AddonReport {
    /// Whether any entry failed. A caller decides what that is worth; nothing here interrupts a
    /// launch over a helper tool.
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
    pub(super) fn new(
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
/// was going to stop, so an early return cannot leave them running with nobody to end them.
#[must_use = "a launch's companions need either game_closed or abandon, or they are stopped on drop"]
pub struct AddonSession {
    /// Cloned rather than borrowed so the session outlives the call that made it, which it must:
    /// the after-game tools run once the launch is already unwinding.
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
    pub(super) fn new(
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
    pub fn report(&self) -> &AddonReport {
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
    /// # Errors
    /// Never fails as a whole. A companion that cannot be stopped or run is recorded in the returned
    /// report; a helper tool does not fail a launch that already succeeded.
    pub async fn game_closed(mut self, events: &AddonEvents) -> AddonReport {
        for held in std::mem::take(&mut self.held) {
            Self::stop_one(held, events, &mut self.report).await;
        }
        for (index, addon) in std::mem::take(&mut self.on_close) {
            let outcome = super::run_to_completion(
                &self.runtime,
                self.game_prefix.as_deref(),
                &addon,
                events,
            )
            .await;
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
    /// Used when the launch itself failed, where running a tool that expects the game to have played
    /// would be wrong.
    pub async fn abandon(mut self, events: &AddonEvents) -> AddonReport {
        for held in std::mem::take(&mut self.held) {
            Self::stop_one(held, events, &mut self.report).await;
        }
        self.on_close.clear();
        std::mem::take(&mut self.report)
    }

    async fn stop_one(mut held: Held, events: &AddonEvents, report: &mut AddonReport) {
        if held.keep_after_close {
            return;
        }
        let outcome = match held.companion.stop(STOP_GRACE).await {
            Ok(()) => Outcome::Completed { code: None },
            Err(err) => Outcome::Failed {
                reason: err.to_string(),
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
    /// case into "stopped" rather than "leaked with nobody watching".
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

impl std::fmt::Debug for AddonSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AddonSession")
            .field("running", &self.held.len())
            .field("pending_on_close", &self.on_close.len())
            .finish()
    }
}

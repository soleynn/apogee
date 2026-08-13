//! The runtime's typed progress stream.
//!
//! [`Progress`] is a cheap, cloneable sink that long-running operations report [`RuntimeEvent`]s
//! into. A default sink is silent, so a caller that does not want progress passes
//! `&Progress::none()` rather than wiring a channel it will never read.

use std::fmt;

use tokio::sync::mpsc::UnboundedSender;

/// A progress sink.
///
/// Clone it to hand into concurrent work; the stream ends when the last clone is dropped. A launch
/// that reports a supervised launch program keeps a clone alive until that program exits, so the
/// stream can outlive the call that opened it.
///
/// # Examples
///
/// ```
/// use apogee_runtime::{Progress, RuntimeEvent};
///
/// let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<RuntimeEvent>();
/// let progress = Progress::new(tx);
///
/// // Hand `progress` to a runtime call and read events off `rx`. Dropping every clone is what
/// // ends the consumer's read loop.
/// drop(progress);
/// // `RuntimeEvent` is not `PartialEq`, so the disconnect is matched rather than compared.
/// use tokio::sync::mpsc::error::TryRecvError;
/// assert!(matches!(rx.try_recv(), Err(TryRecvError::Disconnected)));
/// ```
#[derive(Debug, Clone, Default)]
pub struct Progress {
    tx: Option<UnboundedSender<RuntimeEvent>>,
}

impl Progress {
    /// A sink that forwards events to `tx`.
    #[must_use]
    pub fn new(tx: UnboundedSender<RuntimeEvent>) -> Self {
        Self { tx: Some(tx) }
    }

    /// A silent sink that discards events.
    #[must_use]
    pub fn none() -> Self {
        Self::default()
    }

    /// Report one event.
    ///
    /// A closed receiver is not an error: progress is advisory, so the send result is dropped.
    pub(crate) fn emit(&self, event: RuntimeEvent) {
        if let Some(tx) = &self.tx {
            let _ = tx.send(event);
        }
    }
}

/// A typed progress event from a runtime operation.
///
/// `#[non_exhaustive]`, so a consumer needs a catch-all arm: a later release can report something
/// this one does not.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum RuntimeEvent {
    /// Download progress for a runner, tool or DXVK artifact, relayed verbatim from `apogee-fetch`.
    Download(apogee_fetch::Progress),
    /// Extraction of a downloaded runner or tool artifact has begun.
    Extracting {
        /// The artifact's name, as the catalog entry gives it.
        name: String,
        /// The artifact's version, as the catalog entry gives it.
        version: String,
    },
    /// A runner finished downloading and extracting.
    RunnerReady {
        /// The runner's name, as the catalog entry gives it.
        name: String,
        /// The runner's version, as the catalog entry gives it.
        version: String,
    },
    /// A supporting tool such as `umu-launcher` finished downloading and extracting.
    ToolReady {
        /// The tool's name, as the catalog entry gives it.
        name: String,
        /// The tool's version, as the catalog entry gives it.
        version: String,
    },
    /// A prefix is being initialized through `wineboot`.
    PrefixInitializing {
        /// Whether the prefix is being created from nothing rather than updated in place.
        fresh: bool,
    },
    /// A prefix finished initializing and its metadata file
    /// ([`PREFIX_JSON`](crate::PREFIX_JSON)) was written.
    PrefixReady,
    /// A prefix repair has begun.
    PrefixRepairing {
        /// How many health issues the repair was handed. Not all of them are locally repairable,
        /// so the residual health it returns can still name some of these.
        issues: usize,
    },
    /// A prefix is being destructively recreated.
    PrefixRecreating,
    /// DXVK is being installed into a prefix.
    DxvkInstalling {
        /// The DXVK version being installed.
        version: String,
        /// Whether the NVAPI DLLs go in with it: both requested by the caller and offered by the
        /// catalog entry.
        nvapi: bool,
    },
    /// DXVK finished installing into a prefix.
    DxvkReady {
        /// The DXVK version that was installed.
        version: String,
    },
    /// The game is being spawned through the runner.
    ///
    /// Not raised by a launch that spawns the game directly (Windows), where there is no runner to
    /// name.
    Spawning {
        /// The runner's name, as the prefix records it.
        runner: String,
    },
    /// The real game process was resolved.
    ///
    /// By the `/proc` scan where a runner started it, and by the spawn itself where the launcher
    /// started the game directly.
    GameResolved {
        /// The game's host process id.
        pid: i32,
    },
    /// The game process exited.
    ///
    /// Nothing reports this today: a session's end is observed by awaiting
    /// [`GameSession::wait`](crate::GameSession::wait) instead.
    GameExited,
    /// The spawned program exited, for a launch where it was not the game itself.
    ///
    /// Raised only when the plan named another process to supervise, which is exactly the case
    /// where something redirected the launch (see
    /// [`LaunchPlan::set_supervised`](crate::LaunchPlan::set_supervised)). For an ordinary launch
    /// the spawned program is the game's own loader and its status reports nothing but the handoff.
    ///
    /// Says nothing about the launch being over: when it arrives is a property of whatever was
    /// spawned, a loader that starts the game and returns exiting seconds in while a
    /// container-style runner outlives the session. The game's own exit comes from awaiting
    /// [`GameSession::wait`](crate::GameSession::wait), not from this stream.
    LaunchProgramExited {
        /// The program as it was spawned, verbatim from the plan.
        program: String,
        /// Its raw status. What a particular code means belongs to whatever put the program on the
        /// launch: this crate does not know what was spawned, and the loaders that redirect a
        /// launch number their own failures.
        status: ProgramStatus,
    },
}

/// How a spawned program ended.
///
/// A signal is its own arm rather than the absent code [`CompanionExit`](crate::CompanionExit)
/// reports, because for a loader the two read in opposite directions: a non-zero code is the
/// program's own report that it did not do its job, and a signal is something else ending it before
/// it could report anything at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProgramStatus {
    /// Exited on its own, with this status code.
    Code(i32),
    /// Killed by this signal, with no status of its own.
    Signal(i32),
}

impl ProgramStatus {
    /// Whether the program reported success, which is [`Self::Code`] zero and nothing else.
    #[must_use]
    pub fn is_success(self) -> bool {
        self == Self::Code(0)
    }

    /// Read a reaped child's status.
    ///
    /// `None` is a status that is neither an exit nor a signal, which a completed `wait` cannot
    /// produce: it resolves only for a process that did one or the other.
    #[cfg(unix)]
    pub(crate) fn from_exit(status: std::process::ExitStatus) -> Option<Self> {
        use std::os::unix::process::ExitStatusExt;

        status
            .code()
            .map(Self::Code)
            .or_else(|| status.signal().map(Self::Signal))
    }
}

impl fmt::Display for ProgramStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Code(code) => write!(f, "exit code {code}"),
            Self::Signal(signal) => write!(f, "signal {signal}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Success is exit code zero and nothing else, a signal included.
    #[test]
    fn only_a_zero_code_is_success() {
        assert!(ProgramStatus::Code(0).is_success());
        assert!(!ProgramStatus::Code(1).is_success());
        // A stopped launcher is not a companion that reported failure, so the signal arm never reads
        // as success and never reads as a code either.
        assert!(!ProgramStatus::Signal(9).is_success());
    }

    /// The `Display` rendering says which of the two a status is, not just its number.
    #[test]
    fn a_status_renders_as_what_it_is() {
        assert_eq!(ProgramStatus::Code(3).to_string(), "exit code 3");
        assert_eq!(ProgramStatus::Signal(9).to_string(), "signal 9");
    }

    /// A reaped `ExitStatus` maps to the arm it actually carries, keeping the two apart.
    #[cfg(unix)]
    #[test]
    fn an_exit_status_reads_as_a_code_or_a_signal() {
        use std::os::unix::process::ExitStatusExt;
        use std::process::ExitStatus;

        assert_eq!(
            ProgramStatus::from_exit(ExitStatus::from_raw(3 << 8)),
            Some(ProgramStatus::Code(3))
        );
        assert_eq!(
            ProgramStatus::from_exit(ExitStatus::from_raw(9)),
            Some(ProgramStatus::Signal(9))
        );
    }
}

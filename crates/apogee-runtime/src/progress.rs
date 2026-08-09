//! The runtime's typed progress stream.
//!
//! [`Progress`] is a cheap, cloneable sink long-running operations report into; the events are
//! [`RuntimeEvent`]s. A `Default` sink is a silent no-op, so a caller that does not care about
//! progress passes `&Progress::none()`.

use std::fmt;

use tokio::sync::mpsc::UnboundedSender;

/// A progress sink. Clone it to hand into concurrent work; drop all clones to close the stream.
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

    /// Report one event. A closed receiver is not an error: progress is advisory.
    pub(crate) fn emit(&self, event: RuntimeEvent) {
        if let Some(tx) = &self.tx {
            let _ = tx.send(event);
        }
    }
}

/// A typed runtime progress event. `#[non_exhaustive]`: later phases add prefix/DXVK events.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum RuntimeEvent {
    /// Download progress for a runner/tool artifact, relayed verbatim from `apogee-fetch`.
    Download(apogee_fetch::Progress),
    /// Extraction of a downloaded artifact has begun.
    Extracting { name: String, version: String },
    /// A runner finished downloading and extracting.
    RunnerReady { name: String, version: String },
    /// A supporting tool (e.g. `umu-launcher`) finished downloading and extracting.
    ToolReady { name: String, version: String },
    /// A prefix is being initialized through `wineboot`. `fresh` is a first-time init vs an update.
    PrefixInitializing { fresh: bool },
    /// A prefix finished initialization and its `prefix.json` was written.
    PrefixReady,
    /// A prefix repair is running over `issues` detected problems.
    PrefixRepairing { issues: usize },
    /// A prefix is being destructively recreated.
    PrefixRecreating,
    /// DXVK is being installed into a prefix.
    DxvkInstalling { version: String, nvapi: bool },
    /// DXVK finished installing into a prefix.
    DxvkReady { version: String },
    /// The game is being spawned through the runner.
    Spawning { runner: String },
    /// The `/proc` scan resolved the real game process.
    GameResolved { pid: i32 },
    /// The game process exited.
    GameExited,
    /// The program that was spawned exited, for a launch where that program was not the game.
    ///
    /// Emitted only when the plan named another process to supervise, which is exactly the case where
    /// something redirected the launch (see [`LaunchPlan::set_supervised`](crate::LaunchPlan::set_supervised)).
    /// For an ordinary launch the spawned program *is* the game's own loader, and its status reports
    /// nothing but the handoff, so it is not raised.
    ///
    /// Says nothing about the launch being over. When this arrives is a property of whatever was
    /// spawned rather than of the session: a loader that starts the game and returns exits seconds in,
    /// while a container-style runner outlives the whole session. The game's own exit is
    /// [`GameExited`](Self::GameExited).
    LaunchProgramExited {
        /// The program as it was spawned, verbatim from the plan.
        program: String,
        /// Its raw status. What a particular code means belongs to whatever put the program on the
        /// launch: this crate does not know what was spawned, and the two loaders that redirect a
        /// launch today number their failures themselves.
        status: ProgramStatus,
    },
}

/// How a spawned program ended.
///
/// A signal is its own arm rather than the absent code [`CompanionExit`](crate::CompanionExit)
/// reports, because for a loader the two read in opposite directions: a non-zero code is the program's
/// own report that it did not do its job, and a signal is something else ending it before it could
/// report anything at all. Collapsing them would turn a launcher the user stopped into a companion
/// that failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProgramStatus {
    /// Exited on its own, with this status code.
    Code(i32),
    /// Killed by this signal, with no status of its own.
    Signal(i32),
}

impl ProgramStatus {
    /// Whether the program exited reporting success.
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

    #[test]
    fn only_a_zero_code_is_success() {
        assert!(ProgramStatus::Code(0).is_success());
        assert!(!ProgramStatus::Code(1).is_success());
        // A stopped launcher is not a companion that reported failure, so the signal arm never reads
        // as success and never reads as a code either.
        assert!(!ProgramStatus::Signal(9).is_success());
    }

    #[test]
    fn a_status_renders_as_what_it_is() {
        assert_eq!(ProgramStatus::Code(3).to_string(), "exit code 3");
        assert_eq!(ProgramStatus::Signal(9).to_string(), "signal 9");
    }

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

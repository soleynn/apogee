//! What the addon layer reports while it works.
//!
//! Its own enum rather than the runtime's: these are facts about companion tools, and widening the
//! runtime's event type would make every runtime consumer match on variants it can never see. The
//! composition root translates, which is what it already does for the runtime's own stream.

use std::path::PathBuf;
use std::time::Duration;

use tokio::sync::mpsc::UnboundedSender;

use super::session::Outcome;

/// Something that happened to a companion tool.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum AddonEvent {
    /// A companion was started.
    #[non_exhaustive]
    Started { program: PathBuf, pid: i32 },
    /// A companion was not started because it was already running.
    #[non_exhaustive]
    AlreadyRunning { program: PathBuf, pid: i32 },
    /// A companion was stopped along with the game.
    #[non_exhaustive]
    Stopped { program: PathBuf, pid: i32 },
    /// A companion that runs after the game finished.
    #[non_exhaustive]
    Finished { program: PathBuf, outcome: Outcome },
    /// One entry could not be run. The launch is unaffected.
    #[non_exhaustive]
    Failed { program: PathBuf, reason: String },
    /// Still waiting on a companion that runs after the game, so a launcher that has not exited can
    /// say why rather than appearing to hang.
    #[non_exhaustive]
    StillWaiting { program: PathBuf, seconds: u64 },
    /// Something loaded into the game left proof it came up: a file it writes from *inside* the game
    /// process was written after this launch began.
    ///
    /// The only report of its kind every runner can produce. A loader's own exit status says what it
    /// believed on its way out, and is unreachable behind a container-style runner where what the
    /// launcher spawned is the runner rather than the loader.
    #[non_exhaustive]
    Loaded { what: String },
    /// No such proof yet, after waiting.
    ///
    /// Deliberately not "it failed". Absence is not evidence here, because the game may still be
    /// starting, and a launcher that announced a failure on a slow machine would be wrong in the one
    /// direction that costs a user their trust in the report. `evidence` is the file that was watched,
    /// so whoever reads this can look for themselves.
    #[non_exhaustive]
    NotConfirmed {
        what: String,
        waited: Duration,
        evidence: PathBuf,
    },
}

/// Where addon events go. Cloneable and cheap, like the runtime's own.
#[derive(Debug, Clone, Default)]
pub struct AddonEvents {
    tx: Option<UnboundedSender<AddonEvent>>,
}

impl AddonEvents {
    /// A stream that goes nowhere, for a caller that does not want the events.
    #[must_use]
    pub fn none() -> Self {
        Self { tx: None }
    }

    /// A stream feeding `tx`.
    #[must_use]
    pub fn new(tx: UnboundedSender<AddonEvent>) -> Self {
        Self { tx: Some(tx) }
    }

    /// Report one event. A closed receiver is not an error: nothing here should fail because a
    /// listener went away.
    pub fn emit(&self, event: AddonEvent) {
        if let Some(tx) = &self.tx {
            let _ = tx.send(event);
        }
    }
}

//! What the addon layer reports while it works.
//!
//! Its own enum rather than the runtime's: these are facts about companion tools, and widening the
//! runtime's event type would make every runtime consumer match on variants it can never see. The
//! composition root translates, which is what it already does for the runtime's own stream.

use std::path::PathBuf;

use tokio::sync::mpsc::UnboundedSender;

use super::session::Outcome;

/// Something that happened to a companion tool.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum AddonEvent {
    /// A companion was started.
    Started { program: PathBuf, pid: i32 },
    /// A companion was not started because it was already running.
    AlreadyRunning { program: PathBuf, pid: i32 },
    /// A companion was stopped along with the game.
    Stopped { program: PathBuf, pid: i32 },
    /// A companion that runs after the game finished.
    Finished { program: PathBuf, outcome: Outcome },
    /// One entry could not be run. The launch is unaffected.
    Failed { program: PathBuf, reason: String },
    /// Still waiting on a companion that runs after the game, so a launcher that has not exited can
    /// say why rather than appearing to hang.
    StillWaiting { program: PathBuf, seconds: u64 },
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

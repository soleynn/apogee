//! What the addon layer reports while it works.
//!
//! Its own enum rather than the runtime's: these are facts about companion tools, and widening the
//! runtime's event type would make every runtime consumer match on variants it can never see. The
//! composition root translates.

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
    Started {
        /// The program that was started.
        program: PathBuf,
        /// Its process id.
        pid: i32,
    },
    /// A companion was not started because it was already running.
    #[non_exhaustive]
    AlreadyRunning {
        /// The program that was already up.
        program: PathBuf,
        /// The process id of the copy that was found.
        pid: i32,
    },
    /// A companion was stopped along with the game.
    #[non_exhaustive]
    Stopped {
        /// The program that was stopped.
        program: PathBuf,
        /// The process id it was stopped under.
        pid: i32,
    },
    /// A companion that runs after the game finished.
    #[non_exhaustive]
    Finished {
        /// The program that ran.
        program: PathBuf,
        /// What it came to.
        outcome: Outcome,
    },
    /// One entry could not be run. The launch is unaffected.
    #[non_exhaustive]
    Failed {
        /// The program the entry names.
        program: PathBuf,
        /// The failure and its causes, as one line.
        reason: String,
    },
    /// Still waiting on a companion that runs after the game, so a launcher that has not exited can
    /// say why rather than appearing to hang.
    #[non_exhaustive]
    StillWaiting {
        /// The program still being waited on.
        program: PathBuf,
        /// How long it has been, in whole seconds.
        seconds: u64,
    },
    /// Something loaded into the game left proof it came up: a file it writes from *inside* the game
    /// process was written after this launch began.
    ///
    /// The only report of its kind every runner can produce. A loader's own exit status says what it
    /// believed on its way out, and is unreachable behind a container-style runner, where what the
    /// launcher spawned is the runner rather than the loader.
    #[non_exhaustive]
    Loaded {
        /// What came up inside the game.
        what: String,
    },
    /// No such proof yet, after waiting.
    ///
    /// Deliberately not "it failed". The game may still be starting, and a launcher that announced a
    /// failure on a slow machine would be wrong in the one direction that costs a user their trust
    /// in the report. `evidence` is the file that was watched, so whoever reads this can look for
    /// themselves.
    #[non_exhaustive]
    NotConfirmed {
        /// What was being waited for.
        what: String,
        /// How long the watch ran before giving up.
        waited: Duration,
        /// The file that was watched, so a reader can look for themselves.
        evidence: PathBuf,
    },
}

/// Where addon events go. Cheap to clone, so a launch can hand one to each stage.
///
/// # Examples
///
/// ```
/// use apogee_addons::{AddonEvent, AddonEvents};
///
/// let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<AddonEvent>();
/// let events = AddonEvents::new(tx);
/// // Each stage of a launch takes one, so it travels by clone.
/// let for_teardown = events.clone();
///
/// assert!(rx.try_recv().is_err(), "nothing has been reported yet");
/// # drop((events, for_teardown));
/// ```
#[derive(Debug, Clone, Default)]
pub struct AddonEvents {
    tx: Option<UnboundedSender<AddonEvent>>,
}

impl AddonEvents {
    /// A stream that goes nowhere, for a caller that does not want the events.
    ///
    /// # Examples
    ///
    /// ```
    /// use apogee_addons::AddonEvents;
    ///
    /// let events = AddonEvents::none();
    /// ```
    #[must_use]
    pub const fn none() -> Self {
        Self { tx: None }
    }

    /// A stream feeding `tx`.
    #[must_use]
    pub const fn new(tx: UnboundedSender<AddonEvent>) -> Self {
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

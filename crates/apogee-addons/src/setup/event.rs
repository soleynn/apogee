//! What the setup layer reports while it prepares a prefix and installs an injectable.
//!
//! Its own enum, for the same reason the companion-lifecycle events are: these are facts about
//! setting a prefix up, and widening either the runtime's stream or the launch-time addon stream
//! would make every consumer of those match on variants it can never see.
//!
//! A caveat is an event rather than a field on a report, because the point of a caveat is that it is
//! read while the thing is being set up. A caveat only available afterwards, from a report nobody
//! prints, is how "it loaded and did nothing" arrives as a surprise a week later.

use tokio::sync::mpsc::UnboundedSender;

/// Something that happened while preparing a prefix or installing an injectable.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum SetupEvent {
    /// An archive is being fetched. `what` is what it is for, named by whatever is fetching it.
    Downloading {
        what: String,
        bytes_done: u64,
        total: Option<u64>,
    },
    /// Files are going into place.
    Installing { what: String, version: String },
    /// It is installed and recorded.
    Installed { what: String },
    /// The prefix already records it, so nothing was done.
    AlreadyPresent { what: String },
    /// A prefix-setup verb is being applied, with the reason its row states.
    Applying { verb: String, reason: String },
    /// A verb the prefix records is being applied again, because the effect it left was checked and is
    /// gone. `because` is the reading that says so.
    ///
    /// Said out loud rather than kept to the plan, because a verb reapplied on every launch is what a
    /// wrong reading looks like from outside, and the reading is the only thing that distinguishes it
    /// from something in the prefix genuinely undoing the verb each time.
    Reapplying { verb: String, because: String },
    /// A verb was applied and recorded.
    Applied { verb: String },
    /// Something the user needs to know about this now rather than later: the support tier it is on,
    /// or what the runner it is about to run under costs it.
    Caveat { what: String, note: String },
    /// One step could not be completed. Whatever else was asked for continues.
    Failed { what: String, reason: String },
    /// The signed catalog could not be reached. `using_cached` says whether the last one a fetch verified
    /// stood in for it, or whether the launch went ahead with no prefix setup at all.
    ///
    /// A report rather than an error, and that distinction is the point: falling back to a catalog that
    /// once verified is the *correct* outcome for a launch, so a shell must not turn it into a failed
    /// exit for a game that started fine. It still has to be said out loud, because which build of a
    /// companion started is exactly what somebody debugging one needs to know.
    CatalogUnavailable { detail: String, using_cached: bool },
}

/// Where setup events go. Cloneable and cheap, like the crate's other stream.
#[derive(Debug, Clone, Default)]
pub struct SetupEvents {
    tx: Option<UnboundedSender<SetupEvent>>,
}

impl SetupEvents {
    /// A stream that goes nowhere, for a caller that does not want the events.
    #[must_use]
    pub fn none() -> Self {
        Self { tx: None }
    }

    /// A stream feeding `tx`.
    #[must_use]
    pub fn new(tx: UnboundedSender<SetupEvent>) -> Self {
        Self { tx: Some(tx) }
    }

    /// Report one event. A closed receiver is not an error: nothing here should fail because a listener
    /// went away.
    pub fn emit(&self, event: SetupEvent) {
        if let Some(tx) = &self.tx {
            let _ = tx.send(event);
        }
    }
}

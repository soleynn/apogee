//! What the setup layer reports while it prepares a prefix and installs an injectable.
//!
//! Its own enum rather than a widening of the runtime's stream or of the launch-time addon stream:
//! these are facts about setting a prefix up, and folding them into either of those would make every
//! consumer of those match on variants it can never see.

use apogee_fetch::Recoveries;
use tokio::sync::mpsc::UnboundedSender;

/// Something that happened while preparing a prefix or installing an injectable.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum SetupEvent {
    /// An archive is being fetched.
    Downloading {
        /// What it is for, named by whatever is fetching it.
        what: String,
        /// Bytes written so far.
        bytes_done: u64,
        /// The total, when the server declared one.
        total: Option<u64>,
        /// What the transfer recovered from to get this far. Relayed rather than dropped: every
        /// recovery it counts ends in a download that succeeded, so nothing else here would say a
        /// component took four attempts to arrive.
        recoveries: Recoveries,
    },
    /// Files are going into place.
    Installing {
        /// What is being installed.
        what: String,
        /// The version going down, as its distribution names it.
        version: String,
    },
    /// It is installed and recorded.
    Installed {
        /// What was installed.
        what: String,
    },
    /// The prefix already records it, so nothing was done.
    AlreadyPresent {
        /// What was already there.
        what: String,
    },
    /// A prefix-setup verb is being applied, with the reason its row states.
    Applying {
        /// The verb, by the name the manifest gives it.
        verb: String,
        /// Why it exists, as its row states it.
        reason: String,
    },
    /// A verb the prefix records is being applied again, because the effect it left was checked and
    /// is gone. `because` is the reading that says so.
    ///
    /// Said out loud rather than kept to the plan, because a verb reapplied on every launch is what
    /// a wrong reading looks like from outside, and the reading is the only thing that distinguishes
    /// it from something in the prefix genuinely undoing the verb each time.
    Reapplying {
        /// The verb, by the name the manifest gives it.
        verb: String,
        /// The reading that says the effect is gone.
        because: String,
    },
    /// A verb was applied and recorded.
    Applied {
        /// The verb, by the name the manifest gives it.
        verb: String,
    },
    /// Something the user needs to know about now rather than later: the support tier a component is
    /// on, or what the runner it is about to run under costs it.
    ///
    /// An event rather than a field on a report, because the point of a caveat is that it is read
    /// while the thing is being set up. A caveat only available afterwards, from a report nobody
    /// prints, is how "it loaded and did nothing" arrives as a surprise a week later.
    Caveat {
        /// What the caveat is about.
        what: String,
        /// What it costs, in the user's terms.
        note: String,
    },
    /// One step could not be completed. Whatever else was asked for continues.
    Failed {
        /// What could not be completed.
        what: String,
        /// The failure and its causes, as one line.
        reason: String,
    },
    /// The signed catalog could not be reached. `using_cached` says whether the last one a fetch
    /// verified stood in for it, or whether the launch went ahead with no prefix setup at all.
    ///
    /// A report rather than an error, and that distinction is the point: falling back to a catalog
    /// that once verified is the *correct* outcome for a launch, so a shell must not turn it into a
    /// failed exit for a game that started fine. It still has to be said out loud, because which
    /// build of a companion started is exactly what somebody debugging one needs to know.
    CatalogUnavailable {
        /// Why it could not be reached, as one line.
        detail: String,
        /// Whether the last catalog a fetch verified stood in for it.
        using_cached: bool,
    },
    /// The pass stopped because it was asked to, with `applied` verbs behind it and the rest not
    /// reached.
    ///
    /// The one ending that produces no per-verb event of its own: everything else a pass does is
    /// narrated as it happens, and a stream that simply stopped is indistinguishable from a stream
    /// that finished.
    #[non_exhaustive]
    Stopped {
        /// How many verbs went in before the stop.
        applied: usize,
    },
}

/// Where setup events go. Cloneable and cheap, like the crate's other event stream.
///
/// # Examples
///
/// ```
/// use apogee_addons::{SetupEvent, SetupEvents};
///
/// let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
/// let events = SetupEvents::new(tx);
/// events.emit(SetupEvent::Applied {
///     verb: "no-desktop-integration".to_owned(),
/// });
///
/// assert!(matches!(rx.try_recv(), Ok(SetupEvent::Applied { .. })));
/// ```
#[derive(Debug, Clone, Default)]
pub struct SetupEvents {
    tx: Option<UnboundedSender<SetupEvent>>,
}

impl SetupEvents {
    /// A stream that goes nowhere, for a caller that does not want the events. What [`Default`]
    /// gives, said in a name.
    ///
    /// # Examples
    ///
    /// ```
    /// use apogee_addons::{SetupEvent, SetupEvents};
    ///
    /// let events = SetupEvents::none();
    /// events.emit(SetupEvent::Applied {
    ///     verb: "no-desktop-integration".to_owned(),
    /// });
    /// ```
    #[must_use]
    pub const fn none() -> Self {
        Self { tx: None }
    }

    /// A stream feeding `tx`.
    #[must_use]
    pub const fn new(tx: UnboundedSender<SetupEvent>) -> Self {
        Self { tx: Some(tx) }
    }

    /// Report one event. A closed receiver is not an error: nothing here should fail because a
    /// listener went away.
    pub fn emit(&self, event: SetupEvent) {
        if let Some(tx) = &self.tx {
            let _ = tx.send(event);
        }
    }
}

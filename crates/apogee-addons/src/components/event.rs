//! What the component layer reports while it installs.
//!
//! Its own enum, for the same reason the companion-lifecycle events are: these are facts about
//! components, and widening either the runtime's stream or the launch-time addon stream would make
//! every consumer of those match on variants it can never see.
//!
//! A caveat is an event rather than a field on a report, because the point of a caveat is that it is
//! read at install time. A caveat only available afterwards, from a report nobody prints, is how "the
//! parser sees no data" arrives as a surprise a week later.

use tokio::sync::mpsc::UnboundedSender;

/// Something that happened while installing components.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum ComponentEvent {
    /// A component's archive is being fetched. Byte counts only; the shell supplies the label.
    Downloading {
        component: String,
        bytes_done: u64,
        total: Option<u64>,
    },
    /// A component's files are going into place.
    Installing { component: String, version: String },
    /// A component is installed and recorded.
    Installed { component: String },
    /// The prefix already records it, so nothing was done.
    AlreadyPresent { component: String },
    /// A prefix-setup verb is being applied, with the reason its row states.
    Applying { verb: String, reason: String },
    /// A verb was applied and recorded.
    Applied { verb: String },
    /// Something the user needs to know about this component now rather than later.
    Caveat { component: String, note: String },
    /// One component could not be installed. The rest of the set continues.
    Failed { component: String, reason: String },
    /// The manifest offers it but this build cannot drive it.
    Unsupported { component: String, what: String },
    /// The signed catalog could not be reached. `using_cached` says whether the last one a fetch verified
    /// stood in for it, or whether the launch went ahead with none of the enabled components.
    ///
    /// A report rather than an error, and that distinction is the point: falling back to a catalog that
    /// once verified is the *correct* outcome for a launch, so a shell must not turn it into a failed
    /// exit for a game that started fine. It still has to be said out loud, because which build of a
    /// companion started is exactly what somebody debugging one needs to know.
    CatalogUnavailable { detail: String, using_cached: bool },
}

/// Where component events go. Cloneable and cheap, like the crate's other stream.
#[derive(Debug, Clone, Default)]
pub struct ComponentEvents {
    tx: Option<UnboundedSender<ComponentEvent>>,
}

impl ComponentEvents {
    /// A stream that goes nowhere, for a caller that does not want the events.
    #[must_use]
    pub fn none() -> Self {
        Self { tx: None }
    }

    /// A stream feeding `tx`.
    #[must_use]
    pub fn new(tx: UnboundedSender<ComponentEvent>) -> Self {
        Self { tx: Some(tx) }
    }

    /// Report one event. A closed receiver is not an error: nothing here should fail because a listener
    /// went away.
    pub fn emit(&self, event: ComponentEvent) {
        if let Some(tx) = &self.tx {
            let _ = tx.send(event);
        }
    }
}

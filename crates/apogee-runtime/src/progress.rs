//! The runtime's typed progress stream.
//!
//! [`Progress`] is a cheap, cloneable sink long-running operations report into; the events are
//! [`RuntimeEvent`]s. A `Default` sink is a silent no-op, so a caller that does not care about
//! progress passes `&Progress::none()`.

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
    /// The game is being spawned through the runner.
    Spawning { runner: String },
    /// The `/proc` scan resolved the real game process.
    GameResolved { pid: i32 },
    /// The game process exited.
    GameExited,
}

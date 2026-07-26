//! The seam over `apogee-addons` for one launch's companion tools.
//!
//! A trait rather than the concrete manager for the same reason patch and launch are: the flow
//! context is cloned onto a spawned task, and the flow tests state that they start no real process.
//! A fake here keeps that true while still exercising the ordering the flow is responsible for.
//!
//! The teardown is a separate object from the thing that started it, because it must be consumed to
//! run. That is what makes "the companions are torn down exactly once" a property of the types rather
//! than of remembering to call something.

pub(crate) mod addons_backend;
#[cfg(test)]
pub(crate) mod fake;

use apogee_runtime::Prefix;
use async_trait::async_trait;
use tokio::sync::mpsc::UnboundedSender;
use tokio_util::sync::CancellationToken;

use apogee_addons::ExternalAddon;

use crate::command::Event;
use crate::error::CoreError;

/// Drives `apogee-addons` for one launch, relaying its events onto the core event stream.
#[async_trait]
pub(crate) trait AddonBackend: Send + Sync {
    /// Start the profile's companions for a game that is already running.
    ///
    /// Infallible by design: a helper tool that cannot start is reported on `events` and in the
    /// returned lifecycle's failures, never as an error that would fail a launch already in progress.
    async fn start(
        &self,
        game_pid: i32,
        prefix: Option<Prefix>,
        addons: Vec<ExternalAddon>,
        cancel: &CancellationToken,
        events: &UnboundedSender<Event>,
    ) -> Box<dyn AddonLifecycle>;
}

/// The teardown one launch's companions are owed.
#[async_trait]
pub(crate) trait AddonLifecycle: Send + Sync {
    /// Whether anything is still owed when the game exits. A launcher that would otherwise detach
    /// after starting the game has to stay attached for this.
    fn has_work(&self) -> bool;

    /// The game exited: stop what goes with it, then run what waits for it. Returns the failures to
    /// report, already in the core's error type, so the shell needs no rule of its own to notice one.
    async fn game_closed(self: Box<Self>, cancel: &CancellationToken) -> Vec<CoreError>;

    /// The launch was cancelled or failed: stop what was started, and run nothing that expects a
    /// session that actually happened.
    async fn abandon(self: Box<Self>, cancel: &CancellationToken) -> Vec<CoreError>;
}

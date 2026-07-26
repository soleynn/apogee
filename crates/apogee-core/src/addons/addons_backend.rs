//! The real seam over `apogee-addons`.
//!
//! Owns the addon event channel and the task that relays it onto the core stream. The teardown
//! awaits that task before returning, so no companion event can arrive after the flow has said the
//! launch is over.

use apogee_addons::{
    AddonEvents, AddonReport, AddonSession, Addons, ExternalAddon, GameContext, Outcome,
};
use apogee_runtime::Prefix;
use async_trait::async_trait;
use tokio::sync::mpsc::{self, UnboundedSender};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use super::{AddonBackend, AddonLifecycle};
use crate::command::Event;
use crate::error::CoreError;

/// The addon seam over the concrete manager.
pub(crate) struct AddonsBackend {
    addons: Addons,
}

impl AddonsBackend {
    pub(crate) fn new(addons: Addons) -> Self {
        Self { addons }
    }
}

#[async_trait]
impl AddonBackend for AddonsBackend {
    async fn start(
        &self,
        game_pid: i32,
        prefix: Option<Prefix>,
        addons: Vec<ExternalAddon>,
        _cancel: &CancellationToken,
        events: &UnboundedSender<Event>,
    ) -> Box<dyn AddonLifecycle> {
        let (addon_events, relay) = relay(events);
        // A pid the runtime reported cannot be zero or negative, but building the context is
        // fallible, and a launch is not worth failing over a helper: an unusable context simply
        // means no companion runs.
        let game = match prefix {
            Some(prefix) => GameContext::in_prefix(game_pid, &prefix),
            None => GameContext::new(game_pid),
        };
        let session = match game {
            Ok(game) => Some(
                self.addons
                    .start_external(&addons, &game, &addon_events)
                    .await,
            ),
            Err(err) => {
                let _ = events.send(Event::Error(CoreError::Addons(err)));
                None
            }
        };
        Box::new(RunningAddons {
            session,
            addon_events: Some(addon_events),
            relay,
        })
    }
}

/// One launch's running companions, and the relay feeding their events onto the core stream.
struct RunningAddons {
    session: Option<AddonSession>,
    /// Dropped before the relay is awaited, which is what lets the relay task finish.
    addon_events: Option<AddonEvents>,
    relay: JoinHandle<()>,
}

impl RunningAddons {
    /// Drop the sender and wait for the relay to drain, so the last companion event is delivered
    /// before the flow moves on.
    async fn drain(mut self) -> Vec<CoreError> {
        let _ = self.addon_events.take();
        let _ = self.relay.await;
        Vec::new()
    }
}

#[async_trait]
impl AddonLifecycle for RunningAddons {
    fn has_work(&self) -> bool {
        self.session.as_ref().is_some_and(AddonSession::has_work)
    }

    async fn game_closed(mut self: Box<Self>, _cancel: &CancellationToken) -> Vec<CoreError> {
        let events = self.addon_events.clone().unwrap_or_else(AddonEvents::none);
        let report = match self.session.take() {
            Some(session) => session.game_closed(&events).await,
            None => AddonReport::default(),
        };
        let mut failures = failures(&report);
        failures.extend((*self).drain().await);
        failures
    }

    async fn abandon(mut self: Box<Self>, _cancel: &CancellationToken) -> Vec<CoreError> {
        let events = self.addon_events.clone().unwrap_or_else(AddonEvents::none);
        let report = match self.session.take() {
            Some(session) => session.abandon(&events).await,
            None => AddonReport::default(),
        };
        let mut failures = failures(&report);
        failures.extend((*self).drain().await);
        failures
    }
}

/// The failures in a report, in the core's error type, so a shell notices one without a rule of its
/// own for what an addon report means.
fn failures(report: &AddonReport) -> Vec<CoreError> {
    report
        .outcomes
        .iter()
        .filter_map(|outcome| match &outcome.outcome {
            Outcome::Failed { reason } => Some(CoreError::Addon {
                program: outcome.program.clone(),
                reason: reason.clone(),
            }),
            _ => None,
        })
        .collect()
}

/// A channel whose addon events are forwarded onto the core stream verbatim, and the task doing it.
fn relay(events: &UnboundedSender<Event>) -> (AddonEvents, JoinHandle<()>) {
    let (tx, mut rx) = mpsc::unbounded_channel();
    let events = events.clone();
    let handle = tokio::spawn(async move {
        while let Some(event) = rx.recv().await {
            let _ = events.send(Event::Addon(event));
        }
    });
    (AddonEvents::new(tx), handle)
}

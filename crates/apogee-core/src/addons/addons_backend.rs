//! The real seam over `apogee-addons`.
//!
//! Owns the addon event channel and the task that relays it onto the core stream. The teardown
//! awaits that task before returning, so no companion event can arrive after the flow has said the
//! launch is over.

use apogee_addons::{
    AddonEvents, AddonReport, AddonSession, Addons, ComponentEvents, ComponentManifest,
    ComponentReport, ExternalAddon, GameContext, Outcome,
};
use apogee_runtime::Prefix;
use async_trait::async_trait;
use tokio::sync::mpsc::{self, UnboundedSender};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use url::Url;

use super::{AddonBackend, AddonLifecycle};
use crate::command::Event;
use crate::error::CoreError;

/// The addon seam over the concrete manager.
pub(crate) struct AddonsBackend {
    addons: Addons,
    /// The hosted component manifest and its detached signature.
    catalog: (Url, Url),
}

impl AddonsBackend {
    pub(crate) fn new(addons: Addons, catalog: (Url, Url)) -> Self {
        Self { addons, catalog }
    }
}

#[async_trait]
impl AddonBackend for AddonsBackend {
    async fn catalog(&self, cancel: &CancellationToken) -> Result<ComponentManifest, CoreError> {
        Ok(self
            .addons
            .fetch_manifest(&self.catalog.0, &self.catalog.1, cancel)
            .await?)
    }

    async fn ensure(
        &self,
        prefix: Option<Prefix>,
        wanted: Vec<String>,
        cancel: &CancellationToken,
        events: &UnboundedSender<Event>,
    ) -> Result<ComponentReport, CoreError> {
        let Some(prefix) = prefix else {
            return Ok(ComponentReport::default());
        };
        let manifest = self
            .addons
            .fetch_manifest(&self.catalog.0, &self.catalog.1, cancel)
            .await?;
        let (component_events, relay) = relay_components(events);
        let report = self
            .addons
            .ensure(&manifest, &prefix, &wanted, cancel, &component_events)
            .await;
        // Dropped before the relay is awaited: the relay ends when the channel closes, and the channel
        // closes only when the last sender is gone.
        drop(component_events);
        let _ = relay.await;
        report.map_err(CoreError::from)
    }

    async fn registrations(
        &self,
        prefix: Option<Prefix>,
        wanted: Vec<String>,
        cancel: &CancellationToken,
        events: &UnboundedSender<Event>,
    ) -> Vec<ExternalAddon> {
        let Some(prefix) = prefix else {
            return Vec::new();
        };
        if wanted.is_empty() {
            // A profile with no components pays nothing for the feature, including a network round trip.
            return Vec::new();
        }
        let Some(manifest) = self.launch_manifest(cancel, events).await else {
            return Vec::new();
        };
        match self.addons.registrations(&manifest, &prefix, &wanted) {
            Ok(addons) => addons,
            Err(err) => {
                let _ = events.send(Event::Error(CoreError::Addons(err)));
                Vec::new()
            }
        }
    }
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

impl AddonsBackend {
    /// The manifest to read a launch's companion registrations from: the hosted one, or the last one a
    /// fetch verified when it cannot be reached.
    ///
    /// The fallback is announced rather than silent, because starting yesterday's companions is the right
    /// answer and quietly doing it is not: which build of a companion started is exactly the thing
    /// somebody debugging one would need to know.
    async fn launch_manifest(
        &self,
        cancel: &CancellationToken,
        events: &UnboundedSender<Event>,
    ) -> Option<ComponentManifest> {
        match self
            .addons
            .fetch_manifest(&self.catalog.0, &self.catalog.1, cancel)
            .await
        {
            Ok(manifest) => Some(manifest),
            Err(fetch_error) => match self.addons.cached_manifest().await {
                Ok(Some(manifest)) => {
                    let _ = events.send(Event::Error(CoreError::Launch {
                        detail: format!(
                            "the component catalog could not be reached ({fetch_error}); using the last one fetched"
                        ),
                    }));
                    Some(manifest)
                }
                // Neither reachable nor usable: the launch goes ahead without the companions the profile
                // enabled, and says so, because a game that starts beats one that does not.
                other => {
                    let cache = match other {
                        Err(err) => format!("the cached one is unusable: {err}"),
                        _ => "nothing has been fetched yet".to_owned(),
                    };
                    let _ = events.send(Event::Error(CoreError::Launch {
                        detail: format!(
                            "no component catalog is available ({fetch_error}; {cache}); this launch starts none of the enabled components"
                        ),
                    }));
                    None
                }
            },
        }
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
    /// Run the teardown, then let the relay finish and wait for it, so the last companion event is
    /// delivered before the flow says the launch is over.
    ///
    /// The sender is moved out and dropped here rather than cloned. The relay ends when the channel
    /// closes, and the channel closes only when the last sender is gone, so holding a second one
    /// across the await would wait forever.
    async fn finish<F>(mut self, teardown: F) -> Vec<CoreError>
    where
        F: AsyncFnOnce(AddonSession, &AddonEvents) -> AddonReport,
    {
        let events = self.addon_events.take().unwrap_or_else(AddonEvents::none);
        let report = match self.session.take() {
            Some(session) => teardown(session, &events).await,
            None => AddonReport::default(),
        };
        let failures = failures(&report);
        drop(events);
        let _ = self.relay.await;
        failures
    }
}

#[async_trait]
impl AddonLifecycle for RunningAddons {
    fn has_work(&self) -> bool {
        self.session.as_ref().is_some_and(AddonSession::has_work)
    }

    async fn game_closed(self: Box<Self>, _cancel: &CancellationToken) -> Vec<CoreError> {
        (*self)
            .finish(async |session, events| session.game_closed(events).await)
            .await
    }

    async fn abandon(self: Box<Self>, _cancel: &CancellationToken) -> Vec<CoreError> {
        (*self)
            .finish(async |session, events| session.abandon(events).await)
            .await
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

/// The same, for the component-install stream.
fn relay_components(events: &UnboundedSender<Event>) -> (ComponentEvents, JoinHandle<()>) {
    let (tx, mut rx) = mpsc::unbounded_channel();
    let events = events.clone();
    let handle = tokio::spawn(async move {
        while let Some(event) = rx.recv().await {
            let _ = events.send(Event::Component(event));
        }
    });
    (ComponentEvents::new(tx), handle)
}

#[cfg(test)]
mod tests {
    use super::*;
    use apogee_addons::{AddonPaths, Addons};
    use apogee_runtime::{Runtime, RuntimePaths};

    fn backend() -> Result<AddonsBackend, Box<dyn std::error::Error>> {
        let fetcher = apogee_fetch::Fetcher::builder().build()?;
        let runtime = Runtime::new(fetcher.clone(), RuntimePaths::default());
        Ok(AddonsBackend::new(
            Addons::new(runtime, fetcher, AddonPaths::default()),
            // Never reached: these tests configure no components, and the launch path skips the catalog
            // entirely when a profile wants none.
            (
                Url::parse("https://example.invalid/manifest.json")?,
                Url::parse("https://example.invalid/manifest.json.sig")?,
            ),
        ))
    }

    /// The teardown waits for the event relay so no companion event lands after the launch is
    /// reported over. It must not wait forever: the relay ends when the channel closes, and the
    /// channel closes only when the last sender is gone, so a sender held across the await is a
    /// deadlock that no amount of waiting resolves.
    #[tokio::test]
    async fn the_teardown_finishes_when_no_companion_was_configured()
    -> Result<(), Box<dyn std::error::Error>> {
        let backend = backend()?;
        let (tx, _rx) = mpsc::unbounded_channel();
        let cancel = CancellationToken::new();

        let lifecycle = backend
            .start(
                std::process::id().cast_signed(),
                None,
                Vec::new(),
                &cancel,
                &tx,
            )
            .await;

        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            lifecycle.game_closed(&cancel),
        )
        .await
        .map_err(|_| "the teardown never finished")?;
        Ok(())
    }

    /// The same for the path a cancelled launch takes.
    #[tokio::test]
    async fn abandoning_finishes_too() -> Result<(), Box<dyn std::error::Error>> {
        let backend = backend()?;
        let (tx, _rx) = mpsc::unbounded_channel();
        let cancel = CancellationToken::new();

        let lifecycle = backend
            .start(
                std::process::id().cast_signed(),
                None,
                Vec::new(),
                &cancel,
                &tx,
            )
            .await;

        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            lifecycle.abandon(&cancel),
        )
        .await
        .map_err(|_| "the teardown never finished")?;
        Ok(())
    }
}

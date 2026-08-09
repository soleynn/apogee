//! The real seam over `apogee-addons`.
//!
//! Owns the addon event channel and the task that relays it onto the core stream. The teardown
//! awaits that task before returning, so no companion event can arrive after the flow has said the
//! launch is over.

use apogee_addons::{
    AddonEvents, AddonReport, AddonSession, Addons, ComponentManifest, DalamudConfig,
    ExternalAddon, GameContext, Injectable, LoadEvidence, Outcome, SetupEvent, SetupEvents,
};
use std::time::SystemTime;

use apogee_runtime::{LaunchPlan, Prefix};
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
}

impl AddonsBackend {
    pub(crate) fn new(addons: Addons) -> Self {
        Self { addons }
    }

    /// Where the signed component catalog lives, resolved when it is needed rather than at construction.
    ///
    /// Resolving it eagerly would make an unparseable override fail the whole launcher, including every
    /// command that never touches a prefix. A misconfigured catalog should cost the prefix setup.
    fn catalog_urls(&self) -> Result<(Url, Url), CoreError> {
        super::catalog_urls()
    }
}

#[async_trait]
impl AddonBackend for AddonsBackend {
    async fn prepare_launch(
        &self,
        prefix: Option<Prefix>,
        dalamud: Option<DalamudConfig>,
        plan: &mut LaunchPlan,
        cancel: &CancellationToken,
        events: &UnboundedSender<Event>,
    ) -> Option<LoadEvidence> {
        let prefix = prefix?;
        let (setup, relay) = relay_setup(events);
        let Some(manifest) = self.setup_pass(&prefix, cancel, &setup).await.manifest else {
            finish(setup, relay).await;
            return None;
        };

        let confirming = match dalamud {
            Some(config) => {
                self.inject(&manifest, &prefix, config, plan, cancel, &setup)
                    .await
            }
            None => None,
        };
        finish(setup, relay).await;
        confirming
    }

    async fn apply_setup(
        &self,
        prefix: Option<Prefix>,
        cancel: &CancellationToken,
        events: &UnboundedSender<Event>,
    ) -> Option<Vec<String>> {
        let prefix = prefix?;
        let (setup, relay) = relay_setup(events);
        let left = self.setup_pass(&prefix, cancel, &setup).await.still_missing;
        finish(setup, relay).await;
        left
    }

    async fn missing_setup(
        &self,
        prefix: Option<Prefix>,
        cancel: &CancellationToken,
        events: &UnboundedSender<Event>,
    ) -> Option<Vec<String>> {
        let prefix = prefix?;
        let (setup, relay) = relay_setup(events);
        let manifest = self.catalog_manifest(cancel, &setup).await;
        let missing = manifest.and_then(|manifest| {
            self.addons
                .missing_setup(&manifest, &prefix)
                // The prefix's own record is unreadable, which is the same refusal an apply makes over
                // it: with no record there is no telling setup that is needed from setup that is not,
                // and answering "none" would be inventing the half that could not be read.
                .inspect_err(|err| {
                    tracing::warn!(
                        reason = err.chain(),
                        "what the prefix is missing is unknown"
                    );
                })
                .ok()
        });
        finish(setup, relay).await;
        missing
    }

    async fn start(
        &self,
        game_pid: i32,
        prefix: Option<Prefix>,
        addons: Vec<ExternalAddon>,
        confirming: Option<LoadEvidence>,
        _cancel: &CancellationToken,
        events: &UnboundedSender<Event>,
    ) -> Box<dyn AddonLifecycle> {
        let (addon_events, relay) = relay(events);
        // Spawned rather than awaited: the proof lands seconds after the game does, and a launch that
        // waited for it would hold the flow at the point it is supposed to report the game running.
        let confirming = confirming.map(|evidence| {
            let events = addon_events.clone();
            tokio::spawn(evidence.watch(events))
        });
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
            confirming,
            relay,
        })
    }
}

/// What one setup pass leaves behind.
#[derive(Default)]
struct SetupPass {
    /// The catalog the pass read, so a launch that needs the row for what it loads into the game does
    /// not fetch and re-verify the same signed file twice, and cannot get a different answer the
    /// second time.
    manifest: Option<ComponentManifest>,
    /// The verbs the pass did not leave the prefix with, or `None` when it could not tell.
    still_missing: Option<Vec<String>>,
}

impl AddonsBackend {
    /// Apply what the catalog publishes to `prefix`.
    async fn setup_pass(
        &self,
        prefix: &Prefix,
        cancel: &CancellationToken,
        setup: &SetupEvents,
    ) -> SetupPass {
        let Some(manifest) = self.catalog_manifest(cancel, setup).await else {
            return SetupPass::default();
        };
        let still_missing = match self
            .addons
            .apply_setup(&manifest, prefix, cancel, setup)
            .await
        {
            Ok(report) => {
                tracing::debug!(applied = report.present().len(), "prefix setup complete");
                // What the pass just did, rather than a second reading of the prefix: this pass
                // applied every verb the prefix was missing, so the ones it reports as failed are
                // exactly the ones still missing, and nothing else has touched the prefix since.
                Some(report.failed().into_iter().map(str::to_owned).collect())
            }
            // Each verb that failed is already on the stream as the event that failed it, so a whole-call
            // failure here is the prefix record being unreadable or the run being stopped. Neither is
            // worth failing a launch over: the setup is hygiene, and a stopped run is about to be torn
            // down anyway. Neither leaves anything to claim about what the prefix now has.
            Err(err) => {
                tracing::warn!(reason = err.chain(), "the prefix setup did not complete");
                None
            }
        };
        SetupPass {
            manifest: Some(manifest),
            still_missing,
        }
    }

    /// Install whatever this launch loads into the game, let it compose the launch, and come back with
    /// the proof to watch for if it left one.
    ///
    /// Failures are narrated by the addon layer as they happen and dropped here. Turning one into an
    /// [`Event::Error`] would make a shell exit non-zero for a game that started perfectly well without
    /// its companion, which is exactly the report a best-effort tier exists to avoid.
    async fn inject(
        &self,
        manifest: &ComponentManifest,
        prefix: &Prefix,
        config: DalamudConfig,
        plan: &mut LaunchPlan,
        cancel: &CancellationToken,
        setup: &SetupEvents,
    ) -> Option<LoadEvidence> {
        // The layer narrates its own `None`: which row is missing and what that costs is its sentence
        // to write, and a shell that had to invent one would be writing about a decision it did not make.
        let dalamud = self.addons.dalamud(manifest, config, setup)?;
        let enabled: [&dyn Injectable; 1] = [&dalamud];
        for err in self
            .addons
            .ensure_injectables(&enabled, prefix, cancel, setup)
            .await
        {
            tracing::warn!(reason = err.chain(), "an injectable could not be installed");
        }
        let prepared = self.addons.prepare_launch(&enabled, plan, setup);
        for err in &prepared.failures {
            tracing::warn!(
                reason = err.chain(),
                "an injectable could not join the launch"
            );
        }
        // Asked of the companion that took the launch over, and asked now: it is dropped at the end of
        // this pass, and the moment is read before the spawn because the proof lands seconds from now
        // in a file that survives previous sessions. A moment from before this launch started is what
        // tells this session's proof from the last one's.
        let redirected_by = prepared.redirected_by?;
        enabled
            .iter()
            .find(|injectable| injectable.name() == redirected_by)?
            .load_evidence(SystemTime::now())
    }

    /// The manifest to read a prefix's setup from: the hosted one, or the last one a fetch verified
    /// when it cannot be reached.
    ///
    /// Announced rather than silent, because which rows a launch applied is exactly what somebody
    /// debugging one needs to know. Announced as a *report* rather than an error, because falling back to
    /// a catalog that once verified is the correct outcome here, and a shell that turned it into a failed
    /// exit would report a game that started fine as a failure.
    async fn catalog_manifest(
        &self,
        cancel: &CancellationToken,
        setup: &SetupEvents,
    ) -> Option<ComponentManifest> {
        let fetch_error = match self.catalog_urls() {
            Ok((manifest_url, signature_url)) => match self
                .addons
                .fetch_manifest(&manifest_url, &signature_url, cancel)
                .await
            {
                Ok(manifest) => return Some(manifest),
                // The chain, not the outer sentence: the reason a catalog could not be reached is
                // always in the cause, and this string is the only thing anybody debugging one sees.
                Err(err) => err.chain(),
            },
            Err(err) => err.to_string(),
        };
        let (manifest, detail) = match self.addons.cached_manifest().await {
            Ok(Some(manifest)) => (Some(manifest), fetch_error),
            // Neither reachable nor usable: the launch goes ahead with no prefix setup applied, and says
            // so, because a game that starts beats one that does not.
            Ok(None) => (None, format!("{fetch_error}; nothing was cached")),
            Err(cache_error) => (
                None,
                format!(
                    "{fetch_error}; the cached one is unusable: {}",
                    cache_error.chain()
                ),
            ),
        };
        setup.emit(SetupEvent::CatalogUnavailable {
            detail,
            using_cached: manifest.is_some(),
        });
        manifest
    }
}

/// Drop the sender and wait for its relay, so the last setup event is delivered before the caller moves
/// on. The relay ends when the channel closes, and the channel closes only when the last sender is gone.
async fn finish(setup: SetupEvents, relay: JoinHandle<()>) {
    drop(setup);
    let _ = relay.await;
}

/// One launch's running companions, and the relay feeding their events onto the core stream.
struct RunningAddons {
    session: Option<AddonSession>,
    /// Dropped before the relay is awaited, which is what lets the relay task finish.
    addon_events: Option<AddonEvents>,
    /// The wait for proof the redirected launch came up, if there was one to watch for.
    confirming: Option<JoinHandle<()>>,
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
        // Stopped first, and waited for, because it holds a sender. The relay below ends only when the
        // last sender is gone, so a watch still polling would hold the teardown open for the rest of
        // its window: a user who quits a minute in would sit looking at a launcher that had nothing
        // left to do. Stopping it also *is* the right answer rather than a concession, since what it
        // would report is only worth knowing while the session is still running.
        if let Some(confirming) = self.confirming.take() {
            confirming.abort();
            let _ = confirming.await;
        }
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

/// The same, for the prefix-setup stream.
fn relay_setup(events: &UnboundedSender<Event>) -> (SetupEvents, JoinHandle<()>) {
    let (tx, mut rx) = mpsc::unbounded_channel();
    let events = events.clone();
    let handle = tokio::spawn(async move {
        while let Some(event) = rx.recv().await {
            let _ = events.send(Event::Setup(event));
        }
    });
    (SetupEvents::new(tx), handle)
}

#[cfg(test)]
mod tests {
    use super::*;
    use apogee_addons::{AddonPaths, Addons};
    use apogee_runtime::{Runtime, RuntimePaths};

    fn backend() -> Result<AddonsBackend, Box<dyn std::error::Error>> {
        let fetcher = apogee_fetch::Fetcher::builder().build()?;
        let runtime = Runtime::new(fetcher.clone(), RuntimePaths::default());
        // No catalog is reached: these tests hand over no prefix, and the launch path stops there.
        Ok(AddonsBackend::new(Addons::new(
            runtime,
            fetcher,
            AddonPaths::default(),
        )))
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
                None,
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

    /// And the same when a launch is waiting for proof its companion came up.
    ///
    /// That wait holds a sender, and its window is a minute and a half of a session a user may quit
    /// twenty seconds into. Left running it would hold the channel open, the relay would never end,
    /// and the teardown would sit there: the launcher would look hung for the rest of the window with
    /// nothing left to do. The wait is stopped rather than waited out, which is also the honest
    /// answer, since what it would report is only worth knowing while the session is still running.
    #[tokio::test]
    async fn the_teardown_does_not_wait_out_a_confirmation_that_will_never_land()
    -> Result<(), Box<dyn std::error::Error>> {
        let backend = backend()?;
        let (tx, _rx) = mpsc::unbounded_channel();
        let cancel = CancellationToken::new();

        // A launch something redirected, watching a file nothing will ever write.
        let evidence = LoadEvidence::new(
            "Companion",
            std::path::Path::new("/nonexistent/never-written.log"),
            SystemTime::now(),
        );
        let lifecycle = backend
            .start(
                std::process::id().cast_signed(),
                None,
                Vec::new(),
                Some(evidence),
                &cancel,
                &tx,
            )
            .await;

        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            lifecycle.game_closed(&cancel),
        )
        .await
        .map_err(|_| "the teardown waited for the confirmation window")?;
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
                None,
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

    /// A launch with no prefix has nothing to set up, and must not reach the catalog to discover that.
    /// This is the shape a test double hands back, and the shape a Windows launch will.
    #[tokio::test]
    async fn a_launch_with_no_prefix_prepares_nothing() -> Result<(), Box<dyn std::error::Error>> {
        use std::collections::BTreeMap;

        let backend = backend()?;
        let (tx, _rx) = mpsc::unbounded_channel();
        let mut plan = LaunchPlan::new("ffxiv_dx11.exe", "", BTreeMap::new());

        let confirming = backend
            .prepare_launch(
                None,
                Some(DalamudConfig::default()),
                &mut plan,
                &CancellationToken::new(),
                &tx,
            )
            .await;

        assert!(
            confirming.is_none(),
            "nothing composed this launch, so there is nothing to confirm"
        );
        assert!(plan.inserted_args().is_empty());
        assert_eq!(plan.program(), "ffxiv_dx11.exe");
        Ok(())
    }
}

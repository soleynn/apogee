//! The real seam over `apogee-addons`.
//!
//! Owns the addon event channel and the task that relays it onto the core stream. The teardown
//! awaits that task before returning, so no companion event can arrive after the flow has said the
//! launch is over.

use apogee_addons::{
    AddonError, AddonEvents, AddonReport, AddonSession, Addons, DalamudConfig, ExternalAddon,
    GameContext, Injectable, LoadEvidence, Outcome, RunIn, SetupEvent, SetupEvents,
    VerifiedManifest,
};
use std::collections::BTreeMap;
use std::time::SystemTime;

use apogee_runtime::{LaunchPlan, Prefix};
use async_trait::async_trait;
use tokio::sync::mpsc::{self, UnboundedSender};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use url::Url;

use super::{AddonBackend, AddonLifecycle, GatedPrograms, LaunchPrograms, PreparedAddons};
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
        request: LaunchPrograms,
        plan: &mut LaunchPlan,
        cancel: &CancellationToken,
        events: &UnboundedSender<Event>,
    ) -> PreparedAddons {
        let Some(prefix) = prefix else {
            return PreparedAddons::default();
        };
        let (setup, relay) = relay_setup(events);
        let Some(manifest) = self
            .setup_pass(&prefix, &request.programs, cancel, &setup)
            .await
            .manifest
        else {
            finish(setup, relay).await;
            return PreparedAddons::default();
        };

        let confirming = match request.dalamud {
            Some(config) => {
                self.inject(&manifest, &prefix, config, plan, cancel, &setup)
                    .await
            }
            None => None,
        };
        let programs = if request.programs.is_empty() {
            GatedPrograms::default()
        } else {
            self.gate(
                manifest,
                prefix,
                request.programs,
                request.game_version,
                &setup,
            )
            .await
        };
        finish(setup, relay).await;
        PreparedAddons {
            confirming,
            programs,
        }
    }

    async fn apply_setup(
        &self,
        prefix: Option<Prefix>,
        programs: &[String],
        cancel: &CancellationToken,
        events: &UnboundedSender<Event>,
    ) -> Option<Vec<String>> {
        let prefix = prefix?;
        let (setup, relay) = relay_setup(events);
        let left = self
            .setup_pass(&prefix, programs, cancel, &setup)
            .await
            .still_missing;
        finish(setup, relay).await;
        left
    }

    async fn missing_setup(
        &self,
        prefix: Option<Prefix>,
        programs: &[String],
        cancel: &CancellationToken,
        events: &UnboundedSender<Event>,
    ) -> Option<Vec<String>> {
        let prefix = prefix?;
        let (setup, relay) = relay_setup(events);
        let manifest = self.catalog_manifest(cancel, &setup).await;
        let missing = manifest.and_then(|manifest| {
            let names: Vec<&str> = programs.iter().map(String::as_str).collect();
            let missing = if names.is_empty() {
                self.addons.missing_setup(&manifest, &prefix)
            } else {
                self.addons.missing_setup_for(&manifest, &prefix, &names)
            };
            missing
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
        shared_env: BTreeMap<String, String>,
        programs: GatedPrograms,
        addons: Vec<ExternalAddon>,
        confirming: Option<LoadEvidence>,
        cancel: &CancellationToken,
        events: &UnboundedSender<Event>,
    ) -> Box<dyn AddonLifecycle> {
        let (addon_events, relay) = relay(events);
        // A pid the runtime reported cannot be zero or negative, but building the context is
        // fallible, and a launch is not worth failing over a helper: an unusable context simply
        // means no companion runs.
        let game = match &prefix {
            Some(prefix) => GameContext::in_prefix(game_pid, prefix),
            None => GameContext::new(game_pid),
        }
        .map(|game| game.with_launch_env(shared_env));
        let mut watches = Vec::new();
        let session = match game {
            Ok(game) => {
                let (plan, program_evidence) = programs.into_parts();
                // Built from the game's own context, never from a fresh prefix handle, so a program
                // can only be started into the session the game is running in.
                let mut list = match plan.map(|plan| plan.companions(&game)) {
                    Some(Ok(list)) => list,
                    Some(Err(err)) => {
                        report_program_failure(events, &err);
                        Vec::new()
                    }
                    None => Vec::new(),
                };
                let curated = list.len();
                // Ahead of the user's own tools: a tool pointed at one of these expects it up.
                list.extend(addons);
                let session = self
                    .addons
                    .start_external(&list, &game, &addon_events)
                    .await;
                let mut evidence: Vec<LoadEvidence> = confirming.into_iter().collect();
                if all_started(&session, curated) {
                    evidence.extend(program_evidence);
                } else if !program_evidence.is_empty() {
                    // Something at a curated program's path was already running, or did not start.
                    // Its proof would be proof of something this launch did not start, and the
                    // evidence cannot be told apart per program from here, so none is watched.
                    tracing::info!(
                        "a curated program was not started by this launch, so its proof is not watched"
                    );
                }
                watches.extend(evidence.into_iter().map(|evidence| {
                    // Spawned rather than awaited: the proof lands seconds after the game does, and a
                    // launch that waited for it would hold the flow at the point it is supposed to
                    // report the game running. The token ends it on the path where the launch is
                    // stopped; the teardown ends it on the path where the game simply exited.
                    tokio::spawn(evidence.watch(cancel.clone(), addon_events.clone()))
                }));
                if list
                    .iter()
                    .any(|a| a.enabled() && a.run_in() == RunIn::Prefix)
                {
                    watches.push(self.shared_session_check(game, list, cancel, &addon_events));
                }
                Some(session)
            }
            Err(err) => {
                let _ = events.send(Event::Error(CoreError::Addons(err)));
                None
            }
        };
        Box::new(RunningAddons {
            session,
            addon_events: Some(addon_events),
            watches,
            relay,
        })
    }
}

/// How long after the companions start the shared-session check looks. A companion that missed the
/// game's session starts its own server as it comes up, which is not instant under a container
/// runtime, and a look taken before then would see one server and say nothing.
const SHARED_SESSION_DELAY: std::time::Duration = std::time::Duration::from_secs(15);

/// Whether every one of the first `curated` entries was started by this launch.
fn all_started(session: &AddonSession, curated: usize) -> bool {
    session
        .report()
        .outcomes
        .iter()
        .filter(|outcome| outcome.index < curated)
        .all(|outcome| matches!(outcome.outcome, Outcome::Started { .. }))
}

/// A curated program that could not be built into a companion, said on the setup stream under the
/// program's own name. Not an [`Event::Error`]: the game is running and is unaffected.
fn report_program_failure(events: &UnboundedSender<Event>, err: &AddonError) {
    tracing::warn!(
        reason = err.chain(),
        "curated programs could not be started"
    );
    let _ = events.send(Event::Setup(SetupEvent::Failed {
        what: match err {
            AddonError::ProgramPrefixMismatch { program, .. } => program.clone(),
            _ => "programs".to_owned(),
        },
        reason: err.chain(),
    }));
}

impl AddonsBackend {
    /// Check, a little after the companions start, that every one inside the prefix joined the
    /// game's wine session. Its findings are narrated by the addon layer on the companion stream.
    fn shared_session_check(
        &self,
        game: GameContext,
        started: Vec<ExternalAddon>,
        cancel: &CancellationToken,
        events: &AddonEvents,
    ) -> JoinHandle<()> {
        let addons = self.addons.clone();
        let cancel = cancel.clone();
        let events = events.clone();
        tokio::spawn(async move {
            tokio::select! {
                () = tokio::time::sleep(SHARED_SESSION_DELAY) => {}
                () = cancel.cancelled() => return,
            }
            for err in addons.check_shared_session(&game, &started, &events).await {
                tracing::warn!(
                    reason = err.chain(),
                    "a companion is not on the game's session"
                );
            }
        })
    }

    /// Gate the enabled programs against the prefix's own runner and this game version, off the
    /// async runtime because the gates hash every file a program placed.
    async fn gate(
        &self,
        manifest: VerifiedManifest,
        prefix: Prefix,
        programs: Vec<String>,
        game_version: String,
        setup: &SetupEvents,
    ) -> GatedPrograms {
        // Read the moment before the spawn: a program's proof is a file a previous session also
        // wrote, and only a write after this moment is this launch's.
        let since = SystemTime::now();
        let addons = self.addons.clone();
        let setup = setup.clone();
        let gated = tokio::task::spawn_blocking(move || {
            // The runner the prefix records, which is what each row was validated against; the handle
            // the launch holds is the fallback for a prefix with no record to read.
            let runner = match prefix.metadata() {
                Ok(Some(metadata)) => metadata.runner,
                _ => apogee_runtime::RunnerRef::from(prefix.runner()),
            };
            let names: Vec<&str> = programs.iter().map(String::as_str).collect();
            addons.program_gates(&manifest, &prefix, &names, &game_version, &runner, &setup)
        })
        .await;
        match gated {
            Ok(plan) => GatedPrograms::from_plan(plan, since),
            Err(err) => {
                tracing::warn!(error = %err, "the program gates did not finish");
                GatedPrograms::default()
            }
        }
    }
}

/// What one setup pass leaves behind.
#[derive(Default)]
struct SetupPass {
    /// The catalog the pass read, so a launch that needs the row for what it loads into the game does
    /// not fetch and re-verify the same signed file twice, and cannot get a different answer the
    /// second time.
    manifest: Option<VerifiedManifest>,
    /// The verbs the pass did not leave the prefix with, or `None` when it could not tell.
    still_missing: Option<Vec<String>>,
}

impl AddonsBackend {
    /// Apply what the catalog publishes to `prefix`.
    ///
    /// With curated `programs` turned on, their install steps run after the base verbs; with none,
    /// the pass is exactly the base setup, so a profile with every program off asks nothing new of
    /// the catalog.
    async fn setup_pass(
        &self,
        prefix: &Prefix,
        programs: &[String],
        cancel: &CancellationToken,
        setup: &SetupEvents,
    ) -> SetupPass {
        let Some(manifest) = self.catalog_manifest(cancel, setup).await else {
            return SetupPass::default();
        };
        let applied = if programs.is_empty() {
            self.addons
                .apply_setup(&manifest, prefix, cancel, setup)
                .await
        } else {
            let names: Vec<&str> = programs.iter().map(String::as_str).collect();
            self.addons
                .apply_setup_for(&manifest, prefix, &names, cancel, setup)
                .await
        };
        let still_missing = match applied {
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
        manifest: &VerifiedManifest,
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
    ) -> Option<VerifiedManifest> {
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
    /// The waits for proof that what was loaded or started came up, and the shared-session check:
    /// everything still watching the session on the side.
    watches: Vec<JoinHandle<()>>,
    relay: JoinHandle<()>,
}

impl RunningAddons {
    /// Run the teardown, then let the relay finish and wait for it, so the last companion event is
    /// delivered before the flow says the launch is over.
    ///
    /// The sender is moved out and dropped here rather than cloned. The relay ends when the channel
    /// closes, and the channel closes only when the last sender is gone, so holding a second one
    /// across the await would wait forever.
    async fn finish<F>(mut self, cancel: &CancellationToken, teardown: F) -> Vec<CoreError>
    where
        F: AsyncFnOnce(AddonSession, &CancellationToken, &AddonEvents) -> AddonReport,
    {
        // Stopped first, and waited for, because it holds a sender. The relay below ends only when the
        // last sender is gone, so a watch still polling would hold the teardown open for the rest of
        // its window: a user who quits a minute in would sit looking at a launcher that had nothing
        // left to do. Stopping it also *is* the right answer rather than a concession, since what it
        // would report is only worth knowing while the session is still running.
        for watch in std::mem::take(&mut self.watches) {
            watch.abort();
            let _ = watch.await;
        }
        let events = self.addon_events.take().unwrap_or_else(AddonEvents::none);
        let report = match self.session.take() {
            Some(session) => teardown(session, cancel, &events).await,
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

    async fn game_closed(self: Box<Self>, cancel: &CancellationToken) -> Vec<CoreError> {
        (*self)
            .finish(cancel, async |session, cancel, events| {
                session.game_closed(cancel, events).await
            })
            .await
    }

    async fn abandon(self: Box<Self>, cancel: &CancellationToken) -> Vec<CoreError> {
        (*self)
            .finish(cancel, async |session, cancel, events| {
                session.abandon(cancel, events).await
            })
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
            Outcome::Failed { reason, .. } => Some(CoreError::Addon {
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
                BTreeMap::new(),
                GatedPrograms::default(),
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
                BTreeMap::new(),
                GatedPrograms::default(),
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
                BTreeMap::new(),
                GatedPrograms::default(),
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
        let backend = backend()?;
        let (tx, _rx) = mpsc::unbounded_channel();
        let mut plan = LaunchPlan::new("ffxiv_dx11.exe", "", BTreeMap::new());

        let prepared = backend
            .prepare_launch(
                None,
                LaunchPrograms {
                    dalamud: Some(DalamudConfig::default()),
                    programs: vec!["act".to_owned()],
                    game_version: "2024.01.01.0000.0000".to_owned(),
                },
                &mut plan,
                &CancellationToken::new(),
                &tx,
            )
            .await;

        assert!(
            prepared.confirming.is_none(),
            "nothing composed this launch, so there is nothing to confirm"
        );
        assert!(
            !prepared.programs.any(),
            "nothing was gated without a prefix"
        );
        assert!(plan.inserted_args().is_empty());
        assert_eq!(plan.program(), "ffxiv_dx11.exe");
        Ok(())
    }
}

//! Run lifetime, cancellation, and forwarding from core streams to shell channels.

use std::collections::HashMap;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use apogee_core::{
    AddonEvent, Command, Core, Event, FirstRunRequest, FlowState, FrontierData, ImportData,
    ImportXivLauncher, PatchProgress, Repo, SetupEvent, StableCode, Uuid,
};
use tauri::ipc::Channel;
use tokio_stream::{Stream, StreamExt};
use tokio_util::sync::CancellationToken;

use crate::dto::{EventDto, EventWireDto};
use crate::navigation::NavigationState;

pub(crate) trait AssetRegistrar {
    fn allow_file(&self, path: &std::path::Path) -> Result<(), ()>;
}

impl AssetRegistrar for tauri::scope::fs::Scope {
    fn allow_file(&self, path: &std::path::Path) -> Result<(), ()> {
        tauri::scope::fs::Scope::allow_file(self, path).map_err(|error| {
            tracing::warn!(%error, path = %path.display(), "could not admit a validated banner asset");
        })
    }
}

pub(crate) trait Driver {
    fn execute_cancellable(
        &self,
        command: Command,
        cancel: CancellationToken,
    ) -> Pin<Box<dyn Stream<Item = Event> + Send + '_>>;
}

impl Driver for Core {
    fn execute_cancellable(
        &self,
        command: Command,
        cancel: CancellationToken,
    ) -> Pin<Box<dyn Stream<Item = Event> + Send + '_>> {
        Box::pin(Core::execute_cancellable(self, command, cancel))
    }
}

pub(crate) trait EventSink {
    fn send(&self, event: EventDto);
}

impl EventSink for Channel<EventWireDto> {
    fn send(&self, event: EventDto) {
        // Losing the receiver is not itself a cancellation request. Keep draining until core emits
        // its outcome; the lifecycle owner decides separately when a run should stop.
        let wire = match event {
            EventDto::Unknown { code } => EventWireDto::Unknown(crate::dto::UnknownEventDto {
                kind: "unknown".to_owned(),
                code: code.to_owned(),
            }),
            known => EventWireDto::Known(known),
        };
        let _ = Channel::send(self, wire);
    }
}

/// Drive exactly the command the request converted, forwarding every core frame in order.
pub(crate) async fn drive<D, S, A>(
    driver: &D,
    command: Command,
    cancel: CancellationToken,
    run_id: Uuid,
    navigation: &NavigationState,
    assets: &A,
    sink: &S,
) -> bool
where
    D: Driver + ?Sized,
    S: EventSink + ?Sized,
    A: AssetRegistrar + ?Sized,
{
    let mut events = driver.execute_cancellable(command, cancel);
    let mut pending = HashMap::new();
    let mut observed = 0_u64;
    let mut flush = tokio::time::interval(Duration::from_millis(100));
    let mut close_requested = false;
    flush.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    // An interval's first tick is immediate. Consume it so a progress frame gets one complete
    // coalescing window rather than depending on which branch `select!` happens to poll first.
    flush.tick().await;

    loop {
        tokio::select! {
            event = events.next() => {
                let Some(event) = event else { break };
                close_requested |= matches!(event, Event::State(FlowState::Detached));
                if let Some(key) = progress_key(&event) {
                    observed = observed.saturating_add(1);
                    pending.insert(key, (observed, event));
                } else {
                    flush_pending(&mut pending, sink);
                    sink.send(observe_event(&event, run_id, navigation, assets));
                }
            }
            _ = flush.tick() => flush_pending(&mut pending, sink),
        }
    }
    flush_pending(&mut pending, sink);
    close_requested
}

fn observe_event<A: AssetRegistrar + ?Sized>(
    event: &Event,
    run_id: Uuid,
    navigation: &NavigationState,
    assets: &A,
) -> EventDto {
    match event {
        Event::Addon(addon @ AddonEvent::NotConfirmed { evidence, .. }) => {
            let addon_id = navigation.register_evidence(run_id, evidence.clone());
            EventDto::Addon {
                code: event.code(),
                addon: crate::dto::AddonDto::from_observed(addon, Some(addon_id)),
            }
        }
        Event::Frontier(FrontierData::Banners(banners)) => {
            for artwork in banners
                .iter()
                .filter_map(|banner| banner.artwork.as_deref())
            {
                let _ = assets.allow_file(artwork);
            }
            EventDto::from(event)
        }
        Event::SupportBundle(bundle) => {
            navigation.set_pending_support_bundle(bundle.clone());
            EventDto::from(event)
        }
        Event::Import(import @ ImportData::Scan(scan)) => {
            let scan_id = navigation.register_import_scan(scan.clone());
            EventDto::Import {
                code: event.code(),
                import: crate::dto::ImportDto::from_observed(import, Some(scan_id)),
            }
        }
        Event::FirstRun(checkpoint) => {
            let snapshot = navigation.replace_first_run(checkpoint);
            EventDto::FirstRun {
                code: event.code(),
                first_run: Box::new(crate::dto::first_run::FirstRunDto::from_observed(
                    checkpoint,
                    Some(&snapshot),
                )),
            }
        }
        _ => EventDto::from(event),
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum ProgressKey {
    General,
    Patch { phase: u8, repo: String, index: u32 },
    Setup { what: String },
}

fn progress_key(event: &Event) -> Option<ProgressKey> {
    match event {
        Event::Progress(_) => Some(ProgressKey::General),
        Event::Patch(PatchProgress::Downloading { repo, index, .. }) => Some(ProgressKey::Patch {
            phase: 0,
            repo: repo_label(*repo),
            index: *index,
        }),
        Event::Patch(PatchProgress::Applying { repo, index, .. }) => Some(ProgressKey::Patch {
            phase: 1,
            repo: repo_label(*repo),
            index: *index,
        }),
        Event::Setup(SetupEvent::Downloading { what, .. }) => {
            Some(ProgressKey::Setup { what: what.clone() })
        }
        _ => None,
    }
}

fn repo_label(repo: Repo) -> String {
    match repo {
        Repo::Boot => "boot".to_owned(),
        Repo::Game => "game".to_owned(),
        Repo::Expansion(number) => format!("ex{number}"),
    }
}

fn flush_pending<S: EventSink + ?Sized>(
    pending: &mut HashMap<ProgressKey, (u64, Event)>,
    sink: &S,
) {
    let mut events: Vec<_> = pending.drain().map(|(_, event)| event).collect();
    events.sort_unstable_by_key(|(observed, _)| *observed);
    for (_, event) in events {
        sink.send(EventDto::from(&event));
    }
}

/// The cancellation tokens for runs the shell has started.
#[derive(Clone, Default)]
pub(crate) struct Runs {
    state: Arc<Mutex<RunState>>,
    changed: Arc<tokio::sync::Notify>,
}

#[derive(Default)]
struct RunState {
    active: HashMap<Uuid, ActiveRun>,
    direct_mutation: bool,
    draining: bool,
}

struct ActiveRun {
    cancel: CancellationToken,
    class: RunClass,
}

/// Flows without profile or checkpoint persistence may overlap; every writer owns one mutation slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RunClass {
    ReadOnly,
    Exclusive,
}

impl RunClass {
    pub(crate) fn for_command(command: &Command) -> Self {
        match command {
            Command::Frontier(_)
            | Command::SupportBundle { .. }
            | Command::Prefix {
                action: apogee_core::PrefixAction::Check,
                ..
            } => Self::ReadOnly,
            Command::FirstRun(FirstRunRequest::Read)
            | Command::ImportXivLauncher(ImportXivLauncher::Scan(_)) => Self::ReadOnly,
            _ => Self::Exclusive,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RunAdmissionError {
    Duplicate,
    Busy,
    Draining,
    Unavailable,
}

/// Ownership of a registered run. Dropping the lease unregisters it even when its task unwinds or
/// returns early, so one failed driver cannot strand the shell's exclusive slot.
pub(crate) struct RunLease {
    runs: Runs,
    id: Uuid,
    cancel: CancellationToken,
}

impl RunLease {
    pub(crate) fn cancellation(&self) -> CancellationToken {
        self.cancel.clone()
    }
}

impl Drop for RunLease {
    fn drop(&mut self) {
        let mut state = match self.runs.state.lock() {
            Ok(state) => state,
            Err(poisoned) => poisoned.into_inner(),
        };
        state.active.remove(&self.id);
        drop(state);
        self.runs.changed.notify_waiters();
    }
}

/// Ownership of the one direct-write slot shared with exclusive streamed runs.
pub(crate) struct MutationLease {
    runs: Runs,
}

impl Drop for MutationLease {
    fn drop(&mut self) {
        let mut state = match self.runs.state.lock() {
            Ok(state) => state,
            Err(poisoned) => poisoned.into_inner(),
        };
        state.direct_mutation = false;
        drop(state);
        self.runs.changed.notify_waiters();
    }
}

impl Runs {
    pub(crate) fn start(&self, id: Uuid, class: RunClass) -> Result<RunLease, RunAdmissionError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| RunAdmissionError::Unavailable)?;
        if state.draining {
            return Err(RunAdmissionError::Draining);
        }
        if state.active.contains_key(&id) {
            return Err(RunAdmissionError::Duplicate);
        }
        if class == RunClass::Exclusive
            && (state.direct_mutation
                || state
                    .active
                    .values()
                    .any(|run| run.class == RunClass::Exclusive))
        {
            return Err(RunAdmissionError::Busy);
        }
        let cancel = CancellationToken::new();
        state.active.insert(
            id,
            ActiveRun {
                cancel: cancel.clone(),
                class,
            },
        );
        Ok(RunLease {
            runs: self.clone(),
            id,
            cancel,
        })
    }

    pub(crate) fn start_mutation(&self) -> Result<MutationLease, RunAdmissionError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| RunAdmissionError::Unavailable)?;
        if state.draining {
            return Err(RunAdmissionError::Draining);
        }
        if state.direct_mutation
            || state
                .active
                .values()
                .any(|run| run.class == RunClass::Exclusive)
        {
            return Err(RunAdmissionError::Busy);
        }
        state.direct_mutation = true;
        Ok(MutationLease { runs: self.clone() })
    }

    pub(crate) fn cancel(&self, id: Uuid) -> Result<bool, ()> {
        let state = self.state.lock().map_err(|_| ())?;
        let Some(run) = state.active.get(&id) else {
            return Ok(false);
        };
        run.cancel.cancel();
        Ok(true)
    }

    /// Freeze admission when a close request finds work. The freeze is reversible until the person
    /// confirms; this closes the race where a new write could start after the cancellation snapshot.
    pub(crate) fn begin_close(&self) -> Result<bool, ()> {
        let mut state = self.state.lock().map_err(|_| ())?;
        if state.active.is_empty() && !state.direct_mutation {
            return Ok(false);
        }
        state.draining = true;
        Ok(true)
    }

    /// Resume normal admission after the close confirmation is declined.
    pub(crate) fn resume(&self) -> Result<(), ()> {
        let mut state = self.state.lock().map_err(|_| ())?;
        state.draining = false;
        drop(state);
        self.changed.notify_waiters();
        Ok(())
    }

    /// Cancel every streamed flow while leaving direct blocking mutations to finish normally.
    pub(crate) fn cancel_all(&self) -> Result<usize, ()> {
        let tokens = {
            let mut state = self.state.lock().map_err(|_| ())?;
            state.draining = true;
            state
                .active
                .values()
                .map(|run| run.cancel.clone())
                .collect::<Vec<_>>()
        };
        for token in &tokens {
            token.cancel();
        }
        Ok(tokens.len())
    }

    /// Wait until every streamed lease and the direct-mutation lease have been released.
    pub(crate) async fn wait_empty(&self) -> Result<(), ()> {
        loop {
            let changed = self.changed.notified();
            let empty = {
                let state = self.state.lock().map_err(|_| ())?;
                state.active.is_empty() && !state.direct_mutation
            };
            if empty {
                return Ok(());
            }
            changed.await;
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, Ordering};

    use apogee_core::{BannerData, FlowState, FrontierData, OtpSource, PasswordSource, RunOutcome};

    use super::*;
    use crate::command::{CommandDto, OtpSourceDto, PasswordSourceDto};
    use crate::dto::secrets::SecretBytes;
    use crate::dto::{OutcomeDto, StateDto};

    struct ScriptedDriver {
        profile: Uuid,
        drove_patch_and_play: AtomicBool,
    }

    impl Driver for ScriptedDriver {
        fn execute_cancellable(
            &self,
            command: Command,
            _cancel: CancellationToken,
        ) -> Pin<Box<dyn Stream<Item = Event> + Send + '_>> {
            match command {
                Command::PatchAndPlay {
                    profile,
                    password: PasswordSource::Provided(_),
                    otp: OtpSource::Totp,
                } if profile == self.profile => {
                    self.drove_patch_and_play.store(true, Ordering::SeqCst);
                }
                _ => return Box::pin(tokio_stream::empty()),
            }
            Box::pin(tokio_stream::iter([
                Event::State(FlowState::Running),
                Event::Outcome(RunOutcome::Succeeded),
            ]))
        }
    }

    #[derive(Default)]
    struct VecSink(Mutex<Vec<EventDto>>);

    struct NoAssets;

    impl AssetRegistrar for NoAssets {
        fn allow_file(&self, _path: &std::path::Path) -> Result<(), ()> {
            Ok(())
        }
    }

    #[derive(Default)]
    struct RecordingAssets(Mutex<Vec<std::path::PathBuf>>);

    impl AssetRegistrar for RecordingAssets {
        fn allow_file(&self, path: &std::path::Path) -> Result<(), ()> {
            match self.0.lock() {
                Ok(mut paths) => paths.push(path.to_path_buf()),
                Err(poisoned) => poisoned.into_inner().push(path.to_path_buf()),
            }
            Ok(())
        }
    }

    #[test]
    fn observation_confines_banner_and_evidence_paths_before_serialization() {
        let run = Uuid::new_v4();
        let navigation = NavigationState::default();
        let assets = RecordingAssets::default();
        let artwork = std::path::PathBuf::from("/validated/banners/banner.png");
        let evidence = std::path::PathBuf::from("/private/evidence/loaded.txt");

        let banner = observe_event(
            &Event::Frontier(FrontierData::Banners(vec![BannerData {
                artwork: Some(artwork.clone()),
                ..BannerData::default()
            }])),
            run,
            &navigation,
            &assets,
        );
        assert!(matches!(banner, EventDto::Frontier { .. }));
        let admitted = match assets.0.lock() {
            Ok(paths) => paths.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        };
        assert_eq!(admitted, vec![artwork]);

        let addon_id = navigation.register_evidence(run, evidence.clone());
        let addon = EventDto::Addon {
            code: "addon.not-confirmed",
            addon: crate::dto::AddonDto::NotConfirmed {
                what: "Dalamud".to_owned(),
                waited_seconds: 10,
                addon: addon_id,
            },
        };
        assert!(matches!(
            &addon,
            EventDto::Addon {
                addon: crate::dto::AddonDto::NotConfirmed { addon, .. },
                ..
            } if *addon != Uuid::nil()
        ));
        let json = serde_json::to_string(&addon).unwrap_or_default();
        assert!(!json.contains(&evidence.to_string_lossy().into_owned()));
        assert!(!json.contains("evidence"));
    }

    #[test]
    fn observation_mints_process_local_first_run_candidate_ids() {
        let navigation = NavigationState::default();
        let import_path = std::path::PathBuf::from("private/import");
        let game_path = std::path::PathBuf::from("private/game");
        let checkpoint = apogee_core::FirstRunCheckpoint {
            import: apogee_core::ImportState::Candidates(vec![
                apogee_core::FirstRunImportCandidate {
                    path: import_path.clone(),
                    source: apogee_core::FirstRunImportSource::Core,
                },
            ]),
            game_candidates: vec![apogee_core::GameCandidate {
                path: game_path.clone(),
                state: apogee_core::GameCandidateState::Current {
                    installed_bytes: 42,
                },
            }],
            ..apogee_core::FirstRunCheckpoint::default()
        };

        let event = observe_event(
            &Event::FirstRun(Box::new(checkpoint)),
            Uuid::new_v4(),
            &navigation,
            &NoAssets,
        );
        let json = serde_json::to_value(event).unwrap_or_default();
        let import_id = json["firstRun"]["import"]["value"][0]["id"]
            .as_str()
            .and_then(|value| Uuid::parse_str(value).ok())
            .expect("opaque import candidate id");
        let game_id = json["firstRun"]["gameCandidates"][0]["id"]
            .as_str()
            .and_then(|value| Uuid::parse_str(value).ok())
            .expect("opaque game candidate id");

        assert!(matches!(
            navigation.first_run_import(import_id),
            Some(apogee_core::ImportDecision::Import(path)) if path == import_path
        ));
        assert!(matches!(
            navigation.first_run_game(game_id),
            Some(apogee_core::GameChoice::Existing { path, .. }) if path == game_path
        ));
        assert!(
            NavigationState::default()
                .first_run_import(import_id)
                .is_none()
        );
        assert!(NavigationState::default().first_run_game(game_id).is_none());

        let next_import_path = std::path::PathBuf::from("private/import-next");
        let next_game_path = std::path::PathBuf::from("private/game-next");
        let next_checkpoint = apogee_core::FirstRunCheckpoint {
            import: apogee_core::ImportState::Candidates(vec![
                apogee_core::FirstRunImportCandidate {
                    path: next_import_path.clone(),
                    source: apogee_core::FirstRunImportSource::Native,
                },
            ]),
            game_candidates: vec![apogee_core::GameCandidate {
                path: next_game_path.clone(),
                state: apogee_core::GameCandidateState::Current {
                    installed_bytes: 84,
                },
            }],
            ..apogee_core::FirstRunCheckpoint::default()
        };
        let next_event = observe_event(
            &Event::FirstRun(Box::new(next_checkpoint)),
            Uuid::new_v4(),
            &navigation,
            &NoAssets,
        );
        let next_json = serde_json::to_value(next_event).unwrap_or_default();
        let next_import_id = next_json["firstRun"]["import"]["value"][0]["id"]
            .as_str()
            .and_then(|value| Uuid::parse_str(value).ok())
            .expect("replacement import candidate id");
        let next_game_id = next_json["firstRun"]["gameCandidates"][0]["id"]
            .as_str()
            .and_then(|value| Uuid::parse_str(value).ok())
            .expect("replacement game candidate id");

        assert_eq!(navigation.first_run_capability_counts(), (1, 1));
        assert!(navigation.first_run_import(import_id).is_none());
        assert!(navigation.first_run_game(game_id).is_none());
        assert!(matches!(
            navigation.first_run_import(next_import_id),
            Some(apogee_core::ImportDecision::Import(path)) if path == next_import_path
        ));
        assert!(matches!(
            navigation.first_run_game(next_game_id),
            Some(apogee_core::GameChoice::Existing { path, .. }) if path == next_game_path
        ));
    }

    impl EventSink for VecSink {
        fn send(&self, event: EventDto) {
            if let Ok(mut events) = self.0.lock() {
                events.push(event);
            }
        }
    }

    #[tokio::test]
    async fn the_shell_constructs_and_drives_patch_and_play_to_core_outcome() {
        let profile = Uuid::new_v4();
        let driver = ScriptedDriver {
            profile,
            drove_patch_and_play: AtomicBool::new(false),
        };
        let sink = VecSink::default();
        let navigation = NavigationState::default();
        let request = CommandDto::PatchAndPlay {
            profile,
            password: PasswordSourceDto::Provided(SecretBytes::new(b"password".to_vec())),
            otp: OtpSourceDto::Totp,
        };

        drive(
            &driver,
            request
                .into_core(&navigation, &crate::render::RenderMonitor::disabled())
                .unwrap_or(Command::Launch { profile }),
            CancellationToken::new(),
            Uuid::new_v4(),
            &navigation,
            &NoAssets,
            &sink,
        )
        .await;

        assert!(driver.drove_patch_and_play.load(Ordering::SeqCst));
        let events = match sink.0.lock() {
            Ok(events) => events,
            Err(poisoned) => poisoned.into_inner(),
        };
        assert!(matches!(
            events.as_slice(),
            [
                EventDto::State {
                    state: StateDto::Running,
                    ..
                },
                EventDto::Outcome {
                    outcome: OutcomeDto::Succeeded,
                    ..
                }
            ]
        ));
    }

    struct DetachedLaunch;

    impl Driver for DetachedLaunch {
        fn execute_cancellable(
            &self,
            _command: Command,
            _cancel: CancellationToken,
        ) -> Pin<Box<dyn Stream<Item = Event> + Send + '_>> {
            Box::pin(tokio_stream::iter([
                Event::State(FlowState::Running),
                Event::State(FlowState::Detached),
                Event::Outcome(RunOutcome::Succeeded),
            ]))
        }
    }

    #[tokio::test]
    async fn detached_launch_requests_shell_close_after_forwarding_the_outcome() {
        let sink = VecSink::default();
        let close = drive(
            &DetachedLaunch,
            Command::Launch {
                profile: Uuid::nil(),
            },
            CancellationToken::new(),
            Uuid::new_v4(),
            &NavigationState::default(),
            &NoAssets,
            &sink,
        )
        .await;

        assert!(close);
        let events = match sink.0.lock() {
            Ok(events) => events,
            Err(poisoned) => poisoned.into_inner(),
        };
        assert!(matches!(
            events.as_slice(),
            [
                EventDto::State {
                    state: StateDto::Running,
                    ..
                },
                EventDto::State {
                    state: StateDto::Detached,
                    ..
                },
                EventDto::Outcome {
                    outcome: OutcomeDto::Succeeded,
                    ..
                }
            ]
        ));
    }

    struct ProgressBurst;

    impl Driver for ProgressBurst {
        fn execute_cancellable(
            &self,
            _command: Command,
            _cancel: CancellationToken,
        ) -> Pin<Box<dyn Stream<Item = Event> + Send + '_>> {
            let progress = (0..100_000).map(|bytes_done| {
                Event::Patch(PatchProgress::Applying {
                    repo: Repo::Game,
                    index: 7,
                    bytes_done,
                })
            });
            Box::pin(tokio_stream::iter(
                progress.chain(std::iter::once(Event::Outcome(RunOutcome::Succeeded))),
            ))
        }
    }

    #[tokio::test(start_paused = true)]
    async fn progress_is_coalesced_before_the_channel_and_outcome_stays_last() {
        let sink = VecSink::default();
        drive(
            &ProgressBurst,
            Command::Launch {
                profile: Uuid::nil(),
            },
            CancellationToken::new(),
            Uuid::new_v4(),
            &NavigationState::default(),
            &NoAssets,
            &sink,
        )
        .await;

        let events = match sink.0.lock() {
            Ok(events) => events,
            Err(poisoned) => poisoned.into_inner(),
        };
        let apply_frames = events
            .iter()
            .filter(|event| {
                matches!(
                    event,
                    EventDto::Patch {
                        patch: crate::dto::PatchDto::Applying { .. },
                        ..
                    }
                )
            })
            .count();
        assert!(apply_frames <= 11);
        assert!(matches!(
            events.first(),
            Some(EventDto::Patch {
                patch: crate::dto::PatchDto::Applying {
                    bytes_done: 99_999,
                    ..
                },
                ..
            })
        ));
        assert!(matches!(
            events.last(),
            Some(EventDto::Outcome {
                outcome: OutcomeDto::Succeeded,
                ..
            })
        ));
    }

    struct InterleavedProgress;

    impl Driver for InterleavedProgress {
        fn execute_cancellable(
            &self,
            _command: Command,
            _cancel: CancellationToken,
        ) -> Pin<Box<dyn Stream<Item = Event> + Send + '_>> {
            Box::pin(tokio_stream::iter([
                Event::Patch(PatchProgress::Applying {
                    repo: Repo::Game,
                    index: 1,
                    bytes_done: 1,
                }),
                Event::Patch(PatchProgress::Applying {
                    repo: Repo::Boot,
                    index: 2,
                    bytes_done: 2,
                }),
                Event::Patch(PatchProgress::Applying {
                    repo: Repo::Game,
                    index: 1,
                    bytes_done: 3,
                }),
                Event::Outcome(RunOutcome::Succeeded),
            ]))
        }
    }

    #[tokio::test(start_paused = true)]
    async fn coalesced_keys_keep_their_latest_values_and_observation_order() {
        let sink = VecSink::default();
        drive(
            &InterleavedProgress,
            Command::Launch {
                profile: Uuid::nil(),
            },
            CancellationToken::new(),
            Uuid::new_v4(),
            &NavigationState::default(),
            &NoAssets,
            &sink,
        )
        .await;

        let events = match sink.0.lock() {
            Ok(events) => events,
            Err(poisoned) => poisoned.into_inner(),
        };
        assert!(matches!(
            events.as_slice(),
            [
                EventDto::Patch {
                    patch: crate::dto::PatchDto::Applying {
                        repo,
                        index: 2,
                        bytes_done: 2
                    },
                    ..
                },
                EventDto::Patch {
                    patch: crate::dto::PatchDto::Applying {
                        repo: game_repo,
                        index: 1,
                        bytes_done: 3
                    },
                    ..
                },
                EventDto::Outcome {
                    outcome: OutcomeDto::Succeeded,
                    ..
                }
            ] if repo == "boot" && game_repo == "game"
        ));
    }

    #[test]
    fn read_only_runs_overlap_but_mutations_own_one_slot() {
        let runs = Runs::default();
        let read_one = Uuid::new_v4();
        let read_two = Uuid::new_v4();
        let exclusive_one = Uuid::new_v4();
        let exclusive_two = Uuid::new_v4();

        let read_one_lease = runs
            .start(read_one, RunClass::ReadOnly)
            .unwrap_or_else(|_| unreachable!("the first read must be admitted"));
        let _read_two_lease = runs
            .start(read_two, RunClass::ReadOnly)
            .unwrap_or_else(|_| unreachable!("the second read must be admitted"));
        let exclusive_one_lease = runs
            .start(exclusive_one, RunClass::Exclusive)
            .unwrap_or_else(|_| unreachable!("the first writer must be admitted"));
        assert_eq!(
            runs.start(exclusive_two, RunClass::Exclusive).err(),
            Some(RunAdmissionError::Busy)
        );
        assert_eq!(
            runs.start(read_one, RunClass::ReadOnly).err(),
            Some(RunAdmissionError::Duplicate)
        );

        drop(exclusive_one_lease);
        assert!(runs.start(exclusive_two, RunClass::Exclusive).is_ok());
        drop(read_one_lease);
    }

    #[test]
    fn direct_mutations_share_the_exclusive_slot_and_release_it_on_drop() {
        let runs = Runs::default();
        let mutation = runs
            .start_mutation()
            .unwrap_or_else(|_| unreachable!("the first direct mutation must be admitted"));

        assert_eq!(
            runs.start(Uuid::new_v4(), RunClass::Exclusive).err(),
            Some(RunAdmissionError::Busy)
        );
        assert_eq!(runs.start_mutation().err(), Some(RunAdmissionError::Busy));
        assert!(runs.start(Uuid::new_v4(), RunClass::ReadOnly).is_ok());

        drop(mutation);
        assert!(runs.start_mutation().is_ok());
    }

    #[test]
    fn a_profile_check_can_overlap_other_read_only_work() {
        let command = Command::Prefix {
            profile: Uuid::nil(),
            action: apogee_core::PrefixAction::Check,
        };

        assert_eq!(RunClass::for_command(&command), RunClass::ReadOnly);
    }

    #[test]
    fn cancellation_reaches_the_registered_token() {
        let runs = Runs::default();
        let run_id = Uuid::new_v4();
        let lease = runs
            .start(run_id, RunClass::Exclusive)
            .unwrap_or_else(|_| unreachable!("the run must be admitted"));
        let token = lease.cancellation();

        assert_eq!(runs.cancel(run_id), Ok(true));
        assert!(token.is_cancelled());
        assert_eq!(runs.cancel(Uuid::new_v4()), Ok(false));
    }

    #[test]
    fn dropping_a_run_lease_unregisters_it() {
        let runs = Runs::default();
        let run_id = Uuid::new_v4();
        let lease = runs
            .start(run_id, RunClass::Exclusive)
            .unwrap_or_else(|_| unreachable!("the run must be admitted"));

        drop(lease);

        assert_eq!(runs.cancel(run_id), Ok(false));
        assert!(runs.start_mutation().is_ok());
    }

    #[test]
    fn close_freezes_admission_before_cancelling_every_stream() {
        let runs = Runs::default();
        let read = runs
            .start(Uuid::new_v4(), RunClass::ReadOnly)
            .unwrap_or_else(|_| unreachable!("the read must be admitted"));
        let write = runs
            .start(Uuid::new_v4(), RunClass::Exclusive)
            .unwrap_or_else(|_| unreachable!("the write must be admitted"));
        let read_token = read.cancellation();
        let write_token = write.cancellation();

        assert_eq!(runs.begin_close(), Ok(true));
        assert_eq!(
            runs.start(Uuid::new_v4(), RunClass::ReadOnly).err(),
            Some(RunAdmissionError::Draining)
        );
        assert_eq!(runs.start_mutation().err(), Some(RunAdmissionError::Draining));
        assert!(!read_token.is_cancelled());
        assert!(!write_token.is_cancelled());

        assert_eq!(runs.cancel_all(), Ok(2));
        assert!(read_token.is_cancelled());
        assert!(write_token.is_cancelled());
    }

    #[test]
    fn declining_close_resumes_admission_without_cancelling_work() {
        let runs = Runs::default();
        let lease = runs
            .start(Uuid::new_v4(), RunClass::ReadOnly)
            .unwrap_or_else(|_| unreachable!("the read must be admitted"));
        let token = lease.cancellation();

        assert_eq!(runs.begin_close(), Ok(true));
        assert_eq!(runs.resume(), Ok(()));
        assert!(
            runs.start(Uuid::new_v4(), RunClass::ReadOnly).is_ok(),
            "a declined close must reopen admission"
        );
        assert!(!token.is_cancelled());
    }

    #[tokio::test]
    async fn drain_waits_for_streams_and_blocking_mutations_without_a_lost_wakeup() {
        let runs = Runs::default();
        let stream = runs
            .start(Uuid::new_v4(), RunClass::ReadOnly)
            .unwrap_or_else(|_| unreachable!("the read must be admitted"));
        let mutation = runs
            .start_mutation()
            .unwrap_or_else(|_| unreachable!("the mutation must be admitted"));
        assert_eq!(runs.begin_close(), Ok(true));
        assert_eq!(runs.cancel_all(), Ok(1));

        let waiting_runs = runs.clone();
        let waiter = tokio::spawn(async move { waiting_runs.wait_empty().await });
        tokio::task::yield_now().await;
        assert!(!waiter.is_finished());
        drop(stream);
        tokio::task::yield_now().await;
        assert!(!waiter.is_finished(), "the mutation lease still owns work");
        drop(mutation);
        assert_eq!(waiter.await.expect("drain waiter task"), Ok(()));

        assert_eq!(runs.wait_empty().await, Ok(()));
    }
}

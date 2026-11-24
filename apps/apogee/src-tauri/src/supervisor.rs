//! Run lifetime, cancellation, and forwarding from core streams to shell channels.

use std::collections::HashMap;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use apogee_core::{
    Command, Core, Event, FirstRunRequest, ImportXivLauncher, PatchProgress, Repo, SetupEvent, Uuid,
};
use tauri::ipc::Channel;
use tokio_stream::{Stream, StreamExt};
use tokio_util::sync::CancellationToken;

use crate::dto::{EventDto, EventWireDto};

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
pub(crate) async fn drive<D, S>(driver: &D, command: Command, cancel: CancellationToken, sink: &S)
where
    D: Driver + ?Sized,
    S: EventSink + ?Sized,
{
    let mut events = driver.execute_cancellable(command, cancel);
    let mut pending = HashMap::new();
    let mut observed = 0_u64;
    let mut flush = tokio::time::interval(Duration::from_millis(100));
    flush.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    // An interval's first tick is immediate. Consume it so a progress frame gets one complete
    // coalescing window rather than depending on which branch `select!` happens to poll first.
    flush.tick().await;

    loop {
        tokio::select! {
            event = events.next() => {
                let Some(event) = event else { break };
                if let Some(key) = progress_key(&event) {
                    observed = observed.saturating_add(1);
                    pending.insert(key, (observed, event));
                } else {
                    flush_pending(&mut pending, sink);
                    sink.send(EventDto::from(&event));
                }
            }
            _ = flush.tick() => flush_pending(&mut pending, sink),
        }
    }
    flush_pending(&mut pending, sink);
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
pub(crate) struct Runs(Arc<Mutex<RunState>>);

#[derive(Default)]
struct RunState {
    active: HashMap<Uuid, ActiveRun>,
    direct_mutation: bool,
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
            Command::Frontier(_) | Command::SupportBundle { .. } => Self::ReadOnly,
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
        let mut state = match self.runs.0.lock() {
            Ok(state) => state,
            Err(poisoned) => poisoned.into_inner(),
        };
        state.active.remove(&self.id);
    }
}

/// Ownership of the one direct-write slot shared with exclusive streamed runs.
pub(crate) struct MutationLease {
    runs: Runs,
}

impl Drop for MutationLease {
    fn drop(&mut self) {
        let mut state = match self.runs.0.lock() {
            Ok(state) => state,
            Err(poisoned) => poisoned.into_inner(),
        };
        state.direct_mutation = false;
    }
}

impl Runs {
    pub(crate) fn start(&self, id: Uuid, class: RunClass) -> Result<RunLease, RunAdmissionError> {
        let mut state = self.0.lock().map_err(|_| RunAdmissionError::Unavailable)?;
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
        let mut state = self.0.lock().map_err(|_| RunAdmissionError::Unavailable)?;
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
        let state = self.0.lock().map_err(|_| ())?;
        let Some(run) = state.active.get(&id) else {
            return Ok(false);
        };
        run.cancel.cancel();
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, Ordering};

    use apogee_core::{FlowState, OtpSource, PasswordSource, RunOutcome};

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
        let request = CommandDto::PatchAndPlay {
            profile,
            password: PasswordSourceDto::Provided(SecretBytes::new(b"password".to_vec())),
            otp: OtpSourceDto::Totp,
        };

        drive(
            &driver,
            request.into_core().unwrap_or(Command::Launch { profile }),
            CancellationToken::new(),
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
    fn a_profile_check_is_admitted_as_a_writer_of_profile_status() {
        let command = Command::Prefix {
            profile: Uuid::nil(),
            action: apogee_core::PrefixAction::Check,
        };

        assert_eq!(RunClass::for_command(&command), RunClass::Exclusive);
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
}

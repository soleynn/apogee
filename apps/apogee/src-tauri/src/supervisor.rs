//! Run lifetime, cancellation, and forwarding from core streams to shell channels.

use std::collections::{BTreeMap, HashMap};
use std::pin::Pin;
use std::sync::Mutex;
use std::time::Duration;

use apogee_core::{Command, Core, Event, PatchProgress, Repo, SetupEvent, Uuid};
use tauri::ipc::Channel;
use tokio_stream::{Stream, StreamExt};
use tokio_util::sync::CancellationToken;

use crate::dto::EventDto;

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

impl EventSink for Channel<EventDto> {
    fn send(&self, event: EventDto) {
        // A webview going away must not abandon an in-flight patch. Keep draining until core emits
        // its outcome; window-close coordination cancels the token explicitly.
        let _ = Channel::send(self, event);
    }
}

/// Drive exactly the command the request converted, forwarding every core frame in order.
pub(crate) async fn drive<D, S>(driver: &D, command: Command, cancel: CancellationToken, sink: &S)
where
    D: Driver + ?Sized,
    S: EventSink + ?Sized,
{
    let mut events = driver.execute_cancellable(command, cancel);
    let mut pending = BTreeMap::new();
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
                    pending.insert(key, event);
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

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
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

fn flush_pending<S: EventSink + ?Sized>(pending: &mut BTreeMap<ProgressKey, Event>, sink: &S) {
    for (_, event) in std::mem::take(pending) {
        sink.send(EventDto::from(&event));
    }
}

/// The cancellation tokens for runs the shell has started.
#[derive(Default)]
pub(crate) struct Runs(Mutex<HashMap<Uuid, CancellationToken>>);

impl Runs {
    pub(crate) fn start(&self, id: Uuid) -> Result<CancellationToken, ()> {
        let mut runs = self.0.lock().map_err(|_| ())?;
        if runs.contains_key(&id) {
            return Err(());
        }
        let cancel = CancellationToken::new();
        runs.insert(id, cancel.clone());
        Ok(cancel)
    }

    pub(crate) fn finish(&self, id: Uuid) {
        if let Ok(mut runs) = self.0.lock() {
            runs.remove(&id);
        }
    }

    pub(crate) fn cancel(&self, id: Uuid) -> Result<bool, ()> {
        let runs = self.0.lock().map_err(|_| ())?;
        let Some(cancel) = runs.get(&id) else {
            return Ok(false);
        };
        cancel.cancel();
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, Ordering};

    use apogee_core::{FlowState, OtpSource, PasswordSource, Progress, RunOutcome};

    use super::*;
    use crate::command::{CommandDto, OtpSourceDto, PasswordSourceDto, SecretBytes};
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
            request.into_core(),
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
            let progress = (0..100_000).map(|completed| {
                Event::Progress(Progress {
                    completed,
                    total: 100_000,
                    ..Progress::default()
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
        assert_eq!(events.len(), 2);
        assert!(matches!(
            events.first(),
            Some(EventDto::Progress {
                completed: 99_999,
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
}

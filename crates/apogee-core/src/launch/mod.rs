//! The launch seam: preparing a runner and spawning the supervised game.
//!
//! The flow drives launch through [`LaunchBackend`] rather than `apogee-runtime` directly, so a
//! headless test can substitute a fake and assert the launch states without a real prefix or
//! process. The real backend ([`runtime_backend::RuntimeLauncher`]) wraps `apogee-runtime`; the
//! opaque exit marker it returns is normalized to a code-less "the game exited" here (the game is a
//! non-child descendant of the runner, so no exit status can be reaped).
//!
//! Preparing and launching are two calls rather than one. What a launch runs is decided between them:
//! the prefix is brought up to date, and whatever loads into the game composes itself onto the plan.
//! Folding them back together would mean the flow could not see the prefix it is about to launch into.

use apogee_runtime::LaunchPlan;
use tokio::sync::mpsc::UnboundedSender;
use tokio_util::sync::CancellationToken;

use crate::command::Event;
use crate::error::CoreError;
use crate::model::RunnerSelection;

pub(crate) mod runtime_backend;

/// A prepared-and-spawned game the flow supervises.
#[async_trait::async_trait]
pub(crate) trait GameHandle: Send + Sync {
    /// The resolved game process id.
    fn game_pid(&self) -> i32;
    /// The prefix the game runs in, when the launch has one.
    fn prefix(&self) -> Option<apogee_runtime::Prefix>;
    /// Resolve when the game process exits (no exit status is available).
    async fn wait(&self) -> Result<(), CoreError>;
    /// Terminate the game process (targeted; not the whole prefix).
    async fn kill(&self) -> Result<(), CoreError>;
}

/// Prepares a runner/prefix and launches the supervised game.
#[async_trait::async_trait]
pub(crate) trait LaunchBackend: Send + Sync {
    /// Install the runner if needed and initialize the prefix, without launching anything.
    ///
    /// `None` means the backend has no real prefix to hand back, which only the test double does. A
    /// caller that needs one treats that as nothing to do rather than as a failure, so the flows around
    /// a prefix stay drivable without a wine.
    async fn prepare(
        &self,
        runner: &RunnerSelection,
        prefix_dir: &std::path::Path,
        cancel: &CancellationToken,
        events: &UnboundedSender<Event>,
    ) -> Result<Option<apogee_runtime::Prefix>, CoreError>;

    /// Spawn `plan` and supervise the game, relaying download/extract progress onto `events` as
    /// [`Event::Progress`]. Returns a handle to the running game.
    async fn launch(
        &self,
        plan: LaunchPlan,
        cancel: &CancellationToken,
        events: &UnboundedSender<Event>,
    ) -> Result<Box<dyn GameHandle>, CoreError>;
}

#[cfg(test)]
pub(crate) mod fake {
    //! An in-memory launch backend for the headless flow tests: it records the plan and returns a
    //! handle whose exit is test-controlled, so the `Launching`/`Running`/`Exited` sequence is
    //! assertable without a runner or a real process.

    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex, PoisonError};

    use tokio::sync::Notify;

    use super::{
        CancellationToken, CoreError, Event, GameHandle, LaunchBackend, LaunchPlan,
        RunnerSelection, UnboundedSender,
    };

    /// A fake backend. `exiting` returns handles that exit immediately (drives through to `Exited`);
    /// `running` returns handles that stay running until killed. `was_killed` reports whether any
    /// launched game's `kill()` ran (the Ctrl-C path).
    pub(crate) struct FakeLaunchBackend {
        recorded: Mutex<Vec<LaunchPlan>>,
        /// The prefix directories `prepare` was asked for, so a flow that has to prepare one before
        /// doing anything else can be checked on rather than taken on trust.
        prepared: Mutex<Vec<std::path::PathBuf>>,
        auto_exit: bool,
        /// Whether `prepare` stops the way a runner does when the token fires mid-`wineboot`.
        cancel_prepare: bool,
        killed: Arc<AtomicBool>,
    }

    impl FakeLaunchBackend {
        /// A backend whose launched games exit immediately.
        pub(crate) fn exiting() -> Self {
            Self::with_auto_exit(true)
        }

        /// A backend whose launched games keep running until killed.
        pub(crate) fn running() -> Self {
            Self::with_auto_exit(false)
        }

        /// A backend whose `prepare` never finishes creating the prefix because the run was stopped.
        /// It hands back the error the real runner does, rather than a stand-in, because what is being
        /// checked is whether that error reads as a cancellation once it reaches the flow.
        pub(crate) fn cancelled_while_preparing() -> Self {
            Self {
                cancel_prepare: true,
                ..Self::with_auto_exit(true)
            }
        }

        fn with_auto_exit(auto_exit: bool) -> Self {
            Self {
                recorded: Mutex::new(Vec::new()),
                prepared: Mutex::new(Vec::new()),
                auto_exit,
                cancel_prepare: false,
                killed: Arc::new(AtomicBool::new(false)),
            }
        }

        /// The prefix directories that were prepared, in order.
        pub(crate) fn prepared(&self) -> Vec<std::path::PathBuf> {
            self.prepared
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .clone()
        }

        /// The most recently launched plan, if any.
        pub(crate) fn last_plan(&self) -> Option<LaunchPlan> {
            self.recorded
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .last()
                .cloned()
        }

        /// How many launches were requested.
        pub(crate) fn launch_count(&self) -> usize {
            self.recorded
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .len()
        }

        /// Whether a launched game was killed.
        pub(crate) fn was_killed(&self) -> bool {
            self.killed.load(Ordering::SeqCst)
        }
    }

    #[async_trait::async_trait]
    impl LaunchBackend for FakeLaunchBackend {
        async fn prepare(
            &self,
            _runner: &RunnerSelection,
            prefix_dir: &std::path::Path,
            _cancel: &CancellationToken,
            _events: &UnboundedSender<Event>,
        ) -> Result<Option<apogee_runtime::Prefix>, CoreError> {
            self.prepared
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .push(prefix_dir.to_path_buf());
            if self.cancel_prepare {
                return Err(apogee_runtime::RuntimeError::PrefixInit {
                    step: apogee_runtime::SetupStep::WinebootInit,
                    source: Box::new(apogee_runtime::StepCancelled),
                }
                .into());
            }
            // No prefix: a fake runner has no wine to initialize one with, and the flows that consume
            // one are written to treat its absence as nothing to do.
            Ok(None)
        }

        async fn launch(
            &self,
            plan: LaunchPlan,
            _cancel: &CancellationToken,
            _events: &UnboundedSender<Event>,
        ) -> Result<Box<dyn GameHandle>, CoreError> {
            self.recorded
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .push(plan);
            let handle = FakeHandle {
                exited: Arc::new(Notify::new()),
                killed: self.killed.clone(),
            };
            if self.auto_exit {
                handle.exited.notify_one();
            }
            Ok(Box::new(handle))
        }
    }

    struct FakeHandle {
        exited: Arc<Notify>,
        killed: Arc<AtomicBool>,
    }

    #[async_trait::async_trait]
    impl GameHandle for FakeHandle {
        fn game_pid(&self) -> i32 {
            // A real pid: the addon layer refuses zero, which means "my whole process group".
            std::process::id().cast_signed()
        }

        fn prefix(&self) -> Option<apogee_runtime::Prefix> {
            None
        }

        async fn wait(&self) -> Result<(), CoreError> {
            self.exited.notified().await;
            Ok(())
        }

        async fn kill(&self) -> Result<(), CoreError> {
            self.killed.store(true, Ordering::SeqCst);
            self.exited.notify_one();
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::path::Path;
    use std::time::Duration;

    use tokio::sync::mpsc;

    use super::fake::FakeLaunchBackend;
    use super::{CancellationToken, LaunchBackend, LaunchPlan};
    use crate::model::RunnerSelection;

    fn plan() -> LaunchPlan {
        LaunchPlan::new(
            "/games/ffxiv/game/ffxiv_dx11.exe",
            "//**sqex0003redacted**//",
            BTreeMap::new(),
        )
    }

    #[tokio::test]
    async fn a_fake_backend_records_the_plan_and_exits() {
        let backend = FakeLaunchBackend::exiting();
        let (tx, _rx) = mpsc::unbounded_channel();
        let handle = backend
            .launch(plan(), &CancellationToken::new(), &tx)
            .await
            .unwrap();

        assert_eq!(backend.launch_count(), 1);
        assert_eq!(
            backend.last_plan().unwrap().program(),
            "/games/ffxiv/game/ffxiv_dx11.exe"
        );
        // An exiting handle resolves its wait immediately.
        handle.wait().await.unwrap();
    }

    /// The double has nothing to prepare, and the flows that ask it for a prefix have to be able to
    /// carry on without one.
    #[tokio::test]
    async fn a_fake_backend_prepares_no_prefix() {
        let backend = FakeLaunchBackend::exiting();
        let (tx, _rx) = mpsc::unbounded_channel();
        let prepared = backend
            .prepare(
                &RunnerSelection::SystemWine,
                Path::new("/tmp/apogee-prefix"),
                &CancellationToken::new(),
                &tx,
            )
            .await
            .unwrap();
        assert!(prepared.is_none());
    }

    #[tokio::test]
    async fn a_running_fake_handle_waits_until_killed() {
        let backend = FakeLaunchBackend::running();
        let (tx, _rx) = mpsc::unbounded_channel();
        let handle = backend
            .launch(plan(), &CancellationToken::new(), &tx)
            .await
            .unwrap();

        // A running handle does not resolve on its own.
        tokio::select! {
            _ = handle.wait() => panic!("running handle resolved before kill"),
            () = tokio::time::sleep(Duration::from_millis(20)) => {}
        }
        handle.kill().await.unwrap();
        handle.wait().await.unwrap();
    }
}

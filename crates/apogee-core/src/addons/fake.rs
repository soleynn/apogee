//! An addon seam that records what the flow asked of it and starts no process.
//!
//! The flow's job is the ordering: start after the game is up, tear down on every path out including
//! the failing ones, and never run the after-game tools for a launch that was cancelled. That is what
//! this records.

use std::sync::{Arc, Mutex};

use apogee_runtime::Prefix;
use async_trait::async_trait;
use tokio::sync::mpsc::UnboundedSender;
use tokio_util::sync::CancellationToken;

use apogee_addons::{DalamudConfig, ExternalAddon};
use apogee_runtime::LaunchPlan;

use super::{AddonBackend, AddonLifecycle};
use crate::command::Event;
use crate::error::CoreError;

/// What the flow did with the addon seam, in order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum AddonCall {
    /// A launch asked for its prefix to be brought up to date, and said whether it wanted Dalamud.
    Prepared {
        prefix: bool,
        dalamud: bool,
    },
    Started {
        game_pid: i32,
        count: usize,
    },
    GameClosed,
    Abandoned,
}

/// A recording addon seam.
#[derive(Clone, Default)]
pub(crate) struct FakeAddons {
    calls: Arc<Mutex<Vec<AddonCall>>>,
    /// The list the launch handed to `start`, in order. Kept whole rather than counted, because the
    /// order within it is a property the flow is responsible for and a count cannot see it.
    started: Arc<Mutex<Vec<ExternalAddon>>>,
    /// Reported by the lifecycle, so a test can drive the close-after-launch decision.
    has_work: bool,
    /// Failures the teardown reports, so a test can check they reach the event stream.
    failures: Vec<String>,
    /// What this seam contributes to a launch's plan, so a test can check it reaches the spawn.
    inserted_args: Vec<String>,
}

impl FakeAddons {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Say that this launch still owes teardown at exit.
    pub(crate) fn with_work(mut self) -> Self {
        self.has_work = true;
        self
    }

    /// Report `reason` as a failed companion when the teardown runs.
    pub(crate) fn failing(mut self, reason: &str) -> Self {
        self.failures.push(reason.to_owned());
        self
    }

    /// Compose `arg` onto the launch, as an injectable that wraps one would.
    pub(crate) fn inserting(mut self, arg: &str) -> Self {
        self.inserted_args.push(arg.to_owned());
        self
    }

    /// Everything the flow asked for, in order.
    pub(crate) fn calls(&self) -> Vec<AddonCall> {
        self.calls.lock().map(|c| c.clone()).unwrap_or_default()
    }

    /// The programs the launch handed to `start`, in the order it handed them over.
    pub(crate) fn started_programs(&self) -> Vec<std::path::PathBuf> {
        self.started
            .lock()
            .map(|started| started.iter().map(|a| a.program().to_path_buf()).collect())
            .unwrap_or_default()
    }

    fn record(&self, call: AddonCall) {
        if let Ok(mut calls) = self.calls.lock() {
            calls.push(call);
        }
    }
}

#[async_trait]
impl AddonBackend for FakeAddons {
    async fn prepare_launch(
        &self,
        prefix: Option<Prefix>,
        dalamud: Option<DalamudConfig>,
        plan: &mut LaunchPlan,
        _cancel: &CancellationToken,
        _events: &UnboundedSender<Event>,
    ) {
        self.record(AddonCall::Prepared {
            prefix: prefix.is_some(),
            dalamud: dalamud.is_some(),
        });
        if !self.inserted_args.is_empty() {
            plan.set_inserted_args(self.inserted_args.clone());
        }
    }

    async fn start(
        &self,
        game_pid: i32,
        _prefix: Option<Prefix>,
        addons: Vec<ExternalAddon>,
        _cancel: &CancellationToken,
        _events: &UnboundedSender<Event>,
    ) -> Box<dyn AddonLifecycle> {
        self.record(AddonCall::Started {
            game_pid,
            count: addons.len(),
        });
        if let Ok(mut started) = self.started.lock() {
            started.extend(addons);
        }
        Box::new(FakeLifecycle {
            calls: self.calls.clone(),
            has_work: self.has_work,
            failures: self.failures.clone(),
        })
    }
}

struct FakeLifecycle {
    calls: Arc<Mutex<Vec<AddonCall>>>,
    has_work: bool,
    failures: Vec<String>,
}

impl FakeLifecycle {
    fn record(&self, call: AddonCall) -> Vec<CoreError> {
        if let Ok(mut calls) = self.calls.lock() {
            calls.push(call);
        }
        self.failures
            .iter()
            .map(|reason| CoreError::Addon {
                program: std::path::PathBuf::from("/fake/tool"),
                reason: reason.clone(),
            })
            .collect()
    }
}

#[async_trait]
impl AddonLifecycle for FakeLifecycle {
    fn has_work(&self) -> bool {
        self.has_work
    }

    async fn game_closed(self: Box<Self>, _cancel: &CancellationToken) -> Vec<CoreError> {
        self.record(AddonCall::GameClosed)
    }

    async fn abandon(self: Box<Self>, _cancel: &CancellationToken) -> Vec<CoreError> {
        self.record(AddonCall::Abandoned)
    }
}

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

use apogee_addons::ExternalAddon;

use super::{AddonBackend, AddonLifecycle};
use crate::command::Event;
use crate::error::CoreError;

/// What the flow did with the addon seam, in order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum AddonCall {
    Started { game_pid: i32, count: usize },
    GameClosed,
    Abandoned,
}

/// A recording addon seam.
#[derive(Clone, Default)]
pub(crate) struct FakeAddons {
    calls: Arc<Mutex<Vec<AddonCall>>>,
    /// Reported by the lifecycle, so a test can drive the close-after-launch decision.
    has_work: bool,
    /// Failures the teardown reports, so a test can check they reach the event stream.
    failures: Vec<String>,
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

    /// Everything the flow asked for, in order.
    pub(crate) fn calls(&self) -> Vec<AddonCall> {
        self.calls.lock().map(|c| c.clone()).unwrap_or_default()
    }
}

#[async_trait]
impl AddonBackend for FakeAddons {
    async fn start(
        &self,
        game_pid: i32,
        _prefix: Option<Prefix>,
        addons: Vec<ExternalAddon>,
        _cancel: &CancellationToken,
        _events: &UnboundedSender<Event>,
    ) -> Box<dyn AddonLifecycle> {
        if let Ok(mut calls) = self.calls.lock() {
            calls.push(AddonCall::Started {
                game_pid,
                count: addons.len(),
            });
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

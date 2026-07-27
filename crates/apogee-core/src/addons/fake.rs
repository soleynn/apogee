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

use apogee_addons::{ComponentReport, ExternalAddon};

use super::{AddonBackend, AddonLifecycle};
use crate::command::Event;
use crate::error::CoreError;

/// What the flow did with the addon seam, in order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum AddonCall {
    Ensured { wanted: Vec<String> },
    Registrations { wanted: Vec<String> },
    Started { game_pid: i32, count: usize },
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
    /// Records this seam contributes to a launch, so a test can check they run ahead of the user's own.
    registrations: Vec<ExternalAddon>,
    /// Components the install reports as failed.
    component_failures: Vec<String>,
    /// Whether the install stops on a cancellation instead of returning a report.
    cancels: bool,
    /// Whether it stops before the install, while the catalog is still being downloaded.
    cancels_in_catalog: bool,
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

    /// Contribute `addon` to a launch, as an installed component's registration would.
    pub(crate) fn contributing(mut self, addon: ExternalAddon) -> Self {
        self.registrations.push(addon);
        self
    }

    /// Report `component` as having failed to install, so a test can check the flow does not call that a
    /// success.
    pub(crate) fn component_failure(mut self, component: &str) -> Self {
        self.component_failures.push(component.to_owned());
        self
    }

    /// Stop the install the way a cancelled one stops: fire the token, then answer the cancellation
    /// rather than a report. The real seam has no report to give once the token has gone, since the step
    /// that was in flight never finished and the ones behind it were never started.
    pub(crate) fn cancelling(mut self) -> Self {
        self.cancels = true;
        self
    }

    /// Stop it a step earlier, while the signed catalog is still downloading. The install loop that
    /// answers for a stopped step has not been reached yet, so what comes back is the download saying
    /// it was stopped, which is a different sentence for the same thing.
    pub(crate) fn cancelling_in_the_catalog(mut self) -> Self {
        self.cancels_in_catalog = true;
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
    async fn catalog(
        &self,
        _cancel: &CancellationToken,
    ) -> Result<apogee_addons::ComponentManifest, CoreError> {
        Ok(apogee_addons::ComponentManifest::default())
    }

    async fn ensure(
        &self,
        _prefix: Option<Prefix>,
        wanted: Vec<String>,
        cancel: &CancellationToken,
        _events: &UnboundedSender<Event>,
    ) -> Result<ComponentReport, CoreError> {
        self.record(AddonCall::Ensured { wanted });
        if self.cancels_in_catalog {
            cancel.cancel();
            return Err(CoreError::Addons(apogee_addons::AddonError::Download(
                apogee_fetch::FetchError::Cancelled,
            )));
        }
        if self.cancels {
            cancel.cancel();
            return Err(CoreError::Addons(apogee_addons::AddonError::Cancelled));
        }
        Ok(ComponentReport {
            outcomes: self
                .component_failures
                .iter()
                .map(|name| apogee_addons::ComponentOutcome {
                    name: name.clone(),
                    state: apogee_addons::ComponentState::Failed {
                        reason: "the fake refused it".to_owned(),
                    },
                })
                .collect(),
        })
    }

    async fn registrations(
        &self,
        _prefix: Option<Prefix>,
        wanted: Vec<String>,
        _cancel: &CancellationToken,
        _events: &UnboundedSender<Event>,
    ) -> Vec<ExternalAddon> {
        self.record(AddonCall::Registrations { wanted });
        self.registrations.clone()
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

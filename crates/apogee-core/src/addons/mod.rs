//! The seam over `apogee-addons` for one launch's companion tools.
//!
//! A trait rather than the concrete manager for the same reason patch and launch are: the flow
//! context is cloned onto a spawned task, and the flow tests state that they start no real process.
//! A fake here keeps that true while still exercising the ordering the flow is responsible for.
//!
//! The teardown is a separate object from the thing that started it, because it must be consumed to
//! run. That is what makes "the companions are torn down exactly once" a property of the types rather
//! than of remembering to call something.

pub(crate) mod addons_backend;
#[cfg(test)]
pub(crate) mod fake;

use apogee_addons::{DalamudConfig, ExternalAddon, LoadEvidence};
use apogee_runtime::{LaunchPlan, Prefix};
use async_trait::async_trait;
use tokio::sync::mpsc::UnboundedSender;
use tokio_util::sync::CancellationToken;
use url::Url;

use crate::command::Event;
use crate::error::CoreError;

/// Resolve the component catalog manifest and signature URLs. Hosted at a fixed HTTPS location with the
/// detached signature beside it under the same name plus `.sig`. `APOGEE_COMPONENT_CATALOG_URL` overrides
/// the manifest URL for a mirror or a pre-deploy test, and cannot weaken trust: the Ed25519 signature is
/// the authenticity gate whatever the origin, and the fetcher refuses plain `http`.
pub(crate) fn catalog_urls() -> Result<(Url, Url), CoreError> {
    let manifest = std::env::var("APOGEE_COMPONENT_CATALOG_URL")
        .unwrap_or_else(|_| "https://soleynn.github.io/apogee/components/manifest.json".to_owned());
    let signature = format!("{manifest}.sig");
    Ok((parse_url(&manifest)?, parse_url(&signature)?))
}

fn parse_url(raw: &str) -> Result<Url, CoreError> {
    Url::parse(raw).map_err(|e| CoreError::Config {
        var: "APOGEE_COMPONENT_CATALOG_URL".to_owned(),
        reason: match e {
            url::ParseError::RelativeUrlWithoutBase => "it must be an absolute url",
            _ => "it is not a valid url",
        },
    })
}

/// Drives `apogee-addons` for one launch, relaying its events onto the core event stream.
#[async_trait]
pub(crate) trait AddonBackend: Send + Sync {
    /// Bring `prefix` up to the setup the signed catalog publishes, then let whatever this launch loads
    /// into the game contribute to `plan`.
    ///
    /// `dalamud` is `Some` when the profile's toggle is on, and its absence is what keeps a launch from
    /// contacting the distribution at all.
    ///
    /// Infallible by design, like `start`. Everything here is an addition to a launch rather than a
    /// precondition for one: an unreachable catalog, a verb a wine refused, an injectable between
    /// releases. Each is reported on `events` and the game still starts, because a launcher that refuses
    /// to run the game over prefix hygiene is worse than one that runs it without.
    ///
    /// `prefix` of `None` is nothing to do, which is what the test double hands back.
    ///
    /// Returns what to watch for proof that whatever took the launch over came up inside the game, or
    /// `None` when nothing did or what did leaves no proof. Taken here rather than after the spawn
    /// because the companion that composed the launch is what knows where its proof lands, and it is
    /// dropped when this pass ends.
    async fn prepare_launch(
        &self,
        prefix: Option<Prefix>,
        dalamud: Option<DalamudConfig>,
        plan: &mut LaunchPlan,
        cancel: &CancellationToken,
        events: &UnboundedSender<Event>,
    ) -> Option<LoadEvidence>;

    /// Bring `prefix` up to the setup the signed catalog publishes, with no launch around it.
    ///
    /// The same pass [`Self::prepare_launch`] performs, minus everything about a game: a prefix
    /// prepared on its own has to end up in the state a launch would leave it in, or preparing one
    /// ahead of time buys nothing and the first launch still pays for it. What the catalog publishes
    /// is prefix hygiene rather than launch setup, and the shipped verb says so itself: it is to be
    /// applied before any Windows program runs in the prefix, and creating one runs several.
    ///
    /// Infallible for the same reason as `prepare_launch`, and `prefix` of `None` is likewise nothing
    /// to do.
    ///
    /// Returns what is *still* missing afterwards, which is the pass's own account of the verbs it
    /// could not apply rather than a second look at the prefix. `None` carries the same meaning it
    /// does on [`Self::missing_setup`]: nothing could be read, so nothing can be claimed.
    async fn apply_setup(
        &self,
        prefix: Option<Prefix>,
        cancel: &CancellationToken,
        events: &UnboundedSender<Event>,
    ) -> Option<Vec<String>>;

    /// The setup the signed catalog publishes that `prefix` does not have, reading it and changing
    /// nothing.
    ///
    /// `None` is the catalog being unreachable and nothing usable cached, so what a prefix is missing
    /// is unknown rather than empty. Why is narrated on `events` by the layer itself, as it is for a
    /// launch.
    ///
    /// `prefix` of `None` answers `None` too: with nothing to read the record of, what is missing is
    /// unknown, and saying "nothing" about a prefix that is not there is the one answer that would be
    /// wrong.
    async fn missing_setup(
        &self,
        prefix: Option<Prefix>,
        cancel: &CancellationToken,
        events: &UnboundedSender<Event>,
    ) -> Option<Vec<String>>;

    /// Start the profile's companions for a game that is already running.
    ///
    /// Infallible by design: a helper tool that cannot start is reported on `events` and in the
    /// returned lifecycle's failures, never as an error that would fail a launch already in progress.
    ///
    /// `confirming` is what [`Self::prepare_launch`] came back with: the proof to watch for, from
    /// whatever took the launch over. Watching is the only such report every runner can produce, since
    /// a loader's own exit status is unreachable behind a container-style runner. `None` is an ordinary
    /// launch, or one whose companion leaves nothing to confirm.
    async fn start(
        &self,
        game_pid: i32,
        prefix: Option<Prefix>,
        addons: Vec<ExternalAddon>,
        confirming: Option<LoadEvidence>,
        cancel: &CancellationToken,
        events: &UnboundedSender<Event>,
    ) -> Box<dyn AddonLifecycle>;
}

/// The teardown one launch's companions are owed.
#[async_trait]
pub(crate) trait AddonLifecycle: Send + Sync {
    /// Whether anything is still owed when the game exits. A launcher that would otherwise detach
    /// after starting the game has to stay attached for this.
    fn has_work(&self) -> bool;

    /// The game exited: stop what goes with it, then run what waits for it. Returns the failures to
    /// report, already in the core's error type, so the shell needs no rule of its own to notice one.
    async fn game_closed(self: Box<Self>, cancel: &CancellationToken) -> Vec<CoreError>;

    /// The launch was cancelled or failed: stop what was started, and run nothing that expects a
    /// session that actually happened.
    async fn abandon(self: Box<Self>, cancel: &CancellationToken) -> Vec<CoreError>;
}

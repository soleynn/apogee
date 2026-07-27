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

use apogee_addons::{ComponentReport, ExternalAddon};
use apogee_runtime::Prefix;
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
    /// The signed catalog of what can be installed, verified against the compiled-in key.
    ///
    /// # Errors
    /// [`CoreError::Addons`] if it cannot be fetched or does not verify. Fallible because the only caller
    /// is a user asking what is on offer, and an empty answer would read as "nothing" rather than "I
    /// could not look".
    async fn catalog(
        &self,
        cancel: &CancellationToken,
    ) -> Result<apogee_addons::ComponentManifest, CoreError>;

    /// Install the components `wanted` into `prefix`, applying the verbs they ask for first.
    ///
    /// Fallible, unlike the launch-time methods, because this is something the user asked for directly:
    /// a catalog it cannot reach means it did not do what was asked, and reporting success would be a
    /// lie. A single component failing is in the report rather than the error.
    ///
    /// `prefix` of `None` is nothing to do, which is what the test double hands back.
    async fn ensure(
        &self,
        prefix: Option<Prefix>,
        wanted: Vec<String>,
        cancel: &CancellationToken,
        events: &UnboundedSender<Event>,
    ) -> Result<ComponentReport, CoreError>;

    /// The launch-time records for whichever of `wanted` are companions that join a launch.
    ///
    /// Infallible for the same reason `start` is: a launch that already has everything it needs must not
    /// fail because a companion catalog was unreachable. What it cannot resolve it reports and omits.
    async fn registrations(
        &self,
        prefix: Option<Prefix>,
        wanted: Vec<String>,
        cancel: &CancellationToken,
        events: &UnboundedSender<Event>,
    ) -> Vec<ExternalAddon>;

    /// Start the profile's companions for a game that is already running.
    ///
    /// Infallible by design: a helper tool that cannot start is reported on `events` and in the
    /// returned lifecycle's failures, never as an error that would fail a launch already in progress.
    async fn start(
        &self,
        game_pid: i32,
        prefix: Option<Prefix>,
        addons: Vec<ExternalAddon>,
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

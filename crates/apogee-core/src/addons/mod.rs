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

use std::collections::BTreeMap;

use apogee_addons::{DalamudConfig, ExternalAddon, LoadEvidence, ProgramPlan};
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

/// What a launch asks of the addon layer, read from the profile's switches.
///
/// One value rather than an argument per switch, so a switch the seam stopped reading is one a
/// compiler can point at, and so the fake records exactly what a real launch hands over.
#[derive(Debug, Clone, Default)]
pub(crate) struct LaunchPrograms {
    /// Dalamud's configuration when the profile's toggle is on. Its absence is what keeps a launch
    /// from contacting the distribution at all.
    pub(crate) dalamud: Option<DalamudConfig>,
    /// The curated programs the profile turns on, by catalog row name. Empty is the whole of the
    /// opt-out: a program not named here is never planned, fetched, gated or started.
    pub(crate) programs: Vec<String>,
    /// The game version this launch runs, which each program's gate is checked against.
    pub(crate) game_version: String,
}

impl LaunchPrograms {
    /// The curated program names a profile turns on, in a fixed order.
    ///
    /// The names are the catalog's row names, which are also the setting names: one spelling for a
    /// program everywhere, so the setting cannot drift from the row it turns on.
    pub(crate) fn enabled(launch: &crate::model::LaunchSettings) -> Vec<String> {
        [("xivalexander", launch.xivalexander), ("act", launch.act)]
            .into_iter()
            .filter(|(_, on)| *on)
            .map(|(name, _)| name.to_owned())
            .collect()
    }
}

/// The curated programs a launch's gates let through, held from before the spawn until the game is
/// up.
///
/// Opaque to the flow on purpose: what turns a passed program into something that can be started
/// needs the running game, and the only way to it is [`AddonBackend::start`], which takes this back.
#[derive(Debug, Default)]
pub(crate) struct GatedPrograms {
    /// The addon layer's own plan, when a real catalog was gated against.
    plan: Option<ProgramPlan>,
    /// What passed, by row name, in the order they start.
    planned: Vec<String>,
    /// What to watch for each passed program's proof, read before the spawn so a write left by a
    /// previous session is not taken for this one's.
    evidence: Vec<LoadEvidence>,
}

impl GatedPrograms {
    /// The passed programs, read from the addon layer's plan before the spawn.
    pub(crate) fn from_plan(plan: ProgramPlan, since: std::time::SystemTime) -> Self {
        Self {
            planned: plan.planned().iter().map(|p| p.name.clone()).collect(),
            evidence: plan.load_evidence(since),
            plan: Some(plan),
        }
    }

    /// A set of passed programs with no plan behind it, for the test double.
    #[cfg(test)]
    pub(crate) fn passed(names: &[&str]) -> Self {
        Self {
            plan: None,
            planned: names.iter().map(|n| (*n).to_owned()).collect(),
            evidence: Vec::new(),
        }
    }

    /// The programs that start with the game, by row name.
    #[cfg(test)]
    pub(crate) fn planned(&self) -> &[String] {
        &self.planned
    }

    /// Whether any program is to start inside the game's prefix. Every curated program does.
    pub(crate) fn any(&self) -> bool {
        !self.planned.is_empty()
    }

    /// Take the plan and the proof to watch for apart.
    pub(crate) fn into_parts(self) -> (Option<ProgramPlan>, Vec<LoadEvidence>) {
        (self.plan, self.evidence)
    }
}

/// What a launch's addon pass decided before the spawn.
#[derive(Debug, Default)]
pub(crate) struct PreparedAddons {
    /// What to watch for proof that whatever took the launch over came up inside the game, or `None`
    /// when nothing did or what did leaves no proof. Taken here rather than after the spawn because the
    /// companion that composed the launch is what knows where its proof lands, and it is dropped when
    /// this pass ends.
    pub(crate) confirming: Option<LoadEvidence>,
    /// The curated programs that passed their gates.
    pub(crate) programs: GatedPrograms,
}

/// Drives `apogee-addons` for one launch, relaying its events onto the core event stream.
#[async_trait]
pub(crate) trait AddonBackend: Send + Sync {
    /// Bring `prefix` up to the setup the signed catalog publishes, install and gate the curated
    /// programs `request` turns on, then let whatever this launch loads into the game contribute to
    /// `plan`.
    ///
    /// Infallible by design, like `start`. Everything here is an addition to a launch rather than a
    /// precondition for one: an unreachable catalog, a verb a wine refused, an injectable between
    /// releases, a program not validated on this game version. Each is reported on `events` and the
    /// game still starts, because a launcher that refuses to run the game over prefix hygiene is worse
    /// than one that runs it without.
    ///
    /// `prefix` of `None` is nothing to do, which is what the test double hands back.
    async fn prepare_launch(
        &self,
        prefix: Option<Prefix>,
        request: LaunchPrograms,
        plan: &mut LaunchPlan,
        cancel: &CancellationToken,
        events: &UnboundedSender<Event>,
    ) -> PreparedAddons;

    /// Bring `prefix` up to the setup the signed catalog publishes, and install the curated
    /// `programs` the profile turns on, with no launch around it.
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
        programs: &[String],
        cancel: &CancellationToken,
        events: &UnboundedSender<Event>,
    ) -> Option<Vec<String>>;

    /// The setup the signed catalog publishes, and the install steps of the curated `programs`, that
    /// `prefix` does not have, reading it and changing nothing.
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
        programs: &[String],
        cancel: &CancellationToken,
        events: &UnboundedSender<Event>,
    ) -> Option<Vec<String>>;

    /// The catalog's rows for the curated programs, for a status report. Reads the hosted catalog
    /// and falls back to the last verified one, as a launch does; `None` is neither being usable.
    async fn program_rows(
        &self,
        cancel: &CancellationToken,
        events: &UnboundedSender<Event>,
    ) -> Option<Vec<crate::ProgramRow>>;

    /// Start the profile's companions for a game that is already running: the curated `programs`
    /// that passed their gates first, then the user's own `addons`.
    ///
    /// Infallible by design: a helper tool that cannot start is reported on `events` and in the
    /// returned lifecycle's failures, never as an error that would fail a launch already in progress.
    ///
    /// `shared_env` is what a companion inside the prefix must share with the game to join its wine
    /// session rather than start a second one. `confirming` is what [`Self::prepare_launch`] came back
    /// with: the proof to watch for, from whatever took the launch over. Watching is the only such
    /// report every runner can produce, since a loader's own exit status is unreachable behind a
    /// container-style runner. `None` is an ordinary launch, or one whose companion leaves nothing to
    /// confirm.
    #[allow(clippy::too_many_arguments)]
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

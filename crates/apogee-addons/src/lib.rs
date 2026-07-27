#![forbid(unsafe_code)]
//! The companion layer: the things people run alongside the game, and the prefix setup they need.
//!
//! Three things, and nothing curates a catalog of installable applications. Prefix-setup **verbs** are
//! hygiene the launch path applies on its own, described entirely by the [signed manifest](manifest) so
//! adding one is an edit rather than a release. An **[`Injectable`]** reaches the game by wrapping its
//! launch; Dalamud is the one that ships, opt-in and honestly tiered. And an
//! [`ExternalAddon`] is the user's own program, run beside the game from a path the user gave.
//!
//! Everything that touches a prefix goes through `apogee-runtime`'s prefix primitives and is recorded
//! in the prefix's own `prefix.json`, which is what makes a second pass a no-op.

use std::path::PathBuf;

use async_trait::async_trait;
use thiserror::Error;

use apogee_fetch::{FetchError, Fetcher};
use apogee_runtime::{LaunchPlan, Prefix, Runtime};

pub mod backup;
pub mod dalamud;
pub mod external;
pub mod manifest;
pub mod setup;

pub use backup::{BackupError, Selection};
pub use dalamud::{ClientLanguage, Dalamud, DalamudConfig, DalamudPaths, LoadMode, PluginPolicy};
pub use external::{
    AddonEvent, AddonEvents, AddonOutcome, AddonReport, AddonSession, ExternalAddon, GameContext,
    Outcome, RunIn, Running, Trigger,
};
pub use manifest::{
    Artifact, COMPONENT_MANIFEST_VERSION, COMPONENT_PUBLIC_KEYS, ComponentManifest, ComponentPath,
    InjectableEntry, InjectableKind, ManifestError, TrustedKey, Verb, VerbOp,
};
pub use setup::{
    PlanStep, SetupEvent, SetupEvents, SetupOutcome, SetupPlan, SetupReport, SetupState, StepAction,
};

/// Crate result over [`AddonError`].
pub type Result<T> = std::result::Result<T, AddonError>;

/// How well a companion is supported.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum SupportTier {
    FirstClass,
    BestEffort { note: String },
}

impl SupportTier {
    /// What the tier costs, when it costs something. `None` for a first-class companion, which is the
    /// honest answer: there is nothing to warn about.
    #[must_use]
    pub fn note(&self) -> Option<&str> {
        match self {
            Self::FirstClass => None,
            Self::BestEffort { note } => Some(note),
        }
    }
}

impl std::fmt::Display for SupportTier {
    /// The tier and not its note. The note is a caveat the user is shown before anything is fetched,
    /// on its own event, and repeating a paragraph of it inside a one-line failure buries the failure.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::FirstClass => "first class",
            Self::BestEffort { .. } => "best effort",
        })
    }
}

/// Prefix-setup and injection failures.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum AddonError {
    #[error("download failed")]
    Download(#[from] FetchError),
    #[error("invalid download request")]
    Spec(#[from] apogee_fetch::SpecError),
    /// The signed catalog was refused. Transparent, because the reason is the inner variant and an
    /// outer sentence over nine of them can only be vague enough to fit a schema slip and a forged
    /// signature at once, which reads as tampering either way.
    #[error(transparent)]
    Manifest(#[from] ManifestError),
    #[error("{verb}: the bytes fetched are not the ones it pins (expected {expected}, got {got})")]
    IntegrityMismatch {
        verb: String,
        expected: String,
        got: String,
    },
    /// A filesystem step failed. `what` names what was being set up and `step` which part of it: the
    /// io error underneath names a path and a kind, and nothing about why the launcher was there.
    #[error("{what}: could not {step}")]
    Io {
        what: String,
        step: &'static str,
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },
    /// An archive did not become the files it was meant to. Its own variant rather than an io failure:
    /// the bytes already matched their pin, so what is wrong is the archive's shape or the layout
    /// declared for it, and retrying the download fixes neither.
    #[error("{what}: the archive did not unpack")]
    Unpack {
        what: String,
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },
    #[error("injection of {injectable} failed ({tier} tier)")]
    Inject {
        injectable: String,
        tier: SupportTier,
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },
    /// A distribution answered with something this launcher cannot read. Its own variant rather than a
    /// download failure: the bytes arrived, they just are not the shape the endpoint promises, which is
    /// an upstream change rather than a network problem.
    #[error("{injectable}'s distribution answered with something this launcher cannot read")]
    Distribution {
        injectable: String,
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },
    #[error("verb {verb} failed")]
    VerbFailed {
        verb: String,
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },
    #[error("addon {index} ({program:?}) cannot be run: {reason}")]
    InvalidAddon {
        program: PathBuf,
        index: usize,
        reason: &'static str,
    },
    #[error("{program:?} runs inside a prefix, but this launch has no prefix")]
    PrefixRequired { program: PathBuf },
    #[error("{program:?} asks for {field:?}, which this launcher does not support")]
    UnsupportedField { program: PathBuf, field: String },
    #[error("failed to start {program:?}")]
    ExternalSpawn {
        program: PathBuf,
        /// Boxed because the runtime's own taxonomy is wide, and this error type is carried in the
        /// error half of results all over this crate.
        #[source]
        source: Box<apogee_runtime::RuntimeError>,
    },
    /// Transparent for the same reason as [`Self::Manifest`], and one more: this arm carries restore
    /// and pruning as well as capture, so any outer sentence naming one of the three is wrong about
    /// the other two.
    #[error(transparent)]
    Backup(#[from] BackupError),
    /// The cancellation token fired, so the work stopped where it was. Its own variant rather than a
    /// per-step failure: a caller counts what failed to decide whether it did what was asked, and a run
    /// somebody stopped on purpose has nothing to count.
    #[error("cancelled")]
    Cancelled,
    #[error("unsupported: {what}")]
    Unsupported { what: &'static str },
}

/// A companion that installs onto the host and reaches the game by wrapping its launch.
///
/// One method does the installing and one contributes to the launch, which is the whole seam: the
/// launcher iterates whatever is enabled and never learns what any of them are. There is deliberately no
/// attach-to-a-running-process half. The only shape that wanted one was a loader taking the resolved
/// game pid, and nothing here is that shape any more: Dalamud wraps the launch, and anything built on
/// top of Dalamud is its plugin rather than a second injector. A trait method with no implementor is a
/// contract nothing tests.
#[async_trait]
pub trait Injectable: Send + Sync {
    /// The name it is recorded and reported under.
    fn name(&self) -> &str;

    /// How well it works here, and what that costs when it is not first class.
    fn support_tier(&self) -> SupportTier;

    /// Install or update it, and say anything the user should know before the game starts.
    ///
    /// `prefix` is what it will run against, so this is also where a companion states what the runner
    /// in front of it costs.
    ///
    /// # Errors
    /// Whatever the companion's own install raises. A failure here is reported and the launch goes
    /// ahead without it, so an error must not describe the launch as broken.
    async fn ensure(
        &self,
        prefix: &Prefix,
        cancel: &tokio_util::sync::CancellationToken,
        events: &SetupEvents,
    ) -> Result<()>;

    /// Contribute to the launch before it is spawned: redirect the program, insert argv, add env.
    ///
    /// A companion that finds itself inapplicable (not installed, built for another game version) says
    /// so on `events`, leaves `plan` untouched, and returns `Ok(())`. Failing here would fail a launch
    /// that is otherwise fine.
    ///
    /// # Errors
    /// Whatever the companion raises while composing its invocation.
    fn prepare_launch(&self, plan: &mut LaunchPlan, events: &SetupEvents) -> Result<()>;
}

/// Where the companion layer keeps what it installs outside a prefix.
///
/// One root rather than a field per consumer: everything under it is re-derivable (the last verified
/// copy of the signed catalog, and an injectable's own versioned trees), so it is one directory to
/// point somewhere else and one to delete.
#[derive(Debug, Clone, Default)]
pub struct AddonPaths {
    /// Root for the verified catalog copy and the injectable trees.
    pub root: PathBuf,
}

impl AddonPaths {
    /// A root at `path`.
    #[must_use]
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { root: path.into() }
    }

    /// Where a verified manifest and its signature are published.
    #[must_use]
    pub fn catalog_cache(&self) -> PathBuf {
        self.root.join(".catalog")
    }

    /// The trees Dalamud installs into.
    #[must_use]
    pub fn dalamud(&self) -> DalamudPaths {
        DalamudPaths::under(self.root.join("dalamud"))
    }
}

/// The companion layer (`apogee-core`'s `addons` field).
///
/// A cheap handle: clone it to share. Every field it holds is itself a handle or a path.
#[derive(Debug, Clone)]
pub struct Addons {
    runtime: Runtime,
    fetcher: Fetcher,
    paths: AddonPaths,
}

impl Addons {
    /// Construct over the runtime, fetcher, and paths (composition root).
    #[must_use]
    pub fn new(runtime: Runtime, fetcher: Fetcher, paths: AddonPaths) -> Self {
        Self {
            runtime,
            fetcher,
            paths,
        }
    }

    /// Fetch the signed component manifest and verify it against the compiled-in key.
    ///
    /// Taken per operation rather than held on this handle: it is the thing that changes without a
    /// release, so a long-lived launcher process caching one would keep serving yesterday's rows.
    ///
    /// # Errors
    /// [`AddonError::Download`] if either file cannot be fetched, or [`AddonError::Manifest`] if the
    /// signature verifies against none of the compiled-in keys or the body violates the schema.
    pub async fn fetch_manifest(
        &self,
        manifest_url: &url::Url,
        signature_url: &url::Url,
        cancel: &tokio_util::sync::CancellationToken,
    ) -> Result<ComponentManifest> {
        setup::fetch_manifest(
            &self.fetcher,
            manifest_url,
            signature_url,
            &self.paths.catalog_cache(),
            &manifest::default_keys()?,
            cancel,
        )
        .await
    }

    /// The same fetch, verified against `keys` instead of the compiled-in ones, so a test can drive the
    /// whole download-verify-publish path with signatures it can produce. A slice rather than one key
    /// for the same reason the shipping path takes one: an overlap window is only real if it is
    /// exercised through the path a launch takes.
    ///
    /// Behind a feature, so a shipping build cannot fetch a manifest trusted against anything but the
    /// keys compiled into it.
    ///
    /// # Errors
    /// As [`Self::fetch_manifest`].
    #[cfg(feature = "testing")]
    pub async fn fetch_manifest_for_testing(
        &self,
        manifest_url: &url::Url,
        signature_url: &url::Url,
        keys: &[ed25519_dalek::VerifyingKey],
        cancel: &tokio_util::sync::CancellationToken,
    ) -> Result<ComponentManifest> {
        setup::fetch_manifest(
            &self.fetcher,
            manifest_url,
            signature_url,
            &self.paths.catalog_cache(),
            keys,
            cancel,
        )
        .await
    }

    /// The last manifest a fetch verified, re-verified before it is returned, or `None` if none has been
    /// fetched yet.
    ///
    /// Separate from [`Self::fetch_manifest`] rather than folded into it as a fallback, because whether a
    /// stale manifest is better than none depends on what the caller is doing: a launch would rather
    /// apply yesterday's prefix setup than none, and a command the user just asked for would rather say
    /// it could not reach the catalog.
    ///
    /// # Errors
    /// [`AddonError::Manifest`] if a cached copy is present but no longer verifies, which is a corrupt
    /// cache rather than an absent one.
    pub async fn cached_manifest(&self) -> Result<Option<ComponentManifest>> {
        setup::cached_manifest(&self.paths.catalog_cache(), &manifest::default_keys()?).await
    }

    /// The same read, verified against `keys`, so a test can read back what a test-key fetch published.
    ///
    /// # Errors
    /// As [`Self::cached_manifest`].
    #[cfg(feature = "testing")]
    pub async fn cached_manifest_for_testing(
        &self,
        keys: &[ed25519_dalek::VerifyingKey],
    ) -> Result<Option<ComponentManifest>> {
        setup::cached_manifest(&self.paths.catalog_cache(), keys).await
    }

    /// Apply every prefix-setup verb the manifest defines that `prefix` is missing.
    ///
    /// Idempotent: a verb the prefix already records is left alone, and a verb whose effect has since
    /// gone is applied again. Nothing selects which verbs run, because a verb is hygiene rather than a
    /// feature: the published list *is* the setup.
    ///
    /// # Errors
    /// [`AddonError::Install`] if the prefix's record cannot be read, or [`AddonError::Cancelled`] if
    /// the token fired. A single verb failing is in the report rather than the error.
    pub async fn apply_setup(
        &self,
        manifest: &ComponentManifest,
        prefix: &Prefix,
        cancel: &tokio_util::sync::CancellationToken,
        events: &SetupEvents,
    ) -> Result<SetupReport> {
        setup::apply_verbs(
            &self.runtime,
            &self.fetcher,
            manifest,
            prefix,
            cancel,
            events,
        )
        .await
    }

    /// The Dalamud injectable behind the launch setting, or `None` when the manifest offers no row for
    /// it.
    ///
    /// `None` rather than a compiled-in fallback: the row is where the distribution endpoint and the
    /// tier note live, so a build with no row has nothing honest to say about either and must not reach
    /// goatcorp on a guess.
    #[must_use]
    pub fn dalamud(&self, manifest: &ComponentManifest, config: DalamudConfig) -> Option<Dalamud> {
        let entry = manifest
            .injectables
            .iter()
            .find(|entry| entry.kind == InjectableKind::Dalamud)?;
        Some(Dalamud::new(
            self.paths.dalamud(),
            self.fetcher.clone(),
            entry,
            config,
        ))
    }

    /// Install or update each injectable, returning what failed.
    ///
    /// Never fails as a whole. An injectable that cannot be installed is reported and the launch goes
    /// ahead without it, because a companion is an addition to a launch rather than a precondition for
    /// one.
    pub async fn ensure_injectables(
        &self,
        injectables: &[&dyn Injectable],
        prefix: &Prefix,
        cancel: &tokio_util::sync::CancellationToken,
        events: &SetupEvents,
    ) -> Vec<AddonError> {
        let mut failures = Vec::new();
        for injectable in injectables {
            if let Err(err) = injectable.ensure(prefix, cancel, events).await {
                events.emit(SetupEvent::Failed {
                    what: injectable.name().to_owned(),
                    reason: setup::describe(&err),
                });
                failures.push(err);
            }
        }
        failures
    }

    /// Let each injectable contribute to `plan`, in order, returning what failed.
    ///
    /// The same list and the same loop as [`Self::ensure_injectables`], so nothing about a launch knows
    /// which companion it is composing. One failing leaves the plan as the previous ones left it and the
    /// launch proceeds.
    #[must_use]
    pub fn prepare_launch(
        &self,
        injectables: &[&dyn Injectable],
        plan: &mut LaunchPlan,
        events: &SetupEvents,
    ) -> Vec<AddonError> {
        let mut failures = Vec::new();
        for injectable in injectables {
            if let Err(err) = injectable.prepare_launch(plan, events) {
                events.emit(SetupEvent::Failed {
                    what: injectable.name().to_owned(),
                    reason: setup::describe(&err),
                });
                failures.push(err);
            }
        }
        failures
    }

    /// Start the companions that run alongside a game that is already up.
    ///
    /// Never fails as a whole: an entry that cannot be run is recorded in the session's report and
    /// the rest continue, because a helper tool must not fail a launch that has already succeeded.
    pub async fn start_external(
        &self,
        addons: &[ExternalAddon],
        game: &GameContext,
        events: &AddonEvents,
    ) -> AddonSession {
        external::start(&self.runtime, addons, game, events).await
    }
}

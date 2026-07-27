#![forbid(unsafe_code)]
//! The companion layer: the things people run alongside the game, and the prefix setup they need.
//!
//! Everything installable is a row in the [signed component manifest](manifest), so adding a companion
//! or correcting where its files land is a manifest edit. Installation goes through `apogee-runtime`'s
//! prefix primitives and is recorded in the prefix's own `prefix.json`, which is what makes a second
//! install a no-op. Injection ([`Injectable`]) is the seam this crate owns and does not yet drive.

use std::path::PathBuf;

use async_trait::async_trait;
use thiserror::Error;

use apogee_fetch::{FetchError, Fetcher};
use apogee_runtime::{GameSession, LaunchPlan, Prefix, Progress, Runtime};

pub mod backup;
pub mod components;
pub mod external;
pub mod manifest;

pub use backup::{BackupError, Selection};
pub use components::{
    ComponentEvent, ComponentEvents, ComponentOutcome, ComponentReport, ComponentState, EnsurePlan,
    PlanStep, StepAction, StepKind,
};
pub use external::{
    AddonEvent, AddonEvents, AddonOutcome, AddonReport, AddonSession, ExternalAddon, GameContext,
    Outcome, RunIn, Running, Trigger,
};
pub use manifest::{
    Artifact, Attach, COMPONENT_MANIFEST_VERSION, COMPONENT_PUBLIC_KEY, ComponentManifest,
    ComponentPath, InjectableEntry, InjectableKind, ManifestError, Registration, ToolEntry,
    ToolKind, Verb, VerbOp,
};

/// Crate result over [`AddonError`].
pub type Result<T> = std::result::Result<T, AddonError>;

/// How well a component is supported.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum SupportTier {
    FirstClass,
    BestEffort { note: String },
}

/// Component install / injection failures.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum AddonError {
    #[error("component download failed")]
    Download(#[from] FetchError),
    #[error("invalid component download request")]
    Spec(#[from] apogee_fetch::SpecError),
    #[error("the component manifest is not trustworthy")]
    Manifest(#[from] ManifestError),
    #[error("no component named {name:?} in the manifest")]
    UnknownComponent { name: String },
    #[error("integrity mismatch for {component}: expected {expected}, got {got}")]
    IntegrityMismatch {
        component: String,
        expected: String,
        got: String,
    },
    #[error("install of {component} failed at step {step}")]
    Install {
        component: String,
        step: &'static str,
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },
    #[error("injection of {injectable} failed ({tier:?})")]
    Inject {
        injectable: String,
        tier: SupportTier,
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
    #[error("config backup failed")]
    Backup(#[from] BackupError),
    /// The cancellation token fired, so the work stopped where it was. Its own variant rather than a
    /// per-component failure: a caller counts what failed to decide whether it did what was asked, and
    /// a run somebody stopped on purpose has nothing to count.
    #[error("cancelled")]
    Cancelled,
    #[error("unsupported: {what}")]
    Unsupported { what: &'static str },
}

/// A component that installs into a prefix and hooks the launch / attach lifecycle.
#[async_trait]
pub trait Injectable: Send + Sync {
    fn name(&self) -> &str;
    fn support_tier(&self) -> SupportTier;

    /// Install or update the component into `prefix` (opt-in).
    async fn ensure(&self, prefix: &Prefix, p: &Progress) -> Result<()>;

    /// Wrap or mutate the launch before spawn. Default: no-op.
    fn prepare_launch(&self, _plan: &mut LaunchPlan) -> Result<()> {
        Ok(())
    }

    /// Attach after the game process is resolved. Default: no-op.
    async fn attach(&self, _game: &GameSession) -> Result<()> {
        Ok(())
    }
}

/// Where the companion layer keeps what it installs outside a prefix.
///
/// A prefix tool's files live inside the prefix that runs it, so they need no path here. A native
/// companion runs on the host and has nowhere else to go.
#[derive(Debug, Clone, Default)]
pub struct AddonPaths {
    /// Root for natively-installed components, one directory per component.
    pub components: PathBuf,
}

/// Companion / component manager (`apogee-core`'s `addons` field).
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
    /// signature does not verify against the compiled-in key or the body violates the schema.
    pub async fn fetch_manifest(
        &self,
        manifest_url: &url::Url,
        signature_url: &url::Url,
        cancel: &tokio_util::sync::CancellationToken,
    ) -> Result<ComponentManifest> {
        components::fetch_manifest(
            &self.fetcher,
            manifest_url,
            signature_url,
            &self.catalog_cache(),
            &manifest::default_key()?,
            cancel,
        )
        .await
    }

    /// The same fetch, verified against `key` instead of the compiled-in one, so a test can drive the
    /// whole download-verify-publish path with a signature it can produce.
    ///
    /// Behind a feature, so a shipping build cannot fetch a manifest trusted against anything but the
    /// key compiled into it.
    ///
    /// # Errors
    /// As [`Self::fetch_manifest`].
    #[cfg(feature = "testing")]
    pub async fn fetch_manifest_for_testing(
        &self,
        manifest_url: &url::Url,
        signature_url: &url::Url,
        key: &ed25519_dalek::VerifyingKey,
        cancel: &tokio_util::sync::CancellationToken,
    ) -> Result<ComponentManifest> {
        components::fetch_manifest(
            &self.fetcher,
            manifest_url,
            signature_url,
            &self.catalog_cache(),
            key,
            cancel,
        )
        .await
    }

    /// The last manifest a fetch verified, re-verified before it is returned, or `None` if none has been
    /// fetched yet.
    ///
    /// Separate from [`Self::fetch_manifest`] rather than folded into it as a fallback, because whether a
    /// stale manifest is better than none depends on what the caller is doing: a launch would rather
    /// start yesterday's companions than none, and an install the user just asked for would rather say
    /// it could not reach the catalog.
    ///
    /// # Errors
    /// [`AddonError::Manifest`] if a cached copy is present but no longer verifies, which is a corrupt
    /// cache rather than an absent one.
    pub async fn cached_manifest(&self) -> Result<Option<ComponentManifest>> {
        components::cached_manifest(&self.catalog_cache(), &manifest::default_key()?).await
    }

    /// The same read, verified against `key`, so a test can read back what a test-key fetch published.
    ///
    /// # Errors
    /// As [`Self::cached_manifest`].
    #[cfg(feature = "testing")]
    pub async fn cached_manifest_for_testing(
        &self,
        key: &ed25519_dalek::VerifyingKey,
    ) -> Result<Option<ComponentManifest>> {
        components::cached_manifest(&self.catalog_cache(), key).await
    }

    fn catalog_cache(&self) -> PathBuf {
        self.paths.components.join(".catalog")
    }

    /// Install the named components into `prefix`, applying the verbs they ask for first.
    ///
    /// Idempotent: a component the prefix already records is left alone. The whole call fails only for
    /// something structural (a name no row offers); a component that fails to install is recorded in
    /// the report and the rest continue, because one broken row should cost the user that component
    /// rather than the set.
    ///
    /// # Errors
    /// [`AddonError::UnknownComponent`] if a name is not in `manifest`.
    pub async fn ensure(
        &self,
        manifest: &ComponentManifest,
        prefix: &Prefix,
        wanted: &[String],
        cancel: &tokio_util::sync::CancellationToken,
        events: &ComponentEvents,
    ) -> Result<ComponentReport> {
        components::ensure(
            &self.runtime,
            &self.fetcher,
            &self.paths,
            manifest,
            prefix,
            wanted,
            cancel,
            events,
        )
        .await
    }

    /// The companions among `wanted` that join a launch, as external-addon records pointing at where
    /// they were installed.
    ///
    /// Derived from the manifest on every launch rather than copied into the profile when installed: a
    /// profile stores which components it wants, and how one is started is the manifest's answer, so a
    /// corrected row takes effect without rewriting anybody's configuration.
    ///
    /// # Errors
    /// [`AddonError::InvalidAddon`] if a row describes a program path that cannot be run.
    pub fn registrations(
        &self,
        manifest: &ComponentManifest,
        prefix: &Prefix,
        wanted: &[String],
    ) -> Result<Vec<ExternalAddon>> {
        components::registrations(&self.paths, manifest, prefix, wanted)
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

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
use std::time::SystemTime;

use async_trait::async_trait;
use thiserror::Error;

use apogee_fetch::{FetchError, Fetcher};
use apogee_runtime::{LaunchPlan, Prefix, Runtime};

pub mod backup;
pub mod dalamud;
pub mod external;
pub mod launch;
pub mod manifest;
pub mod setup;

#[cfg(test)]
mod tests;

pub use backup::{BackupError, Selection};
pub use dalamud::{
    ClientLanguage, Dalamud, DalamudConfig, DalamudPaths, LoadEvidence, LoadMode, PluginPolicy,
};
pub use external::{
    AddonEvent, AddonEvents, AddonOutcome, AddonReport, AddonSession, ExternalAddon, GameContext,
    Outcome, RunIn, Running, Trigger,
};
pub use launch::{Contribution, LaunchEdit, Preparation, Redirect};
pub use manifest::{
    Artifact, COMPONENT_MANIFEST_VERSION, COMPONENT_PUBLIC_KEYS, ComponentManifest, ComponentPath,
    InjectableEntry, InjectableKind, ManifestError, TrustedKey, Verb, VerbOp,
};
pub use setup::{SetupEvent, SetupEvents, SetupOutcome, SetupReport, SetupState};

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
    #[non_exhaustive]
    IntegrityMismatch {
        verb: String,
        expected: String,
        got: String,
    },
    /// A filesystem step failed. `what` names what was being set up and `step` which part of it: the
    /// io error underneath names a path and a kind, and nothing about why the launcher was there.
    #[error("{what}: could not {step}")]
    #[non_exhaustive]
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
    #[non_exhaustive]
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
    /// Two companions each reach the game by becoming the program the launch spawns, and a launch
    /// spawns one program. No `source`, because nothing underneath went wrong: both composed their
    /// invocation correctly and the launch has room for one of them.
    #[error(
        "{injectable} cannot redirect this launch: {redirector} already did, and a launch spawns one program"
    )]
    #[non_exhaustive]
    LaunchAlreadyRedirected {
        /// The one refused.
        injectable: String,
        /// The one that already holds the launch.
        redirector: String,
    },
    /// A distribution answered with something this launcher cannot read. Its own variant rather than a
    /// download failure: the bytes arrived, they just are not the shape the endpoint promises, which is
    /// an upstream change rather than a network problem.
    #[error("{injectable}'s distribution answered with something this launcher cannot read")]
    #[non_exhaustive]
    Distribution {
        injectable: String,
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },
    #[error("verb {verb} failed")]
    #[non_exhaustive]
    VerbFailed {
        verb: String,
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },
    #[error("addon {index} ({program:?}) cannot be run: {reason}")]
    #[non_exhaustive]
    InvalidAddon {
        program: PathBuf,
        index: usize,
        reason: &'static str,
    },
    #[error("{program:?} runs inside a prefix, but this launch has no prefix")]
    #[non_exhaustive]
    PrefixRequired { program: PathBuf },
    #[error("{program:?} asks for {field:?}, which this launcher does not support")]
    #[non_exhaustive]
    UnsupportedField { program: PathBuf, field: String },
    #[error("failed to start {program:?}")]
    #[non_exhaustive]
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
    #[non_exhaustive]
    Unsupported { what: &'static str },
}

impl AddonError {
    /// This failure and its causes as one line.
    ///
    /// The outer message is routinely the least specific part of a chain: "could not stage a download"
    /// over "no space left on device", or a transparent arm over the taxonomy that knows what happened.
    /// Every seam this crate reports through carries a `String` rather than the error itself, so a
    /// caller with only `Display` has already lost the useful half by the time it renders. This is what
    /// those callers should render.
    #[must_use]
    pub fn chain(&self) -> String {
        chain_of(self)
    }

    /// Whether this is the work stopping because it was asked to, rather than something going wrong.
    ///
    /// Answered here rather than by each consumer, because a stop reaches this taxonomy two ways: the
    /// setup pass ends its own run as [`Self::Cancelled`], and a download the token interrupted arrives
    /// spelled as the fetcher's cancellation, since the catalog is fetched before that loop begins. A
    /// caller restating the list is a caller that will miss the second one.
    #[must_use]
    pub fn is_cancellation(&self) -> bool {
        matches!(
            self,
            Self::Cancelled | Self::Download(FetchError::Cancelled)
        )
    }
}

/// Narrate a companion's failure and keep it for the caller.
///
/// Both, always, and in one place: the launch goes ahead either way, so the event stream is the only
/// thing that tells a user why a companion they asked for is not in the game they are playing, and a
/// returned failure nobody said out loud is the silent case this layer exists to avoid.
fn report(failures: &mut Vec<AddonError>, events: &SetupEvents, what: &str, err: AddonError) {
    events.emit(SetupEvent::Failed {
        what: what.to_owned(),
        reason: err.chain(),
    });
    failures.push(err);
}

/// The same for any error, so the places this crate reports another crate's failure through a `String`
/// do not have to lose its causes either.
pub(crate) fn chain_of(err: &dyn std::error::Error) -> String {
    let mut text = err.to_string();
    let mut source = err.source();
    while let Some(cause) = source {
        text.push_str(": ");
        text.push_str(&cause.to_string());
        source = cause.source();
    }
    text
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

    /// What to add to the launch before it is spawned: redirect the program, insert argv, add env, add
    /// a wrapper.
    ///
    /// Composed and handed back rather than written into `plan`, which is read-only here for two
    /// reasons. A companion whose own work fails partway through contributes nothing rather than the
    /// half it had already written. And what a companion may change is then the three things a
    /// [`LaunchEdit`] can express, rather than every field of a launch it did not compose.
    ///
    /// `plan` is the launch as the injectables before it left it, to read the program and the prefix
    /// from.
    ///
    /// A companion that finds itself inapplicable (not installed, built for another game version) says
    /// so on `events` and returns [`Contribution::Declined`]. Failing here would fail a launch that is
    /// otherwise fine.
    ///
    /// Redirecting the program is the one contribution a launch has room for once: a second
    /// [`Redirect`] in the same pass is refused whole by
    /// [`Addons::prepare_launch`](crate::Addons::prepare_launch), so an implementor composes its own
    /// invocation without checking what ran before it.
    ///
    /// # Errors
    /// Whatever the companion raises while composing its invocation.
    fn prepare_launch(&self, plan: &LaunchPlan, events: &SetupEvents) -> Result<Contribution>;

    /// What to watch for proof that this companion came up inside the game, if it leaves any.
    ///
    /// `since` is when the launch began. A companion writes its proof into a file that outlives the
    /// session, so only a write after that point belongs to this launch.
    ///
    /// Asked while the companion is still here, because it is dropped once the launch is composed and
    /// the proof lands seconds later. What comes back owns everything it needs, so a caller can spawn
    /// it and forget it.
    ///
    /// Defaulted to `None`: a companion that leaves no trace of loading is not a companion that failed
    /// to, and a launcher that has nothing to watch says nothing rather than reporting an absence.
    fn load_evidence(&self, since: SystemTime) -> Option<LoadEvidence> {
        let _ = since;
        None
    }
}

/// Where the companion layer keeps what it installs outside a prefix.
///
/// One root rather than a field per consumer: everything under it is re-derivable (the last verified
/// copy of the signed catalog, and an injectable's own versioned trees), so it is one directory to
/// point somewhere else and one to delete.
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
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

    /// The prefix-setup verbs the manifest defines that `prefix` does not have.
    ///
    /// The same decision [`Self::apply_setup`] acts on, taken without acting on it, so a caller can
    /// report what a prefix is missing without setting it up. A verb whose effect has gone is missing
    /// however the prefix's record reads.
    ///
    /// # Errors
    /// [`AddonError::Io`] if the prefix's record cannot be read, which is the same refusal
    /// [`Self::apply_setup`] makes: with no record there is no telling setup that is needed from setup
    /// that is not.
    pub fn missing_setup(
        &self,
        manifest: &ComponentManifest,
        prefix: &Prefix,
    ) -> Result<Vec<String>> {
        setup::missing_verbs(manifest, prefix)
    }

    /// The Dalamud injectable behind the launch setting, or `None` when the manifest offers no row for
    /// it.
    ///
    /// `None` rather than a compiled-in fallback: the row is where the distribution endpoint and the
    /// tier note live, so a build with no row has nothing honest to say about either and must not reach
    /// goatcorp on a guess.
    ///
    /// Narrates the `None` on `events` rather than leaving it to the caller. The user asked for this at
    /// a launch and is owed a reason it did not happen, and a caller inventing one is a caller writing a
    /// sentence about a decision it did not make.
    #[must_use]
    pub fn dalamud(
        &self,
        manifest: &ComponentManifest,
        config: DalamudConfig,
        events: &SetupEvents,
    ) -> Option<Dalamud> {
        let Some(entry) = manifest.injectable(InjectableKind::Dalamud) else {
            events.emit(SetupEvent::Failed {
                what: dalamud::DALAMUD.to_owned(),
                reason: "the catalog carries no row for it, so there is nowhere to fetch it from"
                    .to_owned(),
            });
            return None;
        };
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
            // The tier is said here rather than by each companion, so a second injectable gets the
            // warning right by existing rather than by remembering to announce itself. A first-class
            // tier has nothing to say and says nothing.
            if let Some(note) = injectable.support_tier().note() {
                events.emit(SetupEvent::Caveat {
                    what: injectable.name().to_owned(),
                    note: note.to_owned(),
                });
            }
            if let Err(err) = injectable.ensure(prefix, cancel, events).await {
                events.emit(SetupEvent::Failed {
                    what: injectable.name().to_owned(),
                    reason: err.chain(),
                });
                failures.push(err);
            }
        }
        failures
    }

    /// Let each injectable contribute to `plan`, in order, returning what the pass came to.
    ///
    /// The same list and the same loop as [`Self::ensure_injectables`], so nothing about a launch knows
    /// which companion it is composing. Each is offered the launch as the ones before it left it, and
    /// what it hands back is applied here: one failing contributes nothing at all and the launch
    /// proceeds.
    ///
    /// [`Preparation::redirected_by`] names the companion that took the launch over, which is the one
    /// thing about this pass a caller cannot read back off the plan afterwards.
    ///
    /// A launch spawns one program, so the first companion to redirect it keeps it and a second is
    /// refused with [`AddonError::LaunchAlreadyRedirected`], reported by name like any other companion
    /// failure. The refusal is of the whole contribution rather than of the redirect alone: a plan
    /// carrying one companion's env and argv around another's program is a launch neither of them
    /// composed, which is worse than one companion cleanly absent.
    ///
    /// *First* wins, and what claims the slot is asking for a [`Redirect`] rather than changing the
    /// program to something new, so a companion that redirects a launch to the program it already names
    /// still holds it.
    #[must_use]
    pub fn prepare_launch(
        &self,
        injectables: &[&dyn Injectable],
        plan: &mut LaunchPlan,
        events: &SetupEvents,
    ) -> Preparation {
        let mut failures = Vec::new();
        // The companion that became the program, so a second one asking for the same slot is refused
        // rather than silently overwriting it. Kept here rather than as a flag on the plan because the
        // rule is about companions: `apogee-runtime` does not know they exist, and a plan that refused
        // its own redirect would raise inside whichever injectable happened to compose it, leaving
        // every implementor to map and narrate a rule that belongs to the one loop that runs them.
        let mut redirected_by: Option<String> = None;
        for injectable in injectables {
            let edit = match injectable.prepare_launch(plan, events) {
                Ok(Contribution::Edit(edit)) => edit,
                Ok(Contribution::Declined) => continue,
                Err(err) => {
                    report(&mut failures, events, injectable.name(), err);
                    continue;
                }
            };
            if edit.redirects() {
                if let Some(holder) = redirected_by.as_deref() {
                    let refused = AddonError::LaunchAlreadyRedirected {
                        injectable: injectable.name().to_owned(),
                        redirector: holder.to_owned(),
                    };
                    report(&mut failures, events, injectable.name(), refused);
                    continue;
                }
                redirected_by = Some(injectable.name().to_owned());
            }
            edit.apply(plan);
        }
        Preparation {
            redirected_by,
            failures,
        }
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

#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![warn(clippy::pedantic, clippy::nursery)]
// `pub(crate)` inside an already-private module is redundant to the compiler, but it is this
// crate's own signal that an item is deliberately not part of its public surface, independent of
// how deep the module nesting runs or whether a later edit makes an enclosing module `pub`.
// Widening every one of these to plain `pub` would erase that guardrail for a lint with no
// behavioral stake, right before the surface it protects freezes at 1.0.
#![allow(clippy::redundant_pub_crate)]

//! The companion layer: what runs alongside the game, and the prefix setup it needs.
//!
//! Three kinds of thing, and no catalog of installable applications. Prefix-setup **verbs** are
//! hygiene the launch path applies on its own, described entirely by the [signed manifest](manifest)
//! so adding one is an edit rather than a release. An **[`Injectable`]** reaches the game by wrapping
//! its launch, and [`Dalamud`] is the one that ships, opt-in and honestly tiered. An
//! **[`ExternalAddon`]** is the user's own program, run beside the game from a path the user gave.
//!
//! Everything that touches a prefix goes through `apogee-runtime`'s prefix primitives and is
//! recorded in that prefix's own metadata, which is what makes a second pass a no-op.
//!
//! # Layout
//!
//! - [`Addons`] is the handle the whole layer hangs off, over a `Runtime`, a `Fetcher` and
//!   [`AddonPaths`].
//! - [`VerifiedManifest`] is the signed catalog of verbs and injectables, and the only shape the
//!   apply path accepts. [`Addons::apply_setup`] brings a prefix up to it and
//!   [`Addons::missing_setup`] takes the same decision without acting on it.
//! - [`Injectable`] is the seam a companion reaches the game through. What one contributes is a
//!   [`LaunchEdit`], and [`Addons::prepare_launch`] is what applies it.
//! - [`ExternalAddon`] is a user-supplied program. [`Addons::start_external`] returns the
//!   [`AddonSession`] that holds the ones running with the game and stops them when it closes.
//! - [`backup`] captures and restores a prefix's configuration files.
//! - [`SetupEvents`] is the stream all of it narrates onto, and [`AddonError`] the taxonomy it fails
//!   with.
//!
//! # Examples
//!
//! A launch: fetch the catalog, bring the prefix up to it, then let the companions edit the plan.
//!
//! ```
//! # use apogee_addons::{Addons, DalamudConfig, Injectable, SetupEvents};
//! # use apogee_runtime::{LaunchPlan, Prefix};
//! # use tokio_util::sync::CancellationToken;
//! # async fn demo(
//! #     addons: &Addons,
//! #     prefix: &Prefix,
//! #     plan: &mut LaunchPlan,
//! #     manifest_url: &url::Url,
//! #     signature_url: &url::Url,
//! #     config: DalamudConfig,
//! #     events: &SetupEvents,
//! #     cancel: &CancellationToken,
//! # ) -> apogee_addons::Result<()> {
//! let manifest = addons.fetch_manifest(manifest_url, signature_url, cancel).await?;
//! addons.apply_setup(&manifest, prefix, cancel, events).await?;
//!
//! if let Some(dalamud) = addons.dalamud(&manifest, config, events) {
//!     let enabled: [&dyn Injectable; 1] = [&dalamud];
//!     addons.ensure_injectables(&enabled, prefix, cancel, events).await;
//!     let prepared = addons.prepare_launch(&enabled, plan, events);
//!
//!     // The companion that became the program the launch spawns, if one did.
//!     let redirector: Option<String> = prepared.redirected_by;
//! }
//! # Ok(())
//! # }
//! ```

use std::path::PathBuf;
use std::time::SystemTime;

use async_trait::async_trait;
use thiserror::Error;

use apogee_fetch::{FetchError, Fetcher};
use apogee_runtime::{LaunchPlan, Prefix, Runtime};
use url::Url;

use crate::launch::Preparation;
use crate::setup::SetupReport;

pub mod backup;
pub mod dalamud;
pub mod external;
pub mod launch;
pub mod manifest;
pub mod setup;

#[cfg(test)]
mod tests;

pub use backup::{BackupError, Selection};

// What is re-exported here is what a consumer imports from the crate root. The rest keeps its module
// path and nothing else: a name reachable at two paths that nobody spells at either is two things to
// keep working rather than one.
pub use dalamud::{ClientLanguage, Dalamud, DalamudConfig, DalamudPaths, LoadEvidence};
pub use external::{
    AddonEvent, AddonEvents, AddonOutcome, AddonReport, AddonSession, ExternalAddon, GameContext,
    Outcome, RunIn, Trigger,
};
pub use launch::{Contribution, LaunchEdit, Redirect};
pub use manifest::{ComponentManifest, ManifestError, VerifiedManifest};
pub use setup::{SetupEvent, SetupEvents, SetupState};

/// Crate result over [`AddonError`].
pub type Result<T> = std::result::Result<T, AddonError>;

/// How well a companion is supported here.
///
/// # Examples
///
/// ```
/// use apogee_addons::SupportTier;
///
/// assert_eq!(SupportTier::FirstClass.note(), None);
///
/// let tier = SupportTier::BestEffort { note: "no controller input".to_owned() };
/// assert_eq!(tier.note(), Some("no controller input"));
/// assert_eq!(tier.to_string(), "best effort");
/// ```
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum SupportTier {
    /// It works here as well as it works anywhere.
    FirstClass,
    /// It works with a caveat, stated in `note` and shown before anything is fetched.
    BestEffort {
        /// What being best-effort costs, in the user's terms.
        note: String,
    },
}

impl SupportTier {
    /// What the tier costs, or `None` for a first-class companion, which has nothing to warn about.
    #[must_use]
    pub fn note(&self) -> Option<&str> {
        match self {
            Self::FirstClass => None,
            Self::BestEffort { note } => Some(note),
        }
    }
}

impl std::fmt::Display for SupportTier {
    // The tier and not its note. The note is shown to the user on its own event before anything is
    // fetched, and repeating a paragraph of it inside a one-line failure buries the failure.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::FirstClass => "first class",
            Self::BestEffort { .. } => "best effort",
        })
    }
}

/// Prefix-setup and companion failures.
///
/// # Examples
///
/// ```
/// use apogee_addons::AddonError;
/// use apogee_fetch::FetchError;
/// use std::path::Path;
///
/// let err = AddonError::from_fetch(
///     FetchError::LengthMismatch { expected: 10, got: 9 },
///     "dalamud",
///     Path::new("/tmp/latest.zip"),
/// );
///
/// assert_eq!(err.chain(), "download failed: length mismatch: expected 10, got 9");
/// assert!(!err.is_cancellation());
/// ```
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum AddonError {
    /// A download did not arrive.
    // Deliberately no `#[from]`. The conversion it generates would map every fetch failure onto this
    // arm, including `FetchError::FileVerifyFailed`, which has a typed home of its own below; an
    // unwritten `?` would flatten it into "download failed". Every caller goes through `from_fetch`.
    #[error("download failed")]
    Download(#[source] FetchError),
    /// The disk filled while a download was being written.
    ///
    /// Its own arm rather than a [`Download`](Self::Download) with the reason buried in the chain,
    /// because it is the one download failure the user can act on directly and the only one where
    /// retrying without doing anything is pointless. Names the path the filesystem refused, which is
    /// the part that says which volume is full.
    #[error("{what}: out of disk space at {path:?}")]
    #[non_exhaustive]
    OutOfSpace {
        /// What was being set up.
        what: String,
        /// The file the filesystem would not make room for.
        path: PathBuf,
        /// The `ENOSPC` the filesystem raised. The [`FetchError`] it arrived in held this same path
        /// and nothing else besides, so the pair is carried rather than the wrapper.
        #[source]
        source: std::io::Error,
    },
    /// A download was described in a way the fetcher will not accept.
    #[error("invalid download request")]
    Spec(#[from] apogee_fetch::SpecError),
    /// The signed catalog was refused. See [`ManifestError`] for which way.
    // Transparent, because the reason is the inner variant: an outer sentence over all of them could
    // only be vague enough to fit a schema slip and a forged signature at once, which reads as
    // tampering either way.
    #[error(transparent)]
    Manifest(#[from] ManifestError),
    /// Bytes that arrived intact and are not the bytes they were published as.
    ///
    /// Retrying fetches the same wrong file. Names the file, because a component is a tree of them.
    #[error(
        "{what}: {file:?} is not the bytes it was published as (expected {expected}, got {got})"
    )]
    #[non_exhaustive]
    IntegrityMismatch {
        /// What was being set up.
        what: String,
        /// The file whose bytes did not match.
        file: PathBuf,
        /// The digest the publisher named.
        expected: String,
        /// The digest the bytes actually have.
        got: String,
    },
    /// A filesystem step failed.
    // The path is a field rather than something folded into the message, because an `io::Error`
    // carries a kind and no path: folding one in means building a second error to hold the string
    // and dropping the one the filesystem raised.
    #[error("{what}: could not {step} at {path:?}")]
    #[non_exhaustive]
    Io {
        /// What was being set up.
        what: String,
        /// Which part of it, as a verb phrase ("make a staging directory").
        step: &'static str,
        /// What it was working on.
        path: PathBuf,
        /// The failure the filesystem raised.
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },
    /// An archive did not become the files it was meant to.
    ///
    /// Its own variant rather than an I/O failure: the bytes already matched their pin, so what is
    /// wrong is the archive's shape or the layout declared for it, and retrying fixes neither.
    #[error("{what}: the archive did not unpack")]
    #[non_exhaustive]
    Unpack {
        /// What was being set up.
        what: String,
        /// The failure the extractor raised.
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },
    /// An archive that unpacked and produced nothing.
    ///
    /// Separate from [`Self::Unpack`]: extraction succeeded and the layout declared for the archive
    /// selected none of what it held, so there is no underlying failure to carry.
    #[error("{what}: the archive that was served held nothing under the layout declared for it")]
    #[non_exhaustive]
    EmptyArchive {
        /// What was being set up.
        what: String,
    },
    /// A distribution pointer the catalog carries that the endpoints around it cannot be derived
    /// from. Names the pointer, because that is the row somebody has to correct.
    #[error("{injectable}: {pointer} is not a pointer its other endpoints can be derived from")]
    #[non_exhaustive]
    BadDistribution {
        /// The companion whose row carries it.
        injectable: String,
        /// The pointer as published.
        pointer: Url,
    },
    /// A companion could not be put into the game.
    #[error("injection of {injectable} failed ({tier} tier)")]
    Inject {
        /// The companion.
        injectable: String,
        /// How well it is supported here, so a best-effort failure reads as one.
        tier: SupportTier,
        /// What went wrong underneath.
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },
    /// Two companions each wanted to become the program the launch spawns, and a launch spawns one.
    ///
    /// No `source`: nothing underneath went wrong. Both composed their invocation correctly and the
    /// launch has room for one of them.
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
    /// A distribution answered with something this launcher cannot read.
    ///
    /// Its own variant rather than a download failure: the bytes arrived, they are just not the
    /// shape the endpoint promises, which is an upstream change rather than a network problem.
    #[error("{injectable}'s distribution answered with something this launcher cannot read")]
    #[non_exhaustive]
    Distribution {
        /// The companion whose distribution was read.
        injectable: String,
        /// What could not be read.
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },
    /// One of a verb's ops raised.
    #[error("verb {verb} failed")]
    #[non_exhaustive]
    VerbFailed {
        /// The verb, by the name the manifest gives it.
        verb: String,
        /// What the op raised.
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },
    /// Every op a verb declares ran and something it promised is still not there.
    ///
    /// Separate from [`Self::VerbFailed`]: nothing raised, so what there is to say is the path that
    /// was promised.
    #[error("verb {verb} finished without producing {missing:?}")]
    #[non_exhaustive]
    VerbIncomplete {
        /// The verb, by the name the manifest gives it.
        verb: String,
        /// A path the verb declared it would produce, that does not exist.
        missing: PathBuf,
    },
    /// An external addon entry that cannot be run as written.
    #[error("addon {index} ({program:?}) cannot be run: {reason}")]
    #[non_exhaustive]
    InvalidAddon {
        /// The program the entry names.
        program: PathBuf,
        /// Its position in the configured list, since two entries may name the same program.
        index: usize,
        /// Why it was refused.
        reason: &'static str,
    },
    /// An external addon asked to run inside the prefix, and this launch has none.
    #[error("{program:?} runs inside a prefix, but this launch has no prefix")]
    #[non_exhaustive]
    PrefixRequired {
        /// The program the entry names.
        program: PathBuf,
    },
    /// An imported addon entry uses a field this launcher does not implement.
    #[error("{program:?} asks for {field:?}, which this launcher does not support")]
    #[non_exhaustive]
    UnsupportedField {
        /// The program the entry names.
        program: PathBuf,
        /// The field, as the entry spells it.
        field: String,
    },
    /// An external addon could not be started.
    #[error("failed to start {program:?}")]
    #[non_exhaustive]
    ExternalSpawn {
        /// The program that did not start.
        program: PathBuf,
        // Boxed because the runtime's own taxonomy is wide, and this type is carried in the error
        // half of results all over this crate.
        /// What the runtime raised.
        #[source]
        source: Box<apogee_runtime::RuntimeError>,
    },
    /// A backup, restore or prune was refused. See [`BackupError`] for which way.
    // Transparent for the same reason as `Manifest`, and one more: this arm carries all three of
    // capture, restore and pruning, so any outer sentence naming one is wrong about the other two.
    #[error(transparent)]
    Backup(#[from] BackupError),
    /// The cancellation token fired, so the work stopped where it was.
    ///
    /// Its own variant rather than a per-step failure: a caller counts what failed to decide whether
    /// it did what was asked, and a run somebody stopped on purpose has nothing to count.
    #[error("cancelled")]
    Cancelled,
    /// Something this build cannot do, on this platform or at all.
    #[error("unsupported: {what}")]
    #[non_exhaustive]
    Unsupported {
        /// What is not supported.
        what: &'static str,
    },
}

impl AddonError {
    /// A fetch failure in this crate's taxonomy, with `FileVerifyFailed` routed to
    /// [`Self::IntegrityMismatch`], a full disk to [`Self::OutOfSpace`], and everything else to
    /// [`Self::Download`].
    ///
    /// `what` names what was being fetched and `file` where it landed. A named conversion rather
    /// than a `From` because of both: a `From` cannot be told either, and it would put the
    /// flattening one unwritten `?` away.
    ///
    /// # Examples
    ///
    /// ```
    /// use apogee_addons::AddonError;
    /// use apogee_fetch::FetchError;
    /// use std::path::Path;
    ///
    /// let raised = FetchError::FileVerifyFailed { expected: "aa".to_owned(), got: "bb".to_owned() };
    /// let err = AddonError::from_fetch(raised, "dalamud", Path::new("/tmp/latest.zip"));
    /// assert!(matches!(err, AddonError::IntegrityMismatch { .. }));
    ///
    /// let full = FetchError::Io {
    ///     path: "/tmp/latest.zip.part".into(),
    ///     source: std::io::ErrorKind::StorageFull.into(),
    /// };
    /// let err = AddonError::from_fetch(full, "dalamud", Path::new("/tmp/latest.zip"));
    /// assert!(matches!(err, AddonError::OutOfSpace { .. }));
    /// ```
    #[must_use]
    pub fn from_fetch(source: FetchError, what: &str, file: &std::path::Path) -> Self {
        match source {
            // The bytes arrived and are not the bytes that were promised, which is not a download
            // problem: retrying fetches the same wrong file.
            FetchError::FileVerifyFailed { expected, got } => Self::IntegrityMismatch {
                what: what.to_owned(),
                file: file.to_path_buf(),
                expected,
                got,
            },
            // The path here is fetch's, the `.part` the reservation failed on, rather than `file`:
            // the published destination is not what the filesystem refused.
            other => match other.into_out_of_space() {
                Ok((path, source)) => Self::OutOfSpace {
                    what: what.to_owned(),
                    path,
                    source,
                },
                Err(other) => Self::Download(other),
            },
        }
    }

    /// This failure and its causes as one line, joined by `": "`.
    ///
    /// What a caller should render. The outer message is routinely the least specific part of a
    /// chain ("could not stage a download" over "no space left on device"), and every seam this
    /// crate reports through carries a `String` rather than the error, so a caller with only
    /// `Display` has already lost the useful half.
    ///
    /// # Examples
    ///
    /// ```
    /// use apogee_addons::AddonError;
    ///
    /// let err = AddonError::Cancelled;
    /// assert_eq!(err.chain(), "cancelled");
    /// ```
    #[must_use]
    pub fn chain(&self) -> String {
        chain_of(self)
    }

    /// Whether this is the work stopping because it was asked to, rather than something going wrong.
    ///
    /// Answered here rather than by each consumer, because a stop reaches this taxonomy two ways:
    /// the setup pass ends its own run as [`Self::Cancelled`], and a download the token interrupted
    /// arrives spelled as the fetcher's cancellation, since the catalog is fetched before that loop
    /// begins. A caller that restates the list will miss the second one.
    ///
    /// # Examples
    ///
    /// ```
    /// use apogee_addons::AddonError;
    /// use apogee_fetch::FetchError;
    ///
    /// assert!(AddonError::Cancelled.is_cancellation());
    /// assert!(AddonError::Download(FetchError::Cancelled).is_cancellation());
    /// ```
    #[must_use]
    pub const fn is_cancellation(&self) -> bool {
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

/// An error and its causes as one line, for the seams that report another crate's failure as a
/// `String`.
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
/// One method installs and one contributes to the launch, which is the whole seam: the launcher
/// iterates whatever is enabled and never learns what any of them are. There is deliberately no
/// attach-to-a-running-process half. The only shape that wanted one was a loader taking the resolved
/// game pid, and nothing here is that shape: a loader wraps the launch, and anything built on top of
/// one is its plugin rather than a second injector.
#[async_trait]
pub trait Injectable: Send + Sync {
    /// The name it is recorded and reported under.
    fn name(&self) -> &str;

    /// How well it works here, and what that costs when it is not first class.
    fn support_tier(&self) -> SupportTier;

    /// Install or update it, and say anything the user should know before the game starts.
    ///
    /// `prefix` is what it will run against, so this is also where a companion states what the
    /// runner in front of it costs.
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

    /// What to add to the launch before it is spawned.
    ///
    /// `plan` is the launch as the injectables before it left it, to read the program and the prefix
    /// from. It is read-only: the [`Contribution`] is composed and handed back, so a companion whose
    /// own work fails partway through contributes nothing rather than the half it had written.
    ///
    /// A companion that finds itself inapplicable (not installed, built for another game version)
    /// says so on `events` and returns [`Contribution::Declined`]. Failing here would fail a launch
    /// that is otherwise fine.
    ///
    /// Redirecting the program is the one contribution a launch has room for once. A second
    /// [`Redirect`] in the same pass is refused whole by [`Addons::prepare_launch`], so an
    /// implementor composes its own invocation without checking what ran before it.
    ///
    /// # Errors
    /// Whatever the companion raises while composing its invocation.
    fn prepare_launch(&self, plan: &LaunchPlan, events: &SetupEvents) -> Result<Contribution>;

    /// What to watch for proof that this companion came up inside the game, if it leaves any.
    ///
    /// `since` is when the launch began: a companion writes its proof into a file that outlives the
    /// session, so only a write after that point belongs to this launch. Asked while the companion
    /// is still here, because it is dropped once the launch is composed and the proof lands seconds
    /// later, so what comes back owns everything it needs and a caller can spawn it and forget it.
    ///
    /// Defaults to `None`: a companion that leaves no trace of loading is not a companion that
    /// failed to, and a launcher with nothing to watch says nothing rather than reporting an absence.
    fn load_evidence(&self, since: SystemTime) -> Option<LoadEvidence> {
        let _ = since;
        None
    }
}

/// Where the companion layer keeps what it installs outside a prefix.
///
/// One root rather than a field per consumer. Everything under it is re-derivable (the last verified
/// copy of the signed catalog, and an injectable's own versioned trees), so it is one directory to
/// point somewhere else and one to delete.
///
/// # Examples
///
/// ```
/// use apogee_addons::AddonPaths;
///
/// let paths = AddonPaths::new("/home/user/.local/share/apogee/addons");
/// assert!(paths.catalog_cache().ends_with(".catalog"));
/// ```
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

/// The companion layer.
///
/// A cheap handle: clone it to share. Every field it holds is itself a handle or a path.
#[derive(Debug, Clone)]
pub struct Addons {
    runtime: Runtime,
    fetcher: Fetcher,
    paths: AddonPaths,
}

impl Addons {
    /// Construct over the runtime, fetcher, and paths.
    #[must_use]
    pub const fn new(runtime: Runtime, fetcher: Fetcher, paths: AddonPaths) -> Self {
        Self {
            runtime,
            fetcher,
            paths,
        }
    }

    /// Fetch the signed component manifest, verify it against the compiled-in keys, and publish it
    /// to the catalog cache.
    ///
    /// Taken per operation rather than held on this handle: it is the thing that changes without a
    /// release, so a long-lived launcher process caching one would keep serving yesterday's rows.
    ///
    /// # Errors
    /// [`AddonError::Spec`] if either URL cannot be turned into a download, [`AddonError::Download`]
    /// if either file cannot be fetched, [`AddonError::Io`] if the cache directory cannot be staged
    /// or published to, or [`AddonError::Manifest`] if the signature verifies against none of the
    /// compiled-in keys or the body violates the schema.
    ///
    /// # Examples
    ///
    /// ```
    /// # use apogee_addons::Addons;
    /// # use tokio_util::sync::CancellationToken;
    /// # async fn demo(addons: &Addons, manifest: &url::Url, signature: &url::Url)
    /// #     -> apogee_addons::Result<()> {
    /// let cancel = CancellationToken::new();
    /// let verified = addons.fetch_manifest(manifest, signature, &cancel).await?;
    ///
    /// // Every verb states why it exists, so a list of them is reviewable.
    /// let reasons: Vec<(&str, &str)> = verified
    ///     .rows()
    ///     .verbs
    ///     .iter()
    ///     .map(|verb| (verb.name.as_str(), verb.reason.as_str()))
    ///     .collect();
    /// # Ok(())
    /// # }
    /// ```
    pub async fn fetch_manifest(
        &self,
        manifest_url: &url::Url,
        signature_url: &url::Url,
        cancel: &tokio_util::sync::CancellationToken,
    ) -> Result<VerifiedManifest> {
        setup::fetch_manifest(
            &self.fetcher,
            manifest_url,
            signature_url,
            &self.paths.catalog_cache(),
            manifest::default_keys(),
            cancel,
        )
        .await
    }

    /// The same fetch, verified against `keys` instead of the compiled-in ones, so a test can drive
    /// the whole download-verify-publish path with signatures it can produce.
    ///
    /// A slice rather than one key for the same reason the shipping path takes one: an overlap
    /// window is only real if it is exercised through the path a launch takes.
    ///
    /// Behind the `testing` feature, so a shipping build cannot fetch a manifest trusted against
    /// anything but the keys compiled into it.
    ///
    /// # Errors
    /// As [`Self::fetch_manifest`].
    #[cfg(feature = "testing")]
    pub async fn fetch_manifest_for_testing(
        &self,
        manifest_url: &url::Url,
        signature_url: &url::Url,
        keys: &[[u8; 32]],
        cancel: &tokio_util::sync::CancellationToken,
    ) -> Result<VerifiedManifest> {
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

    /// The last manifest a fetch published, re-verified before it is returned, or `None` if none has
    /// been fetched yet.
    ///
    /// Separate from [`Self::fetch_manifest`] rather than folded in as a fallback, because whether a
    /// stale manifest beats none depends on the caller: a launch would rather apply yesterday's
    /// prefix setup than none, and a command the user just typed would rather say it could not reach
    /// the catalog.
    ///
    /// # Errors
    /// [`AddonError::Manifest`] if a cached copy is present and no longer verifies, which is a
    /// corrupt cache rather than an absent one.
    pub async fn cached_manifest(&self) -> Result<Option<VerifiedManifest>> {
        setup::cached_manifest(&self.paths.catalog_cache(), manifest::default_keys()).await
    }

    /// The same read, verified against `keys`, so a test can read back what a test-key fetch
    /// published. Behind the `testing` feature.
    ///
    /// # Errors
    /// As [`Self::cached_manifest`].
    #[cfg(feature = "testing")]
    pub async fn cached_manifest_for_testing(
        &self,
        keys: &[[u8; 32]],
    ) -> Result<Option<VerifiedManifest>> {
        setup::cached_manifest(&self.paths.catalog_cache(), keys).await
    }

    /// Apply every prefix-setup verb the manifest defines that `prefix` is missing.
    ///
    /// Idempotent: a verb the prefix already records is left alone, and a verb whose effect has since
    /// gone is applied again. Nothing selects which verbs run, because a verb is hygiene rather than
    /// a feature: the published list *is* the setup.
    ///
    /// # Errors
    /// [`AddonError::Io`] if the prefix's own record cannot be read, or [`AddonError::Cancelled`] if
    /// the token fired. A single verb failing is in the returned [`SetupReport`] rather than in the
    /// error.
    pub async fn apply_setup(
        &self,
        manifest: &VerifiedManifest,
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
    /// The decision [`Self::apply_setup`] acts on, taken without acting on it, so a caller can report
    /// what a prefix is missing without setting it up. A verb whose effect has gone is missing
    /// however the prefix's record reads.
    ///
    /// # Errors
    /// [`AddonError::Io`] if the prefix's own record cannot be read, which is the same refusal
    /// [`Self::apply_setup`] makes: with no record there is no telling setup that is needed from
    /// setup that is not.
    ///
    /// # Examples
    ///
    /// ```
    /// # use apogee_addons::{Addons, VerifiedManifest};
    /// # use apogee_runtime::Prefix;
    /// # fn demo(addons: &Addons, manifest: &VerifiedManifest, prefix: &Prefix)
    /// #     -> apogee_addons::Result<()> {
    /// let missing: Vec<String> = addons.missing_setup(manifest, prefix)?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn missing_setup(
        &self,
        manifest: &VerifiedManifest,
        prefix: &Prefix,
    ) -> Result<Vec<String>> {
        setup::missing_verbs(manifest, prefix)
    }

    /// The Dalamud injectable behind the launch setting, or `None` when the manifest offers no row
    /// for it.
    ///
    /// `None` rather than a compiled-in fallback: the row is where the distribution endpoint and the
    /// tier note live, so a build with no row has nothing honest to say about either and must not
    /// reach goatcorp on a guess. The `None` is narrated on `events` here rather than left to the
    /// caller, since the user asked for this at a launch and is owed a reason it did not happen.
    #[must_use]
    pub fn dalamud(
        &self,
        manifest: &VerifiedManifest,
        config: DalamudConfig,
        events: &SetupEvents,
    ) -> Option<Dalamud> {
        let built = Dalamud::new(self.paths.dalamud(), self.fetcher.clone(), manifest, config);
        if built.is_none() {
            events.emit(SetupEvent::Failed {
                what: dalamud::DALAMUD.to_owned(),
                reason: "the catalog carries no row for it, so there is nowhere to fetch it from"
                    .to_owned(),
            });
        }
        built
    }

    /// Install or update each injectable, returning what failed.
    ///
    /// Never fails as a whole. An injectable that cannot be installed is reported on `events` and
    /// the launch goes ahead without it, because a companion is an addition to a launch rather than
    /// a precondition for one.
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

    /// Let each injectable contribute to `plan`, in order, and report what the pass came to.
    ///
    /// The same list and the same loop as [`Self::ensure_injectables`], so nothing about a launch
    /// knows which companion it is composing. Each is offered the launch as the ones before it left
    /// it, and what it hands back is applied here. One failing contributes nothing at all and the
    /// launch proceeds. [`Preparation::redirected_by`] names the companion that took the launch
    /// over, which is the one thing about this pass a caller cannot read back off the plan.
    ///
    /// A launch spawns one program, so the first companion to redirect it keeps it and a second is
    /// refused with [`AddonError::LaunchAlreadyRedirected`]. The refusal is of the whole
    /// contribution rather than of the redirect alone: a plan carrying one companion's environment
    /// and argv around another's program is a launch neither of them composed, which is worse than
    /// one companion cleanly absent.
    ///
    /// *First* wins, and what claims the slot is asking for a [`Redirect`] rather than changing the
    /// program to something new, so a companion that redirects a launch to the program it already
    /// names still holds it.
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

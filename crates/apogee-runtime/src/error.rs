//! The runner, prefix and launch error taxonomy.

use std::path::PathBuf;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use apogee_fetch::FetchError;

use crate::metadata::RunnerRef;

/// A runner, prefix or launch failure.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum RuntimeError {
    /// The catalog has no entry for the requested runner name and version.
    #[error("runner {name} {version} unavailable")]
    RunnerUnavailable {
        /// The runner name that was requested.
        name: String,
        /// The version that was requested.
        version: String,
    },
    /// The runner catalog could not be trusted or understood.
    #[error("runner catalog is not trustworthy")]
    Catalog(#[from] CatalogError),
    /// A download request this crate built was rejected by the fetcher.
    #[error("invalid download request")]
    Spec(#[from] apogee_fetch::SpecError),
    // Deliberately no `#[from]`. The conversion it generates would map every fetch failure onto this
    // arm, including the full disk that has a typed home of its own below; an unwritten `?` would
    // flatten it into "runner download failed". Every caller goes through `from_fetch`.
    /// A download did not arrive.
    #[error("runner download failed")]
    Download(#[source] FetchError),
    /// The disk filled while a runner, DXVK build or catalog was being written.
    ///
    /// Its own arm rather than a [`Download`](Self::Download) with the reason buried in the chain:
    /// a runner tarball is the one download here big enough to fill a volume, and it is the only
    /// failure the user can fix without touching the launcher. The path is what says whether the
    /// cache or the prefix is the full one. Carries the `ENOSPC` itself rather than the
    /// [`FetchError`] that wrapped it, giving it the same shape as [`Io`](Self::Io).
    #[error("out of disk space at {path:?}")]
    OutOfSpace {
        /// The path the filesystem refused to grow.
        path: PathBuf,
        /// The underlying out-of-space error.
        #[source]
        source: std::io::Error,
    },
    /// A filesystem operation failed.
    #[error("filesystem error at {path:?}")]
    Io {
        /// The path being read or written.
        path: PathBuf,
        /// The underlying error.
        #[source]
        source: std::io::Error,
    },
    /// An archive could not be unpacked.
    #[error("extract of {archive:?} failed")]
    Extract {
        /// The archive being unpacked.
        archive: PathBuf,
        /// The underlying error, which includes an entry that would escape the destination.
        #[source]
        source: std::io::Error,
    },
    /// A prefix setup step failed.
    ///
    /// A step stopped by a cancellation token carries [`StepCancelled`] as its source, so an
    /// interrupted step and a broken one share this variant and are still told apart by type.
    #[error("prefix init failed at {step:?}")]
    PrefixInit {
        /// The step that failed.
        step: SetupStep,
        /// The underlying error.
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },
    /// A prefix's recorded metadata is unreadable or corrupt.
    #[error("prefix metadata at {path:?} is unreadable or corrupt")]
    PrefixJson {
        /// The metadata file that could not be read.
        path: PathBuf,
        /// The underlying deserialization error.
        #[source]
        source: serde_json::Error,
    },
    /// A process this crate started, or waited on, could not be.
    #[error("spawn of {program} failed")]
    Spawn {
        /// Whatever was handed to the spawn.
        ///
        /// The runner on the two paths that spawn one, a launch through a prefix and the
        /// prefix-wide stop; a companion, a program run inside a prefix, or the game itself on
        /// Windows, everywhere else.
        program: String,
        /// The underlying error.
        #[source]
        source: std::io::Error,
    },
    /// A program run inside a prefix did not finish.
    #[error("{program} did not finish inside the prefix: {reason}")]
    InPrefixIncomplete {
        /// The program that was run.
        program: String,
        /// Why it did not finish, which is [`is_cancellation`](Self::is_cancellation)'s oracle for
        /// this variant.
        reason: &'static str,
    },
    /// A registry edit named a key outside the set this launcher will write.
    #[error("registry key {key:?} is not one this launcher will write: {reason}")]
    RegistryKey {
        /// The key that was refused.
        key: String,
        /// Why it was refused.
        reason: &'static str,
    },
    /// A launch plan was missing something the launch needs, or contradicted itself.
    #[error("invalid launch plan: {reason}")]
    InvalidLaunchPlan {
        /// What was wrong with the plan.
        reason: &'static str,
    },
    /// The game never appeared in the process table inside the time budget.
    ///
    /// Names what was scanned for, because the scan matches on the kernel-visible process name and
    /// the answer to "why did nothing match" is usually that name rather than the waiting. The
    /// kernel caps that name at 15 bytes and the runner renames its loader to the executable's base
    /// name, so a launch that resolves nothing is diagnosed by comparing the base name against what
    /// the prefix actually started, and neither is recoverable from a duration.
    #[error("game process {program:?} not found in {prefix:?} after {waited:?}")]
    GameProcessNotFound {
        /// The executable base name the `/proc` scan matched on.
        program: String,
        /// The prefix the scan narrowed to, by each process's own `WINEPREFIX`.
        prefix: PathBuf,
        /// How long the scan ran before giving up.
        waited: Duration,
    },
    /// The wait for the game process ended because the run was stopped.
    ///
    /// Its own variant rather than a flag on [`GameProcessNotFound`](Self::GameProcessNotFound):
    /// nothing was found either way, but one is a launch that failed and the other is a user who
    /// changed their mind, and only the first is worth reporting.
    #[error("the wait for game process {program:?} was stopped after {waited:?}")]
    GameWaitCancelled {
        /// The executable base name the `/proc` scan was matching on.
        program: String,
        /// How long the scan ran before it was stopped.
        waited: Duration,
    },
    /// Supervision of a running game ended before the process was reaped, so whether it is still
    /// running is no longer known.
    ///
    /// Raised where a launch is supervised by the child handle rather than by the process table,
    /// and reachable only when the async runtime that owns the supervision is itself going away.
    #[error("supervision of {program} ended before it exited")]
    SupervisionLost {
        /// The program that was being supervised.
        program: String,
    },
    /// A path could not be translated between unix and windows form.
    #[error("path mapping failed for {path:?}: {reason}")]
    PathMapping {
        /// The path that could not be translated.
        path: PathBuf,
        /// Why translation failed.
        reason: &'static str,
    },
    /// A tool this crate has to run was not found on the host.
    #[error("missing host tool: {tool:?}")]
    MissingHostTool {
        /// The tool that was missing.
        tool: HostTool,
    },
    /// The operation does not exist on this target.
    #[error("unsupported: {what}")]
    Unsupported {
        /// What was attempted.
        what: &'static str,
    },
}

/// The `reason` an [`RuntimeError::InPrefixIncomplete`] carries when the cancellation token, rather
/// than the time budget, ended the run.
// Named once and read once: the alternative is the same word spelled in two crates, where a typo in
// either silently stops a stopped run from reading as one.
pub(crate) const CANCELLED_REASON: &str = "cancelled";

/// The source a prefix setup step carries when a cancellation token ended it.
///
/// Keeps a stopped step and a broken one in one [`RuntimeError::PrefixInit`] variant, told apart by
/// downcasting rather than by parsing a message.
#[derive(Debug, Error)]
#[error("the step was stopped before it finished")]
pub struct StepCancelled;

impl RuntimeError {
    /// Convert a fetch failure into this taxonomy.
    ///
    /// A full disk is routed to [`OutOfSpace`](Self::OutOfSpace) and everything else to
    /// [`Download`](Self::Download). A named conversion rather than a `From`, so the routing cannot
    /// be skipped by an unwritten `?`. Which failures count as a full disk is
    /// [`FetchError::into_out_of_space`]'s to answer, so this stays correct if the fetcher ever
    /// raises `ENOSPC` from a second place.
    ///
    /// # Examples
    ///
    /// ```
    /// use apogee_fetch::FetchError;
    /// use apogee_runtime::RuntimeError;
    ///
    /// let full = FetchError::Io {
    ///     path: "/cache/GE-Proton.tar.gz.part".into(),
    ///     source: std::io::ErrorKind::StorageFull.into(),
    /// };
    /// assert!(matches!(RuntimeError::from_fetch(full), RuntimeError::OutOfSpace { .. }));
    /// assert!(matches!(
    ///     RuntimeError::from_fetch(FetchError::Cancelled),
    ///     RuntimeError::Download(FetchError::Cancelled),
    /// ));
    /// ```
    #[must_use]
    pub fn from_fetch(source: FetchError) -> Self {
        match source.into_out_of_space() {
            Ok((path, source)) => Self::OutOfSpace { path, source },
            Err(other) => Self::Download(other),
        }
    }

    /// Whether this is the run stopping because it was asked to, rather than something going wrong.
    ///
    /// Cancellation reaches this taxonomy by four routes: a runner download the token stopped, a
    /// `wineboot` it interrupted, a setup program killed mid-run, and a wait for the game process
    /// that gave up because it was asked to. Answered here, beside the code that constructs them,
    /// so a consumer telling "the user pressed Ctrl-C" from "the prefix is broken" does not have to
    /// know all four and be re-edited when a fifth appears.
    #[must_use]
    pub fn is_cancellation(&self) -> bool {
        match self {
            Self::Download(FetchError::Cancelled) | Self::GameWaitCancelled { .. } => true,
            Self::InPrefixIncomplete { reason, .. } => *reason == CANCELLED_REASON,
            Self::PrefixInit { source, .. } => source.downcast_ref::<StepCancelled>().is_some(),
            _ => false,
        }
    }
}

/// Why a signed runner catalog was rejected.
///
/// Kept separate from [`RuntimeError`], which wraps it, so the pure parser has a total taxonomy of
/// its own that is fuzzable and builds on every target.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum CatalogError {
    /// The manifest is not valid JSON, or violates the schema.
    #[error("manifest is not valid JSON or violates the schema")]
    Malformed(#[source] serde_json::Error),
    /// No trusted key verified the manifest signature.
    #[error("manifest signature did not verify against any trusted key")]
    BadSignature,
    /// A key compiled into this build is not a point on the curve, so it can admit nothing.
    ///
    /// A build problem, and the one failure on this path the hosted file cannot be the cause of.
    /// Reporting it as a [`BadSignature`](Self::BadSignature) would send whoever reads it to check
    /// the one thing that is not wrong.
    #[error("the trusted key at position {position} in this build is not a usable ed25519 key")]
    #[non_exhaustive]
    TrustedKeyUnusable {
        /// The key's index in the trusted-key list, which is the only part of the message that
        /// locates the typo.
        position: usize,
    },
    /// The manifest declares a version this build does not implement.
    #[error("unsupported manifest version {found} (expected {expected})")]
    UnsupportedVersion {
        /// The version the manifest declared.
        found: u32,
        /// The version this build implements,
        /// [`CATALOG_MANIFEST_VERSION`](crate::CATALOG_MANIFEST_VERSION).
        expected: u32,
    },
    /// A runner entry names a kind this build does not know how to launch.
    #[error("unknown runner kind {kind:?}")]
    UnknownRunnerKind {
        /// The unrecognized kind, as spelled in the manifest.
        kind: String,
    },
    /// An entry names an archive format this build cannot unpack.
    #[error("unknown archive format {format:?}")]
    UnknownArchiveFormat {
        /// The unrecognized format, as spelled in the manifest.
        format: String,
    },
    /// An entry carries no content hash of 32 hex-encoded bytes under either hash key.
    #[error("{name} {version}: no blake3 or sha256 pin of 32 hex bytes")]
    BadPin {
        /// The entry's name.
        name: String,
        /// The entry's version.
        version: String,
    },
    /// An entry's download location is not a valid absolute url.
    #[error("{name} {version}: not a valid absolute url")]
    BadUrl {
        /// The entry's name.
        name: String,
        /// The entry's version.
        version: String,
    },
}

/// A prefix setup step, recorded in the prefix's own history and named in
/// [`RuntimeError::PrefixInit`].
///
/// Serializes as its snake_case name (`wineboot_init`, `dxvk_install`, and so on).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum SetupStep {
    /// `wineboot -i` on a brand-new prefix.
    WinebootInit,
    /// `wineboot -u`, a non-destructive update that regenerates missing prefix structure.
    WinebootUpdate,
    /// A DXVK install into the prefix.
    DxvkInstall,
    /// A registry or configuration tweak.
    ApplyTweaks,
    /// A curated prefix-setup verb was applied, named by the record's detail.
    VerbApply,
    /// A companion component was installed into the prefix, named with its version by the record's
    /// detail.
    ComponentInstall,
}

/// A prefix health problem found by [`Runtime::check_prefix`](crate::Runtime::check_prefix).
///
/// Each variant carries what a targeted fix needs.
/// [`Runtime::repair_prefix`](crate::Runtime::repair_prefix) resolves the fixable ones without ever
/// recreating the prefix.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum HealthIssue {
    /// A core wine-prefix file or directory is missing.
    ///
    /// The fix re-runs `wineboot` to regenerate the skeleton, keeping user data.
    MissingSkeleton {
        /// The missing path.
        path: PathBuf,
    },
    /// A DOS drive symlink is absent or points at the wrong target.
    ///
    /// The fix rewrites the single symlink.
    DriveMapping {
        /// The drive letter.
        letter: char,
        /// The link target to restore.
        expected: PathBuf,
        /// What the link currently resolves to, or `None` if it is missing.
        found: Option<PathBuf>,
    },
    /// The prefix was built with a different runner than the profile now selects.
    ///
    /// Reconciling this is an explicit [`recreate_prefix`](crate::Runtime::recreate_prefix), not an
    /// in-place fix.
    RunnerMismatch {
        /// The runner the prefix records.
        recorded: RunnerRef,
        /// The runner now selected.
        expected: RunnerRef,
    },
    /// A DXVK DLL the prefix records as installed is missing.
    ///
    /// Replacing it needs the catalog, so the fix is to re-run the DXVK install rather than an
    /// in-place repair.
    MissingDxvkDll {
        /// The missing DLL's file name.
        dll: String,
        /// Where it was expected in the prefix.
        path: PathBuf,
    },
    /// The caller asked for the `dxvk-nvapi` companion and the prefix does not have it.
    ///
    /// Placing it needs the catalog, so the fix is the DXVK install, as above. Carries nothing,
    /// because nothing distinguishes one instance from another.
    // The only issue whose other half comes from outside the prefix. Every other one is drift
    // between the prefix and its own record, which is why the check needed nothing but the prefix
    // until this existed: a record can say what a prefix *has* and never what was wanted of it.
    MissingNvapi,
}

/// What the caller wanted of the prefix, for the half of the health check the prefix cannot answer
/// about itself.
///
/// The check's oracle is the prefix's own record, which can only ever say what a prefix *has*, so
/// whatever the caller asked for and never got is invisible to it and is handed in here.
// Kept to what this crate can both diagnose and see resolved: which runner a prefix should have is
// already its own record, and the setup a prefix should carry belongs to the layer above, which is
// why this is one field rather than a picture of a profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PrefixWants {
    /// Whether the caller asked for DXVK's `dxvk-nvapi` companion.
    pub nvapi: bool,
}

/// The outcome of a prefix health check: the drift found, if any.
#[derive(Debug, Clone, Default)]
pub struct PrefixHealth {
    /// Every detected problem, in check order. Empty means the prefix is healthy.
    pub issues: Vec<HealthIssue>,
}

impl PrefixHealth {
    /// Whether the prefix has no detected problems.
    #[must_use]
    pub fn is_healthy(&self) -> bool {
        self.issues.is_empty()
    }
}

/// A host-side tool this crate has to run, named by [`RuntimeError::MissingHostTool`].
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub enum HostTool {
    /// `wine`.
    Wine,
    /// The Steam client.
    Steam,
    /// `tar`.
    Tar,
    /// `umu-run`.
    Umu,
    /// `flatpak-spawn`, the only way a confined process starts a program outside its sandbox.
    ///
    /// It belongs to the runtime rather than to the application, so a build can be missing one
    /// (see [`Confinement`](crate::Confinement)).
    FlatpakSpawn,
    /// `gamescope`.
    ///
    /// Named only under confinement, where its absence is a build that does not ship one rather
    /// than a package the user chose not to install.
    Gamescope,
    /// `gamemoderun`, the shim that preloads the gamemode client into what it wraps.
    ///
    /// Named under confinement only, as [`Gamescope`](Self::Gamescope).
    Gamemode,
}

//! Runner / prefix / launch error taxonomy.

use std::path::PathBuf;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use apogee_fetch::FetchError;

use crate::metadata::RunnerRef;

/// Runner / prefix / launch failures.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum RuntimeError {
    #[error("runner {name} {version} unavailable")]
    RunnerUnavailable { name: String, version: String },
    #[error("runner catalog is not trustworthy")]
    Catalog(#[from] CatalogError),
    #[error("invalid download request")]
    Spec(#[from] apogee_fetch::SpecError),
    /// A download did not arrive.
    // Deliberately no `#[from]`. The conversion it generates would map every fetch failure onto this
    // arm, including the full disk that has a typed home of its own below; an unwritten `?` would
    // flatten it into "runner download failed". Every caller goes through `from_fetch`.
    #[error("runner download failed")]
    Download(#[source] FetchError),
    /// The disk filled while a runner, DXVK build, or catalog was being written.
    ///
    /// Its own arm rather than a [`Download`](Self::Download) with the reason buried in the chain: a
    /// runner tarball is the one download here big enough to fill a volume, and it is the only
    /// failure the user can fix without touching the launcher. Names the path the filesystem
    /// refused, which is what says whether the cache or the prefix is the full one.
    ///
    /// The source is the `ENOSPC` itself rather than the [`FetchError`] it came wrapped in, which
    /// holds this same path and nothing else besides. Same shape as [`Io`](Self::Io), so a consumer
    /// rendering a filesystem failure treats them alike.
    #[error("out of disk space at {path:?}")]
    OutOfSpace {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("filesystem error at {path:?}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("extract of {archive:?} failed")]
    Extract {
        archive: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("prefix init failed at {step:?}")]
    PrefixInit {
        step: SetupStep,
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },
    #[error("prefix metadata at {path:?} is unreadable or corrupt")]
    PrefixJson {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },
    #[error("spawn of {runner} failed")]
    Spawn {
        runner: String,
        #[source]
        source: std::io::Error,
    },
    #[error("{program} did not finish inside the prefix: {reason}")]
    InPrefixIncomplete {
        program: String,
        reason: &'static str,
    },
    #[error("registry key {key:?} is not one this launcher will write: {reason}")]
    RegistryKey { key: String, reason: &'static str },
    #[error("invalid launch plan: {reason}")]
    InvalidLaunchPlan { reason: &'static str },
    #[error("game process not found after {waited:?}")]
    GameProcessNotFound { waited: Duration },
    /// The wait for the game process to appear ended because the run was stopped. Its own variant
    /// rather than a flag on [`Self::GameProcessNotFound`]: nothing was found either way, but one is a
    /// launch that failed and the other is a user who changed their mind, and only the first is worth
    /// telling them about.
    #[error("the wait for the game process was stopped after {waited:?}")]
    GameWaitCancelled { waited: Duration },
    /// The supervision of a running game ended before the process was reaped, so whether it is still
    /// running is no longer known. Raised where a launch is supervised by the child handle rather than
    /// by the process table (Windows), and reachable only when the async runtime that owns the
    /// supervision is itself going away.
    #[error("supervision of {program} ended before it exited")]
    SupervisionLost { program: String },
    #[error("path mapping failed for {path:?}: {reason}")]
    PathMapping { path: PathBuf, reason: &'static str },
    #[error("missing host tool: {tool:?}")]
    MissingHostTool { tool: HostTool },
    #[error("unsupported: {what}")]
    Unsupported { what: &'static str },
}

/// The `reason` an [`RuntimeError::InPrefixIncomplete`] carries when the cancellation token, rather
/// than the time budget, ended the run. Named once and read once: the alternative is the same word
/// spelled in two crates, where a typo in either silently stops a stopped run from reading as one.
pub(crate) const CANCELLED_REASON: &str = "cancelled";

/// The source a prefix setup step carries when the cancellation token ended it, so a stopped
/// `wineboot` and a broken one stay one [`RuntimeError::PrefixInit`] variant and are still told apart
/// by a type rather than by parsing a message.
#[derive(Debug, Error)]
#[error("the step was stopped before it finished")]
pub struct StepCancelled;

impl RuntimeError {
    /// A fetch failure in this crate's taxonomy, with a full disk routed to [`Self::OutOfSpace`] and
    /// everything else to [`Self::Download`].
    ///
    /// A named conversion rather than a `From`, so the routing cannot be skipped by an unwritten
    /// `?`. Which failures are a full disk is [`FetchError::into_out_of_space`]'s to answer, so this
    /// stays correct if the fetcher ever raises `ENOSPC` from a second place.
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
    /// `wineboot` it interrupted, a setup program killed mid-run, and a wait for the game process that
    /// gave up because it was asked to. A consumer deciding between "the user pressed Ctrl-C" and "the
    /// prefix is broken" would otherwise have to know all four and be re-edited whenever a fifth
    /// appears, from a crate that cannot see them being added. Answered here, beside the code that
    /// constructs them.
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

/// Why a signed runner catalog was rejected. Kept separate so the pure parser (fuzzed,
/// cross-platform) has its own total taxonomy; [`RuntimeError`] wraps it via `#[from]`.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum CatalogError {
    #[error("manifest is not valid JSON or violates the schema")]
    Malformed(#[source] serde_json::Error),
    #[error("manifest signature did not verify against any trusted key")]
    BadSignature,
    /// A key compiled into this build is not a point on the curve, so it can admit nothing.
    ///
    /// A build problem, and the one failure on this path the hosted file cannot be the cause of.
    /// Reporting it as a bad signature would send whoever reads it to check the one thing that is
    /// not wrong.
    #[error("the trusted key at position {position} in this build is not a usable ed25519 key")]
    #[non_exhaustive]
    TrustedKeyUnusable {
        /// Its index in the key list, which is the only part of the message that locates the typo.
        position: usize,
    },
    #[error("unsupported manifest version {found} (expected {expected})")]
    UnsupportedVersion { found: u32, expected: u32 },
    #[error("unknown runner kind {kind:?}")]
    UnknownRunnerKind { kind: String },
    #[error("unknown archive format {format:?}")]
    UnknownArchiveFormat { format: String },
    #[error("{name} {version}: no blake3 or sha256 pin of 32 hex bytes")]
    BadPin { name: String, version: String },
    #[error("{name} {version}: not a valid absolute url")]
    BadUrl { name: String, version: String },
}

/// A prefix setup step, recorded in `prefix.json`'s history and named in [`RuntimeError::PrefixInit`].
/// Serializes as its snake_case name (`wineboot_init`, `dxvk_install`, …).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum SetupStep {
    /// `wineboot -i` on a brand-new prefix.
    WinebootInit,
    /// `wineboot -u`: a non-destructive update that regenerates missing prefix structure.
    WinebootUpdate,
    /// A DXVK install into the prefix (recorded once the environment matrix owns it).
    DxvkInstall,
    /// A registry or configuration tweak.
    ApplyTweaks,
    /// A curated prefix-setup verb was applied. `detail` names the verb.
    VerbApply,
    /// A companion component was installed into the prefix. `detail` names it and its version.
    ComponentInstall,
}

/// A prefix health problem found by [`Runtime::check_prefix`](crate::Runtime::check_prefix). Each
/// variant carries what a targeted fix needs; [`Runtime::repair_prefix`](crate::Runtime::repair_prefix)
/// resolves the fixable ones without ever recreating the prefix.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum HealthIssue {
    /// A core wine-prefix file or directory is missing (`drive_c`, `dosdevices`, `system.reg`). The
    /// fix re-runs `wineboot` to regenerate the skeleton, keeping user data.
    MissingSkeleton { path: PathBuf },
    /// A DOS drive symlink is absent or points at the wrong target. `expected` is the link target to
    /// restore; `found` is what it currently resolves to (or `None` if missing). The fix rewrites the
    /// single symlink.
    DriveMapping {
        letter: char,
        expected: PathBuf,
        found: Option<PathBuf>,
    },
    /// The prefix was built with a different runner than the profile now selects. Reconciling this is
    /// an explicit [`recreate`](crate::Runtime::recreate_prefix), not an in-place fix.
    RunnerMismatch {
        recorded: RunnerRef,
        expected: RunnerRef,
    },
    /// A DXVK DLL `prefix.json` records as installed is missing from the prefix. Reinstalling it needs
    /// the catalog, so the fix is to re-run the DXVK install, not an in-place repair.
    MissingDxvkDll { dll: String, path: PathBuf },
    /// The caller asked for the `dxvk-nvapi` companion and the prefix does not have it
    /// ([`PrefixWants::nvapi`](crate::PrefixWants)). Placing it needs the catalog, so the fix is the
    /// DXVK install, as above.
    ///
    /// The only issue whose other half comes from outside the prefix. Every other one is drift between
    /// the prefix and its own record, which is why the check needed nothing but the prefix until this
    /// existed: a record can say what a prefix *has* and never what was wanted of it. Carries nothing,
    /// because nothing distinguishes one instance from another; what resolves it is the catalog, which
    /// the caller holds.
    MissingNvapi,
}

/// What the caller wanted of the prefix, for the half of the health check the prefix cannot answer
/// about itself.
///
/// The check's oracle is `prefix.json`, and a record can only ever say what a prefix *has*. Whatever
/// the caller asked for and never got is invisible to it, so that half is handed in. Kept to what this
/// crate can both diagnose and see resolved: which runner a prefix should have is already its own
/// record, and the setup a prefix should carry belongs to the layer above (`apogee-addons`), which is
/// why this is one field rather than a picture of a profile.
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

/// A required host-side tool (for [`RuntimeError::MissingHostTool`]).
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub enum HostTool {
    Wine,
    Steam,
    Tar,
    Umu,
    /// `flatpak-spawn`, the only way a confined process starts a program outside its sandbox. It
    /// belongs to the runtime rather than to the application, so a build can be missing one
    /// ([`crate::Confinement`]).
    FlatpakSpawn,
    /// `gamescope`. Named only under confinement, where its absence is a build that does not ship
    /// one rather than a package the user chose not to install.
    Gamescope,
    /// `gamemoderun`, the shim that preloads the gamemode client into what it wraps. As
    /// [`Self::Gamescope`].
    Gamemode,
}

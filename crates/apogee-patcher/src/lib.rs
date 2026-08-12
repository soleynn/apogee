#![forbid(unsafe_code)]
//! Patch orchestration across download, apply, and repair.
//!
//! [`Patcher`] composes [`apogee_fetch`] (acquire) and [`apogee_zipatch`] (apply) into an install
//! pipeline: it turns the ordered pending patches `sqex-proto` reports into a verified, up-to-date
//! install. It holds no format or transport knowledge, only the sequencing between them: acquire
//! runs ahead through fetch's scheduler while apply consumes strictly in SE list order, nothing
//! unverified reaches the apply queue, and `.ver`/`.bck` advance only after a clean apply.
//!
//! Admission has two shapes because Square Enix hashes the two repo families differently. A game
//! patch carries per-block SHA1 in the patchlist, so fetch verifies it and returns a `VerifiedFile`.
//! A boot patch carries no hashes; fetch delivers its length-checked bytes under
//! [`apogee_fetch::Validator::External`], and the patcher's own ZiPatch chunk-CRC scan mints the
//! admission token before the file may join the apply queue. Either way, an unadmitted patch cannot
//! be applied.
//!
//! Repair verifies an install against its block index and re-fetches only the broken byte ranges,
//! pulling from local patch files on the first (trusted) attempt and over HTTP after, reconstructing
//! zero/empty regions with no fetch, and quarantining strays to a recycler rather than deleting them.
//!
//! Where the install tree is not writable by the user who launched, the apply runs in a separate
//! privileged process instead. [`Elevation`] decides when; the boundary itself, and everything that
//! crosses it, belongs to [`apogee_elevate`]. A worker that dies mid-apply arrives here as
//! [`PatchError::Worker`], a value the caller renders: nothing in this crate ends the launcher.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use apogee_fetch::{FetchError, Fetcher};

mod catalog;
mod elevated;
mod install;
mod job;
pub mod mods;
mod preflight;
mod progress;
mod recycler;
mod repair;
mod request;
mod store;

pub use catalog::{
    INDEX_CATALOG_MANIFEST_VERSION, INDEX_CATALOG_PUBLIC_KEY, IndexCatalog, IndexCatalogError,
    IndexEntry,
};
pub use elevated::{Elevation, probe_writable};
pub use job::Job;
pub use preflight::GameProbe;
pub use progress::PatchProgress;
// Re-exported because `PatchError::Worker` carries one and a caller that matches on it must be able
// to name it without depending on the boundary crate itself.
pub use apogee_elevate::WorkerErrorKind;
// Re-exported because `PatchProgress::Downloading` carries one: a consumer that reads the field must
// be able to name its type without depending on `apogee-fetch` itself.
pub use apogee_fetch::Recoveries;
pub use repair::{RepairOutcome, RepairedRepo};
pub use request::{
    IndexSource, InstallRequest, Installed, RepairPatchSource, RepairRepo, RepairRequest, SePatch,
};

/// Which game repository a patch operation targets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum Repo {
    Boot,
    Game,
    Expansion(u8),
}

impl Repo {
    /// Parse a repo label: `boot`, `game`, or `ex{n}` (expansion `n`, a `u8`). The one spelling,
    /// shared by the signed index catalog's rows and anything a caller lets a user name a repo by,
    /// so the two can never drift apart.
    #[must_use]
    pub fn from_label(label: &str) -> Option<Self> {
        match label {
            "boot" => Some(Self::Boot),
            "game" => Some(Self::Game),
            other => other
                .strip_prefix("ex")
                .and_then(|n| n.parse::<u8>().ok())
                .map(Self::Expansion),
        }
    }
}

/// Names one broken part for repair reporting: the repo-relative file and the byte offset of the run
/// that failed verification.
#[derive(Debug, Clone)]
pub struct PartRef {
    pub repo: Repo,
    pub path: PathBuf,
    pub offset: u64,
}

/// A disk pool checked during preflight.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SpacePool {
    PatchStore,
    GameRoot,
    /// The pools resolved onto one filesystem, so they were guarded once against their combined
    /// need.
    ///
    /// Its own variant rather than reporting whichever pool contributed more, because on a shared
    /// mount that choice is not information: both names point at the same disk, and the `needed`
    /// figure beside it is the sum, which is not a number either pool alone asked for. Naming a pool
    /// would invite a caller to show a per-directory breakdown that does not correspond to anything
    /// the user can act on separately.
    SharedFilesystem,
}

/// Preflight failures, surfaced through [`PatchError::Preflight`].
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum PreflightError {
    /// A pool is predicted to come up short, before a byte moves. This is an estimate derived from
    /// the patchlist lengths, not an observation: `needed` overestimates (patches delete as well as
    /// add) and `free` is a reading taken before the transfer. A disk that actually fills, including
    /// one this estimate cleared or that [`PatcherConfig::ignore_space`] skipped, arrives as
    /// [`PatchError::OutOfSpace`] instead.
    #[error("not enough space in {pool:?}: need {needed}, have {free}")]
    NotEnoughSpace {
        pool: SpacePool,
        needed: u64,
        free: u64,
    },
    /// The game is running in the install this operation targets, so nothing was touched.
    ///
    /// Asked of [`PatcherConfig::game_probe`] before an install or a repair does anything at all, and
    /// not skippable: [`PatcherConfig::ignore_space`] is about free space alone. The install is
    /// exactly as it was, so the operation re-runs once the client is closed.
    #[error("game is running")]
    GameRunning,
}

/// Patch orchestration failures.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum PatchError {
    #[error("preflight failed")]
    Preflight(#[from] PreflightError),
    #[error("patchlist entry {index}: {detail}")]
    Patchlist { index: u32, detail: String },
    /// The disk filled during the transfer: the other half of the space story, and the half that
    /// fires when the [`PreflightError::NotEnoughSpace`] estimate cleared the install or
    /// [`PatcherConfig::ignore_space`] skipped it. Separate from that variant rather than folded
    /// into it because this one is observed, not predicted, so it names the path the filesystem
    /// refused; a needed/free pair is not knowable once a write has already failed, and re-reading
    /// free space here would report whatever another process left behind a moment later.
    ///
    /// The source is the `ENOSPC` itself rather than the [`FetchError`] it came wrapped in, which
    /// holds this same path and nothing else besides.
    #[error("out of disk space at {path:?}")]
    OutOfSpace {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    /// A download failed for a reason with no typed home here, while acquiring patch `index` of
    /// `repo`'s chain: without those two, a failed 200-patch install reads as "acquire failed" and
    /// names no patch. Deliberately not `#[from]`: an unwritten `?` would flatten the arms that do
    /// have one, [`OutOfSpace`](Self::OutOfSpace) and [`Cancelled`](Self::Cancelled), back into
    /// "acquire failed". Every fetch failure in this crate is routed by hand.
    #[error("acquire failed for {repo:?} patch {index}")]
    Acquire {
        /// The repository whose chain was being acquired.
        repo: Repo,
        /// The failed patch's zero-based position in the install's acquisition order.
        index: u32,
        /// The download failure itself.
        #[source]
        source: FetchError,
    },
    #[error("{broken} broken part(s) in {repo:?}")]
    Verify {
        repo: Repo,
        broken: usize,
        first: PartRef,
    },
    #[error("apply failed")]
    Apply(#[from] apogee_zipatch::Error),
    #[error("boot patch {index} failed chunk-crc admission")]
    BootAdmission {
        index: u32,
        #[source]
        source: apogee_zipatch::Error,
    },
    #[error("i/o error on {path}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    /// The privileged apply failed, including by the worker process dying part way through it. The
    /// launcher is untouched, and because a version file advances only on a clean apply, the run is
    /// re-runnable.
    #[error("elevated worker failed: {kind:?}: {detail}")]
    Worker {
        /// What kind of failure it was.
        kind: WorkerErrorKind,
        /// The file it named, when it named one.
        failed_file: Option<PathBuf>,
        /// The rendered underlying error.
        detail: String,
    },
    #[error("index unavailable for {repo:?}")]
    IndexUnavailable {
        repo: Repo,
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },
    #[error("version cross-check failed for {repo:?}: index {index_version}, wanted {wanted}")]
    VersionCrossCheck {
        repo: Repo,
        index_version: String,
        wanted: String,
    },
    #[error("cancelled")]
    Cancelled,
}

/// Runtime configuration for a [`Patcher`]: the profile-independent settings the composition root
/// knows once. The per-profile game root travels with each [`InstallRequest`] instead.
#[derive(Debug, Clone)]
pub struct PatcherConfig {
    /// Where downloaded `.patch` files live (resumable, keepable); the patchlist URL path is
    /// mirrored beneath it.
    pub patch_store: PathBuf,
    /// Keep downloaded patches after a clean apply instead of removing them.
    pub keep_patches: bool,
    /// Skip the disk-space preflight (the escape hatch for a caller that knows better).
    pub ignore_space: bool,
    /// How many repair passes to attempt before giving up on a still-broken part (the reference's
    /// reattempt budget; clamped to at least one). The first pass may trust local patch files; every
    /// pass after re-fetches over HTTP.
    pub repair_reattempts: usize,
    /// Where the apply runs when the install tree is not writable by this process.
    pub elevation: Elevation,
    /// How to tell whether the game is running in the install being worked on. Consulted before
    /// every install and repair; see [`GameProbe`].
    pub game_probe: GameProbe,
}

/// The reference launcher's reattempt budget, adopted as the default repair pass count.
pub const DEFAULT_REPAIR_REATTEMPTS: usize = 5;

impl PatcherConfig {
    /// A config over `game_probe` with no patch store set (the caller must fill
    /// [`patch_store`](Self::patch_store)): patches removed after apply, the disk preflight on, the
    /// reference reattempt budget, and elevation left to the platform.
    ///
    /// Takes the probe rather than defaulting it, and stands in for the [`Default`] impl this type
    /// would otherwise have, because the useful default for a guard is the one that guards nothing:
    /// it would leave every caller correct-looking and unguarded, and the one caller that matters is
    /// the composition root, where forgetting it is silent. Naming it here costs one argument and
    /// makes the compiler ask.
    #[must_use]
    pub fn new(game_probe: GameProbe) -> Self {
        Self {
            patch_store: PathBuf::new(),
            keep_patches: false,
            ignore_space: false,
            repair_reattempts: DEFAULT_REPAIR_REATTEMPTS,
            elevation: Elevation::default(),
            game_probe,
        }
    }
}

/// Orchestrates download to verify to apply across a repo's ordered patch set.
#[derive(Debug, Clone)]
pub struct Patcher {
    fetcher: Fetcher,
    config: PatcherConfig,
}

impl Patcher {
    /// Construct over a `fetcher` and `config` (called by the composition root).
    #[must_use]
    pub fn new(fetcher: Fetcher, config: PatcherConfig) -> Self {
        Self { fetcher, config }
    }

    /// Install one repo's ordered pending patch set: acquire through fetch, admit only verified
    /// bytes, apply in strict list order, and advance `.ver`/`.bck`.
    ///
    /// Returns a [`Job`] whose progress stream carries [`PatchProgress`] and whose result is the
    /// per-repo [`Installed`] version. Runs on a spawned task, so a `tokio` runtime must be active.
    #[must_use]
    pub fn install(&self, request: InstallRequest) -> Job<Installed> {
        let fetcher = self.fetcher.clone();
        let config = self.config.clone();
        job::spawn(move |progress, cancel| install::run(fetcher, config, request, progress, cancel))
    }

    /// Repair one or more repos: verify each against its block index and re-fetch only the broken
    /// byte ranges (local patch files first, HTTP after), reconstruct zero/empty regions locally, and
    /// quarantine strays to the recycler without deleting them.
    ///
    /// Returns a [`Job`] whose progress stream carries [`PatchProgress`] repair phases and whose
    /// result is the [`RepairOutcome`]. Runs on a spawned task, so a `tokio` runtime must be active.
    #[must_use]
    pub fn repair(&self, request: RepairRequest) -> Job<RepairOutcome> {
        let fetcher = self.fetcher.clone();
        let config = self.config.clone();
        job::spawn(move |progress, cancel| repair::run(fetcher, config, request, progress, cancel))
    }
}

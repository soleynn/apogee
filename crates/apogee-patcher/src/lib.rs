#![forbid(unsafe_code)]
#![deny(missing_docs)]

//! Patch orchestration across download, apply, and repair.
//!
//! [`Patcher`] composes [`apogee_fetch`] (acquire) and [`apogee_zipatch`] (apply) into two flows over
//! a repo's patch set. It holds no format or transport knowledge, only the sequencing and policy
//! between the two lower crates.
//!
//! **Install** ([`Patcher::install`]) turns one repo's ordered pending patches into an up-to-date
//! tree: acquire runs ahead through fetch's scheduler while apply consumes strictly in the list order
//! Square Enix requires, so patch `k` applies only once `0..k` already has, even when `k` downloaded
//! first. Only an admitted patch (below) reaches the apply queue. The repo's version file advances
//! only after a patch applies cleanly, so a torn apply leaves the previous version in place and an
//! interrupted install re-runs from there; once the whole set has applied, the version file is copied
//! to its backup.
//!
//! **Repair** ([`Patcher::repair`]) verifies one or more repos against a block index and heals only
//! the byte ranges that no longer match: acquire the index (with a version cross-check against what
//! the caller asked to heal to), verify in parallel, then re-fetch broken ranges through a
//! [`RangeSource`](apogee_zipatch::RangeSource) that reads local patch files on the first, trusted
//! attempt and falls back to HTTP afterward. A bounded number of reattempts re-verifies only what a
//! pass left broken, so a retry never re-hashes a healthy tree. Files the index cannot explain are
//! quarantined into a recycler beside the repo tree; a repair never deletes a user's files.
//!
//! # Admission: proving a patch before it applies
//!
//! An apply only ever consumes an admitted patch, and Square Enix hashes its two repo families
//! differently, so admission has two routes. A game (or expansion) patch carries per-block SHA1 in the
//! patchlist: fetch verifies each block during download and the result is admitted directly. A boot
//! patch carries no hashes at all; fetch delivers its length-checked bytes unverified, and this
//! crate's own ZiPatch chunk-CRC scan is what mints the admission, rejecting a corrupt or malformed
//! patch before a byte of it is applied. That scan also takes a whole-file digest of the bytes it just
//! read, alongside the CRC check: the chunk CRC alone is a checksum anyone can recompute, so on its own
//! it cannot tell an admitted file apart from one substituted afterward, which is exactly the gap that
//! matters once the apply crosses into another process (below).
//!
//! # Elevation: when the writes need another process
//!
//! On Linux the writes always happen in this process: game directories live under the user's home, so
//! there is nothing to elevate to. On Windows, an install under a system-owned directory may not be
//! writable by the user who launched, and [`probe_writable`] answers that with a real write into the
//! tree rather than a permission calculation, since only the filesystem knows the access-control
//! entries, the ownership, and this process's token at once; [`Elevation::Auto`] elevates only once
//! that probe fails. Where the apply does run in a separate, privileged worker, that worker is offline
//! by design: this process fetches and verifies every byte first, and the worker only ever writes
//! bytes it re-derives the proof for from what it reads, since the admission taken here is a value in
//! this process that cannot travel across the boundary unchanged. For a game patch that re-derivation
//! is the same per-block SHA1; for a boot patch it is the whole-file digest taken at admission, since
//! that is the half of the boot proof an attacker cannot recompute.
//!
//! # Error semantics
//!
//! [`PatchError`] keeps two kinds of disk exhaustion apart because they are different claims.
//! [`PreflightError::NotEnoughSpace`], reached through [`PatchError::Preflight`], is a *predicted*
//! shortfall: an estimate taken from patchlist lengths before a byte moves, naming a pool and a
//! needed/free pair that describe a disk reading, not a failure. [`PatchError::OutOfSpace`] is the
//! *observed* half: the disk actually filled during a transfer, so it names the path the filesystem
//! refused instead, a number that is not knowable once a write has already failed. [`PatchError::Acquire`]
//! is deliberately not `#[from]` for the same reason those two stay distinct: an unwritten `?` over a
//! fetch failure would flatten `OutOfSpace` and [`PatchError::Cancelled`] back into a generic acquire
//! failure that names neither the repo nor the patch index responsible, so every fetch failure in this
//! crate is routed to its variant by hand instead.

use std::path::PathBuf;

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
mod staging;
mod store;

pub use catalog::{IndexCatalog, IndexCatalogError, IndexEntry};
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
///
/// The whole taxonomy Square Enix ships: the boot chain, the base game, and expansions numbered by a
/// `u8`. Exhaustive, so a caller mapping a repo to a path or a URL has to answer for all three and
/// gets told when that stops being all of them. It is also not serializable on purpose: the one
/// spelling this crate commits to is [`from_label`](Self::from_label), and a derived encoding beside
/// it would be a second, silently different name for the same value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Repo {
    /// The launcher and updater chain, patched before login.
    Boot,
    /// The base game.
    Game,
    /// Expansion `n`, as its patchlist path spells it (`ex1`).
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
///
/// Carries no repo of its own. It is only ever reached through [`PatchError::Verify`], which names
/// the repo already, and two copies of one value are two chances for a caller to read the one that
/// was not set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PartRef {
    /// The repo-relative path of the file holding the run.
    pub path: PathBuf,
    /// The byte offset of the failing run within that file.
    pub offset: u64,
}

/// A disk pool checked during preflight.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SpacePool {
    /// Where downloaded patch files land ([`PatcherConfig::patch_store`]).
    PatchStore,
    /// The install tree the patches apply into.
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
        /// The pool that came up short (or, on a shared filesystem, both pools together).
        pool: SpacePool,
        /// The heuristic bytes required.
        needed: u64,
        /// The bytes free on the pool's filesystem.
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
    /// Refused before anything was touched: see [`PreflightError`].
    #[error("preflight failed")]
    Preflight(#[from] PreflightError),
    /// A patchlist entry could not be turned into a download request (a bad URL, a version that
    /// strips to nothing, malformed or absent block hashes).
    #[error("patchlist entry {index}: {detail}")]
    Patchlist {
        /// The entry's zero-based position in the patch set.
        index: u32,
        /// What was wrong with it.
        detail: String,
    },
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
        /// The path the filesystem refused to write.
        path: PathBuf,
        /// The underlying `ENOSPC` (or platform equivalent).
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
    /// A repo still failed verification after the last repair pass.
    ///
    /// The message names `first` as well as the count. The count alone says a repair did not
    /// converge and gives nobody a file to look at, and this variant carries no `#[source]`, so a
    /// part left out of the message is a part that reaches no caller at all: the error chain a
    /// launcher renders is built from `Display`.
    #[error(
        "{broken} broken part(s) in {repo:?}, first {} at offset {}",
        first.path.display(),
        first.offset,
    )]
    Verify {
        /// The repo that did not come clean.
        repo: Repo,
        /// How many runs still failed verification.
        broken: usize,
        /// The first of those runs, in verification order.
        first: PartRef,
    },
    /// The apply itself failed (a corrupt patch, a write the filesystem refused).
    #[error("apply failed")]
    Apply(#[from] apogee_zipatch::Error),
    /// A boot patch failed its chunk-CRC admission scan, so it was rejected before any byte of it
    /// was applied.
    #[error("boot patch {index} failed chunk-crc admission")]
    BootAdmission {
        /// The failed patch's zero-based position in the boot chain.
        index: u32,
        /// The parse or CRC fault the scan hit.
        #[source]
        source: apogee_zipatch::Error,
    },
    /// A filesystem operation this crate owns directly failed (version files, directory creation),
    /// distinct from a fault inside the acquire or apply pipelines.
    #[error("i/o error on {path}")]
    Io {
        /// The path the operation was on.
        path: PathBuf,
        /// The underlying I/O failure.
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
    /// A repo's block index could not be obtained or parsed (fetch failure, signature or pin
    /// mismatch, malformed `.apzi`).
    #[error("index unavailable for {repo:?}")]
    IndexUnavailable {
        /// The repo whose index was needed.
        repo: Repo,
        /// The underlying failure.
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },
    /// A repair's index describes a different version than the one the caller asked to heal to, so
    /// it was refused before any byte was rewritten to guard against contents from the wrong
    /// version.
    #[error("version cross-check failed for {repo:?}: index {index_version}, wanted {wanted}")]
    VersionCrossCheck {
        /// The repo whose index failed the cross-check.
        repo: Repo,
        /// The version the index actually describes.
        index_version: String,
        /// The version the repair was asked to heal to.
        wanted: String,
    },
    /// The operation was cancelled through [`Job::cancel`].
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
///
/// Not public: [`PatcherConfig::new`] applies it, which is how every caller has ever obtained it, and
/// a public constant is a number the crate would owe callers forever for tuning that belongs here.
const DEFAULT_REPAIR_REATTEMPTS: usize = 5;

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

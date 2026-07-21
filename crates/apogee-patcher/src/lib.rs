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
//! Repair and the Windows elevated-worker protocol (the [`WorkerRequest`]/[`WorkerResponse`]/
//! [`WorkerProgress`] messages and the [`PatchError::Worker`] arm) are declared here but not yet
//! driven.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use apogee_fetch::{FetchError, Fetcher};

mod install;
mod job;
mod preflight;
mod progress;
mod request;
mod store;

pub use job::Job;
pub use progress::PatchProgress;
pub use request::{InstallRequest, Installed, SePatch};

/// Which game repository a patch operation targets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum Repo {
    Boot,
    Game,
    Expansion(u8),
}

/// Identifies one part-file within a repo (for repair reporting).
#[derive(Debug, Clone)]
pub struct PartRef {
    pub repo: Repo,
    pub index: u32,
}

/// A disk pool checked during preflight.
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub enum SpacePool {
    PatchStore,
    GameRoot,
}

/// Preflight failures, surfaced through [`PatchError::Preflight`].
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum PreflightError {
    #[error("not enough space in {pool:?}: need {needed}, have {free}")]
    NotEnoughSpace {
        pool: SpacePool,
        needed: u64,
        free: u64,
    },
    #[error("game is running")]
    GameRunning,
}

/// How the elevated worker failed (mirrors its stdio error payload).
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub enum WorkerErrorKind {
    Spawn,
    Protocol,
    Apply,
    Verify,
}

/// Patch orchestration failures.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum PatchError {
    #[error("preflight failed")]
    Preflight(#[from] PreflightError),
    #[error("patchlist entry {index}: {detail}")]
    Patchlist { index: u32, detail: String },
    #[error("acquire failed")]
    Acquire(#[from] FetchError),
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
    #[error("elevated worker failed: {kind:?}")]
    Worker {
        kind: WorkerErrorKind,
        failed_file: Option<PathBuf>,
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

/// The elevated-worker stdio protocol: length-prefixed `serde` frames. The exact message set (and
/// whether the worker runs the whole apply or a marshaled [`apogee_zipatch::PatchSink`]) is an open
/// design point, not yet finalized.
#[derive(Debug, Serialize, Deserialize)]
#[non_exhaustive]
pub enum WorkerRequest {
    Apply { repo: Repo, patch: PathBuf },
    Cancel,
}

/// A worker's reply to a [`WorkerRequest`].
#[derive(Debug, Serialize, Deserialize)]
#[non_exhaustive]
pub enum WorkerResponse {
    Done,
    Failed { detail: String },
}

/// A progress frame streamed from the worker mid-apply.
#[derive(Debug, Serialize, Deserialize)]
#[non_exhaustive]
pub enum WorkerProgress {
    Bytes(u64),
    File(PathBuf),
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
    pub fn install(&self, request: InstallRequest) -> Job {
        job::spawn(self.fetcher.clone(), self.config.clone(), request)
    }
}

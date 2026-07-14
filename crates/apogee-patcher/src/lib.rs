#![forbid(unsafe_code)]
//! Patch orchestration across download, apply, and repair.
//!
//! STUB: public shape only (error taxonomy, the elevated-worker stdio protocol messages this
//! crate owns, and the [`Patcher`] handle the composition root constructs); orchestration is not
//! yet built. The `sqex-proto` edge is the future version-cross-check composition edge, unused for
//! now.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use apogee_fetch::{FetchError, Fetcher};

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

/// Runtime configuration for a [`Patcher`].
#[derive(Debug, Clone)]
pub struct PatcherConfig {
    pub patch_store: PathBuf,
    pub game_root: PathBuf,
    pub keep_patches: bool,
    pub ignore_space: bool,
}

/// Orchestrates download to verify to apply across repos.
#[derive(Debug)]
pub struct Patcher;

impl Patcher {
    /// Construct over a `fetcher` and `config` (called by the composition root).
    pub fn new(_fetcher: Fetcher, _config: PatcherConfig) -> Self {
        Self
    }
}

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
    #[error("runner download failed")]
    Download(#[from] FetchError),
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
    #[error("invalid launch plan: {reason}")]
    InvalidLaunchPlan { reason: &'static str },
    #[error("game process not found after {waited:?}")]
    GameProcessNotFound { waited: Duration },
    #[error("path mapping failed for {path:?}: {reason}")]
    PathMapping { path: PathBuf, reason: &'static str },
    #[error("missing host tool: {tool:?}")]
    MissingHostTool { tool: HostTool },
    #[error("unsupported: {what}")]
    Unsupported { what: &'static str },
}

/// Why a signed runner catalog was rejected. Kept separate so the pure parser (fuzzed,
/// cross-platform) has its own total taxonomy; [`RuntimeError`] wraps it via `#[from]`.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum CatalogError {
    #[error("manifest is not valid JSON or violates the schema")]
    Malformed(#[source] serde_json::Error),
    #[error("manifest signature did not verify against the trusted key")]
    BadSignature,
    #[error("unsupported manifest version {found} (expected {expected})")]
    UnsupportedVersion { found: u32, expected: u32 },
    #[error("unknown runner kind {kind:?}")]
    UnknownRunnerKind { kind: String },
    #[error("unknown archive format {format:?}")]
    UnknownArchiveFormat { format: String },
    #[error("{name} {version}: sha256 pin is not 32 hex bytes")]
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
    /// `wineboot -i` (or umu `createprefix`) on a brand-new prefix.
    WinebootInit,
    /// `wineboot -u`: a non-destructive update that regenerates missing prefix structure.
    WinebootUpdate,
    /// A DXVK install into the prefix (recorded once the environment matrix owns it).
    DxvkInstall,
    /// A registry or configuration tweak.
    ApplyTweaks,
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
}

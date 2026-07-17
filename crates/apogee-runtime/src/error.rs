//! Runner / prefix / launch error taxonomy.

use std::path::PathBuf;
use std::time::Duration;

use thiserror::Error;

use apogee_fetch::FetchError;

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
    #[error("prefix is unhealthy ({} issue(s))", issues.len())]
    PrefixUnhealthy { issues: Vec<HealthIssue> },
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

/// A step in prefix initialization (for [`RuntimeError::PrefixInit`]).
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub enum SetupStep {
    CreatePrefix,
    InstallDxvk,
    ApplyTweaks,
}

/// A prefix health problem (for [`RuntimeError::PrefixUnhealthy`]).
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum HealthIssue {
    MissingFile(PathBuf),
    WrongArch,
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

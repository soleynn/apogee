#![forbid(unsafe_code)]
//! Wine and Proton runner management with process supervision.
//!
//! STUB: public shape only (error taxonomy, the [`Runtime`] handle the composition root
//! constructs, and the launch-lifecycle types `apogee-addons` injectables hook); runner download,
//! prefix setup, and process supervision are not yet built.

use std::path::PathBuf;
use std::time::Duration;

use thiserror::Error;

use apogee_fetch::{FetchError, Fetcher};

/// Runner / prefix / launch failures.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum RuntimeError {
    #[error("runner {name} {version} unavailable")]
    RunnerUnavailable { name: String, version: String },
    #[error("runner download failed")]
    Download(#[from] FetchError),
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
    #[error("game process not found after {waited:?}")]
    GameProcessNotFound { waited: Duration },
    #[error("path mapping failed for {path:?}: {reason}")]
    PathMapping { path: PathBuf, reason: &'static str },
    #[error("missing host tool: {tool:?}")]
    MissingHostTool { tool: HostTool },
    #[error("unsupported: {what}")]
    Unsupported { what: &'static str },
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
}

/// Where the runtime stores runners and prefixes.
#[derive(Debug, Clone, Default)]
pub struct RuntimePaths {
    pub runners: PathBuf,
    pub prefixes: PathBuf,
}

/// Wine/Proton runner manager. A cheap handle: clone it to share.
#[derive(Debug, Clone)]
pub struct Runtime;

impl Runtime {
    /// Construct the runtime over `fetcher` and `paths` (called by the composition root).
    pub fn new(_fetcher: Fetcher, _paths: RuntimePaths) -> Self {
        Self
    }
}

/// A prepared Wine prefix, handed to injectables' `ensure`.
#[derive(Debug)]
pub struct Prefix {/* path + runner not yet modeled */}

/// A launch about to be spawned; injectables may wrap or mutate it before spawn.
#[derive(Debug)]
pub struct LaunchPlan {/* argv + env not yet modeled */}

/// A resolved, running game process, handed to injectables' `attach`.
#[derive(Debug)]
pub struct GameSession {/* pid + handles not yet modeled */}

/// A progress observer handed to long-running runtime / addon operations.
#[derive(Debug, Clone, Default)]
pub struct Progress;

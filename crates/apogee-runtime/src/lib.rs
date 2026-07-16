#![forbid(unsafe_code)]
//! Wine and Proton runner management with process supervision.
//!
//! The runner catalog is a signed manifest (see [`Catalog`]); everything else — download/extract,
//! spawn, and `/proc` supervision — is layered on the injected [`apogee_fetch::Fetcher`] seam.

mod catalog;
mod error;

use std::path::PathBuf;

use apogee_fetch::Fetcher;

pub use catalog::{
    ArchiveFormat, ArchiveLayout, CATALOG_MANIFEST_VERSION, CATALOG_PUBLIC_KEY, Catalog, DxvkEntry,
    Runner, RunnerKind, ToolEntry,
};
pub use error::{CatalogError, HealthIssue, HostTool, RuntimeError, SetupStep};

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

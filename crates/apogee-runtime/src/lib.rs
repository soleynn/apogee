#![forbid(unsafe_code)]
// Runner management is Linux-only at this phase; on other targets the download/spawn machinery is
// deliberately dormant (the async methods return `Unsupported`), so silence dead-code there only.
#![cfg_attr(not(target_os = "linux"), allow(dead_code))]
//! Wine and Proton runner management with process supervision.
//!
//! The runner catalog is a signed manifest (see [`Catalog`]); runners and the umu tool are
//! downloaded and extracted through the injected [`apogee_fetch::Fetcher`] seam, then launched and
//! supervised. Runner management is Linux-first: on other targets the async methods return
//! [`RuntimeError::Unsupported`].

mod catalog;
mod error;
#[cfg(target_os = "linux")]
mod extract;
#[cfg(target_os = "linux")]
mod install;
mod plan;
mod progress;

use std::path::PathBuf;
use std::sync::Arc;

use apogee_fetch::Fetcher;

pub use catalog::{
    ArchiveFormat, ArchiveLayout, CATALOG_MANIFEST_VERSION, CATALOG_PUBLIC_KEY, Catalog, DxvkEntry,
    Runner, RunnerKind, ToolEntry,
};
pub use error::{CatalogError, HealthIssue, HostTool, RuntimeError, SetupStep};
#[cfg(target_os = "linux")]
pub use extract::extract_archive;
pub use plan::{LaunchPlan, Prefix, RunnerHandle};
pub use progress::{Progress, RuntimeEvent};

/// Where the runtime stores runners and prefixes.
#[derive(Debug, Clone, Default)]
pub struct RuntimePaths {
    pub runners: PathBuf,
    pub prefixes: PathBuf,
}

#[derive(Debug)]
struct Inner {
    fetcher: Fetcher,
    paths: RuntimePaths,
}

/// Wine/Proton runner manager. A cheap handle: clone it to share.
#[derive(Debug, Clone)]
pub struct Runtime {
    inner: Arc<Inner>,
}

impl Runtime {
    /// Construct the runtime over `fetcher` and `paths` (called by the composition root).
    pub fn new(fetcher: Fetcher, paths: RuntimePaths) -> Self {
        Self {
            inner: Arc::new(Inner { fetcher, paths }),
        }
    }
}

#[cfg(target_os = "linux")]
impl Runtime {
    /// Where managed tools (e.g. umu) install: a `tools` sibling of the runners directory.
    fn tools_dir(&self) -> PathBuf {
        self.inner
            .paths
            .runners
            .parent()
            .map(|p| p.join("tools"))
            .unwrap_or_else(|| self.inner.paths.runners.join(".tools"))
    }

    /// Fetch the signed runner catalog and verify it against the compiled-in key.
    pub async fn fetch_catalog(
        &self,
        manifest_url: &url::Url,
        signature_url: &url::Url,
        cancel: &tokio_util::sync::CancellationToken,
    ) -> Result<Catalog, RuntimeError> {
        let cache = self.inner.paths.runners.join(".catalog");
        install::fetch_catalog(
            &self.inner.fetcher,
            manifest_url,
            signature_url,
            &cache,
            cancel,
        )
        .await
    }

    /// Ensure `runner` is installed and `prefix_dir` exists, returning the prepared prefix. The
    /// prefix is umu/wine auto-initialized on first launch; no `wineboot` at this phase.
    pub async fn prepare(
        &self,
        runner: &Runner,
        prefix_dir: &std::path::Path,
        cancel: &tokio_util::sync::CancellationToken,
        progress: &Progress,
    ) -> Result<Prefix, RuntimeError> {
        let runner_dir = install::install_runner(
            &self.inner.fetcher,
            runner,
            &self.inner.paths.runners,
            cancel,
            progress,
        )
        .await?;
        tokio::fs::create_dir_all(prefix_dir)
            .await
            .map_err(|e| RuntimeError::Io {
                path: prefix_dir.to_path_buf(),
                source: e,
            })?;
        let handle = crate::plan::RunnerHandle {
            dir: runner_dir,
            kind: runner.kind,
            name: runner.name.clone(),
        };
        Ok(Prefix::new(prefix_dir.to_path_buf(), handle))
    }

    /// Ensure a supporting tool (e.g. `umu-launcher`) is installed, returning its directory.
    pub async fn ensure_tool(
        &self,
        tool: &ToolEntry,
        cancel: &tokio_util::sync::CancellationToken,
        progress: &Progress,
    ) -> Result<PathBuf, RuntimeError> {
        let tools = self.tools_dir();
        install::install_tool(&self.inner.fetcher, tool, &tools, cancel, progress).await
    }
}

#[cfg(not(target_os = "linux"))]
impl Runtime {
    /// Runner management is Linux-only at this phase.
    pub async fn fetch_catalog(
        &self,
        _manifest_url: &url::Url,
        _signature_url: &url::Url,
        _cancel: &tokio_util::sync::CancellationToken,
    ) -> Result<Catalog, RuntimeError> {
        Err(RuntimeError::Unsupported {
            what: "runner management is Linux-only at this phase",
        })
    }

    /// Runner management is Linux-only at this phase.
    pub async fn prepare(
        &self,
        _runner: &Runner,
        _prefix_dir: &std::path::Path,
        _cancel: &tokio_util::sync::CancellationToken,
        _progress: &Progress,
    ) -> Result<Prefix, RuntimeError> {
        Err(RuntimeError::Unsupported {
            what: "runner management is Linux-only at this phase",
        })
    }

    /// Runner management is Linux-only at this phase.
    pub async fn ensure_tool(
        &self,
        _tool: &ToolEntry,
        _cancel: &tokio_util::sync::CancellationToken,
        _progress: &Progress,
    ) -> Result<PathBuf, RuntimeError> {
        Err(RuntimeError::Unsupported {
            what: "runner management is Linux-only at this phase",
        })
    }
}

/// A resolved, running game process, handed to injectables' `attach`.
#[derive(Debug)]
pub struct GameSession {/* pid + handles not yet modeled */}

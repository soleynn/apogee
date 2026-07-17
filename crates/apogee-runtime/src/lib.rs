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
#[cfg(target_os = "linux")]
mod session;
#[cfg(target_os = "linux")]
mod spawn;
#[cfg(target_os = "linux")]
mod supervise;

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
#[cfg(not(target_os = "linux"))]
pub use non_linux::{GameExit, GameSession};
pub use plan::{LaunchPlan, Prefix, RunnerHandle};
pub use progress::{Progress, RuntimeEvent};
#[cfg(target_os = "linux")]
pub use session::{GameExit, GameSession};

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

    /// Adopt an existing runner directory (bring-your-own wine/Proton) as a prepared prefix, with no
    /// download. The runner directory must already exist.
    pub async fn prepare_custom(
        &self,
        runner_dir: &std::path::Path,
        kind: RunnerKind,
        name: impl Into<String>,
        prefix_dir: &std::path::Path,
    ) -> Result<Prefix, RuntimeError> {
        let name = name.into();
        if !runner_dir.is_dir() {
            return Err(RuntimeError::RunnerUnavailable {
                name,
                version: "custom".to_owned(),
            });
        }
        tokio::fs::create_dir_all(prefix_dir)
            .await
            .map_err(|source| RuntimeError::Io {
                path: prefix_dir.to_path_buf(),
                source,
            })?;
        let handle = crate::plan::RunnerHandle {
            dir: runner_dir.to_path_buf(),
            kind,
            name,
        };
        Ok(Prefix::new(prefix_dir.to_path_buf(), handle))
    }

    /// Spawn the game through the runner and supervise it, resolving once the real game process
    /// appears in `/proc`. The returned session tracks the game, not the wrapper.
    pub async fn launch(
        &self,
        plan: LaunchPlan,
        cancel: &tokio_util::sync::CancellationToken,
        progress: &Progress,
    ) -> Result<GameSession, RuntimeError> {
        let prefix = plan.prefix_ref().ok_or(RuntimeError::InvalidLaunchPlan {
            reason: "launch plan has no prefix",
        })?;
        let runner_name = prefix.runner().name().to_owned();
        let umu = if prefix.runner().kind() == RunnerKind::ProtonUmu {
            spawn::resolve_umu(&self.tools_dir())
        } else {
            None
        };
        let mut command = spawn::build_command(&plan, umu.as_deref())?;

        progress.emit(RuntimeEvent::Spawning {
            runner: runner_name.clone(),
        });
        let mut child = command.spawn().map_err(|source| RuntimeError::Spawn {
            runner: runner_name,
            source,
        })?;

        let program = plan.program().to_owned();
        let basename = std::path::Path::new(&program)
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or(program.as_str());
        match supervise::resolve_game(basename, prefix.path(), cancel).await {
            Ok(pid) => {
                // Detach the wrapper; tokio reaps it on exit. The game is tracked by pid.
                drop(child);
                progress.emit(RuntimeEvent::GameResolved { pid });
                Ok(GameSession::new(pid, prefix.clone()))
            }
            Err(e) => {
                let _ = child.start_kill();
                Err(e)
            }
        }
    }

    /// Kill everything in a prefix (`wineserver -k`). Separate and explicit: never the default stop.
    pub async fn kill_prefix(&self, prefix: &Prefix) -> Result<(), RuntimeError> {
        let umu = if prefix.runner().kind() == RunnerKind::ProtonUmu {
            spawn::resolve_umu(&self.tools_dir())
        } else {
            None
        };
        spawn::kill_prefix(prefix, umu).await
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

    /// Runner management is Linux-only at this phase.
    pub async fn prepare_custom(
        &self,
        _runner_dir: &std::path::Path,
        _kind: RunnerKind,
        _name: impl Into<String>,
        _prefix_dir: &std::path::Path,
    ) -> Result<Prefix, RuntimeError> {
        Err(RuntimeError::Unsupported {
            what: "runner management is Linux-only at this phase",
        })
    }

    /// Runner management is Linux-only at this phase.
    pub async fn launch(
        &self,
        _plan: LaunchPlan,
        _cancel: &tokio_util::sync::CancellationToken,
        _progress: &Progress,
    ) -> Result<GameSession, RuntimeError> {
        Err(RuntimeError::Unsupported {
            what: "runner management is Linux-only at this phase",
        })
    }

    /// Runner management is Linux-only at this phase.
    pub async fn kill_prefix(&self, _prefix: &Prefix) -> Result<(), RuntimeError> {
        Err(RuntimeError::Unsupported {
            what: "runner management is Linux-only at this phase",
        })
    }
}

/// Cross-platform stand-ins for the game session types on non-Linux targets, where the runner
/// surface is inert.
#[cfg(not(target_os = "linux"))]
mod non_linux {
    /// An opaque game-exit marker (see the Linux implementation).
    #[derive(Debug, Clone)]
    #[non_exhaustive]
    pub struct GameExit {}

    /// A supervised game process. Constructed only by the Linux launch path; here it is uninhabited
    /// (`launch` returns `Unsupported`), so it exists solely to satisfy cross-platform consumers.
    pub struct GameSession(std::convert::Infallible);

    impl GameSession {
        /// The unix PID of the game process.
        #[must_use]
        pub fn game_pid(&self) -> i32 {
            match self.0 {}
        }

        /// The prefix the game runs in.
        #[must_use]
        pub fn prefix(&self) -> &crate::Prefix {
            match self.0 {}
        }

        /// Resolve when the game exits.
        pub async fn wait(&self) -> Result<GameExit, crate::RuntimeError> {
            match self.0 {}
        }

        /// Targeted kill of the game process.
        pub async fn kill(&self) -> Result<(), crate::RuntimeError> {
            match self.0 {}
        }
    }

    impl std::fmt::Debug for GameSession {
        fn fmt(&self, _f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match self.0 {}
        }
    }
}

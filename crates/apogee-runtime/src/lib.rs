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

mod bench;
mod catalog;
#[cfg(target_os = "linux")]
mod companion;
#[cfg(target_os = "linux")]
mod dosdevices;
#[cfg(target_os = "linux")]
mod dxvk;
mod env;
mod error;
mod exec;
#[cfg(target_os = "linux")]
mod extract;
#[cfg(target_os = "linux")]
mod install;
#[cfg(target_os = "linux")]
mod lifecycle;
mod metadata;
mod plan;
mod progress;
mod registry;
#[cfg(target_os = "linux")]
mod session;
#[cfg(target_os = "linux")]
mod spawn;
#[cfg(target_os = "linux")]
mod supervise;

use std::path::PathBuf;
use std::sync::Arc;

use apogee_fetch::Fetcher;

pub use bench::{BenchError, BenchStats, FrameLog};
pub use catalog::{
    ArchiveFormat, ArchiveLayout, CATALOG_MANIFEST_VERSION, CATALOG_PUBLIC_KEY, Catalog, DxvkEntry,
    NvapiRef, Runner, RunnerKind, ToolEntry,
};
#[cfg(target_os = "linux")]
pub use companion::{Companion, CompanionExit, CompanionSpec};
#[cfg(target_os = "linux")]
pub use dosdevices::DriveMap;
pub use env::{
    DxvkEnv, EnvConfig, Environment, Gamescope, GpuSelect, HostCaps, Hud, SyncChoice, SyncStatus,
    compute_environment,
};
pub use error::{CatalogError, HealthIssue, HostTool, PrefixHealth, RuntimeError, SetupStep};
pub use exec::{PrefixRun, ProgramInPrefix};
#[cfg(target_os = "linux")]
pub use extract::extract_archive;
pub use metadata::{DxvkRef, PREFIX_JSON, PrefixMetadata, RunnerRef, SetupRecord};
#[cfg(not(target_os = "linux"))]
pub use non_linux::{Companion, CompanionExit, CompanionSpec};
#[cfg(not(target_os = "linux"))]
pub use non_linux::{GameExit, GameSession, prefix_processes};
pub use plan::{LaunchPlan, Prefix, RunnerHandle};
pub use progress::{Progress, RuntimeEvent};
pub use registry::{RegistryEdit, RegistryValue};
#[cfg(target_os = "linux")]
pub use session::{GameExit, GameSession};

/// The pids of processes running inside `prefix` whose kernel-visible name matches `program_name`.
///
/// This is a candidate set, not an identity. The kernel caps a process name at 15 bytes and the
/// runner renames its loader to the executable's base name, so two programs whose names share a
/// 15-byte prefix both come back and the caller is expected to narrow. The prefix side is exact: it
/// reads each process's own `WINEPREFIX`, normalized for the relocation Proton applies, and the
/// kernel restricts that file to the user who owns the process.
///
/// # Errors
/// [`RuntimeError::Io`] if `/proc` cannot be read.
#[cfg(target_os = "linux")]
pub async fn prefix_processes(
    prefix: &Prefix,
    program_name: &str,
) -> Result<Vec<i32>, RuntimeError> {
    let comm = supervise::comm_target(program_name);
    let path = prefix.path().to_path_buf();
    // A whole-of-`/proc` walk is blocking work, and this runs on the launch path.
    tokio::task::spawn_blocking(move || supervise::scan_matches(&comm, &path))
        .await
        .map_err(|source| RuntimeError::Io {
            path: PathBuf::from("/proc"),
            source: std::io::Error::other(source),
        })?
        .map_err(|source| RuntimeError::Io {
            path: PathBuf::from("/proc"),
            source,
        })
}

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

    /// The resolved `umu-run` for a Proton runner, or `None` for plain wine (which needs no umu).
    fn umu_for(&self, kind: RunnerKind) -> Option<PathBuf> {
        if kind == RunnerKind::ProtonUmu {
            spawn::resolve_umu(&self.tools_dir())
        } else {
            None
        }
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

    /// Ensure `runner` is installed and the prefix at `prefix_dir` is initialized, returning the
    /// prepared prefix. Downloads the runner if absent, runs `wineboot -i` and records `prefix.json`
    /// if the prefix is new, and is a no-op on a prefix that is already set up.
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
        let handle = crate::plan::RunnerHandle::new(
            runner_dir,
            runner.kind,
            runner.name.clone(),
            runner.version.clone(),
        );
        let umu = self.umu_for(runner.kind);
        lifecycle::ensure_ready(handle, prefix_dir, umu.as_deref(), cancel, progress).await
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
    /// download. The runner directory must already exist. Initializes the prefix (`wineboot -i` +
    /// `prefix.json`) if it is new, exactly like [`prepare`](Self::prepare).
    pub async fn prepare_custom(
        &self,
        runner_dir: &std::path::Path,
        kind: RunnerKind,
        name: impl Into<String>,
        prefix_dir: &std::path::Path,
        cancel: &tokio_util::sync::CancellationToken,
        progress: &Progress,
    ) -> Result<Prefix, RuntimeError> {
        let name = name.into();
        if !runner_dir.is_dir() {
            return Err(RuntimeError::RunnerUnavailable {
                name,
                version: "custom".to_owned(),
            });
        }
        let handle = crate::plan::RunnerHandle::new(runner_dir.to_path_buf(), kind, name, "custom");
        let umu = self.umu_for(kind);
        lifecycle::ensure_ready(handle, prefix_dir, umu.as_deref(), cancel, progress).await
    }

    /// Diagnose a prefix against its `prefix.json` and the wine skeleton, returning every drift found
    /// (drive-map breakage, a missing skeleton file, a runner change) without touching it.
    pub async fn check_prefix(&self, prefix: &Prefix) -> Result<PrefixHealth, RuntimeError> {
        lifecycle::check(prefix).await
    }

    /// Apply targeted fixes for the given `issues` and return the residual health. Rewrites a broken
    /// drive symlink in place and regenerates a missing skeleton with `wineboot -u`; never deletes the
    /// prefix. A runner mismatch is left for an explicit [`recreate_prefix`](Self::recreate_prefix).
    pub async fn repair_prefix(
        &self,
        prefix: &Prefix,
        issues: &[HealthIssue],
        cancel: &tokio_util::sync::CancellationToken,
        progress: &Progress,
    ) -> Result<PrefixHealth, RuntimeError> {
        let umu = self.umu_for(prefix.runner().kind());
        lifecycle::repair(prefix, issues, umu.as_deref(), cancel, progress).await
    }

    /// Destructively recreate a prefix: delete it and reinitialize from scratch. Explicit and
    /// user-initiated — never the automatic response to a health problem.
    pub async fn recreate_prefix(
        &self,
        prefix: &Prefix,
        cancel: &tokio_util::sync::CancellationToken,
        progress: &Progress,
    ) -> Result<Prefix, RuntimeError> {
        let umu = self.umu_for(prefix.runner().kind());
        lifecycle::recreate(prefix, umu.as_deref(), cancel, progress).await
    }

    /// Install `dxvk` into `prefix` (its DLLs into `system32`/`syswow64`) and record it in
    /// `prefix.json`. `nvapi` additionally installs `dxvk-nvapi`, if the catalog entry pins one. The
    /// environment matrix ([`compute_environment`]) is what activates the DLLs at launch.
    pub async fn install_dxvk(
        &self,
        dxvk: &DxvkEntry,
        prefix: &Prefix,
        nvapi: bool,
        cancel: &tokio_util::sync::CancellationToken,
        progress: &Progress,
    ) -> Result<(), RuntimeError> {
        dxvk::install(&self.inner.fetcher, dxvk, prefix, nvapi, cancel, progress).await
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
        // The spawned runner process is the wine loader; it renames itself to the PE basename, so the
        // scanner must prefer the real game process over it.
        let wrapper_pid = child.id().map(|id| id as i32);
        match supervise::resolve_game(basename, prefix.path(), wrapper_pid, cancel).await {
            Ok(pid) => {
                // Detach the wrapper; tokio reaps it on exit. The game is tracked by pid.
                drop(child);
                progress.emit(RuntimeEvent::GameResolved { pid });
                Ok(GameSession::new(pid, basename.to_owned(), prefix.clone()))
            }
            Err(e) => {
                let _ = child.start_kill();
                Err(e)
            }
        }
    }

    /// Run one program inside `prefix` through its runner and wait for it: the primitive prefix setup
    /// is built from. Its exit status and captured output come back rather than a pass/fail, because
    /// what a non-zero status means belongs to the step being performed.
    ///
    /// # Errors
    /// [`RuntimeError::MissingHostTool`] if the runner has no resolvable launcher,
    /// [`RuntimeError::Spawn`] if the program could not be started, and
    /// [`RuntimeError::InPrefixIncomplete`] if it outlived its time budget or the run was cancelled.
    pub async fn run_in_prefix(
        &self,
        prefix: &Prefix,
        program: &ProgramInPrefix,
        cancel: &tokio_util::sync::CancellationToken,
    ) -> Result<PrefixRun, RuntimeError> {
        let umu = self.umu_for(prefix.runner().kind());
        exec::run(prefix, program, umu.as_deref(), cancel).await
    }

    /// Write one registry value inside `prefix`. Idempotent: the value is overwritten rather than
    /// added, so applying the same edit twice is applying it once.
    ///
    /// # Errors
    /// [`RuntimeError::RegistryKey`] if the edit is not a shape this launcher writes,
    /// [`RuntimeError::PrefixInit`] if `reg` reported a failure, plus anything
    /// [`Self::run_in_prefix`] raises.
    pub async fn registry_set(
        &self,
        prefix: &Prefix,
        edit: &RegistryEdit,
        cancel: &tokio_util::sync::CancellationToken,
    ) -> Result<(), RuntimeError> {
        let program = edit.command()?;
        let run = self.run_in_prefix(prefix, &program, cancel).await?;
        if run.ok() {
            return Ok(());
        }
        Err(RuntimeError::PrefixInit {
            step: SetupStep::ApplyTweaks,
            source: Box::new(std::io::Error::other(format!(
                "reg add {}\\{} exited with {}: {}",
                edit.key,
                edit.name,
                run.code
                    .map_or_else(|| "a signal".to_owned(), |c| c.to_string()),
                run.diagnostic()
            ))),
        })
    }

    /// Spawn a companion program: a native tool on the host, or a Windows one run inside a prefix
    /// through its runner. Unlike [`Self::launch`] the child is held rather than resolved through
    /// `/proc`, so a short-lived companion is supported and its exit status is readable.
    ///
    /// # Errors
    /// [`RuntimeError::MissingHostTool`] if a prefix companion has no resolvable runner launcher,
    /// or [`RuntimeError::Spawn`] if the process could not be started.
    pub fn spawn_companion(&self, spec: &CompanionSpec) -> Result<Companion, RuntimeError> {
        companion::spawn(spec, &self.tools_dir())
    }

    /// Kill everything in a prefix. Separate and explicit: never the default stop.
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
    /// Companion tools are Linux-only at this phase.
    pub fn spawn_companion(&self, _spec: &CompanionSpec) -> Result<Companion, RuntimeError> {
        Err(RuntimeError::Unsupported {
            what: "running a companion program",
        })
    }

    /// Running a program inside a prefix is Linux-only at this phase.
    pub async fn run_in_prefix(
        &self,
        _prefix: &Prefix,
        _program: &ProgramInPrefix,
        _cancel: &tokio_util::sync::CancellationToken,
    ) -> Result<PrefixRun, RuntimeError> {
        Err(RuntimeError::Unsupported {
            what: "running a program inside a prefix",
        })
    }

    /// Prefix registry edits are Linux-only at this phase.
    pub async fn registry_set(
        &self,
        _prefix: &Prefix,
        _edit: &RegistryEdit,
        _cancel: &tokio_util::sync::CancellationToken,
    ) -> Result<(), RuntimeError> {
        Err(RuntimeError::Unsupported {
            what: "editing a prefix registry",
        })
    }

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
        _cancel: &tokio_util::sync::CancellationToken,
        _progress: &Progress,
    ) -> Result<Prefix, RuntimeError> {
        Err(RuntimeError::Unsupported {
            what: "runner management is Linux-only at this phase",
        })
    }

    /// Runner management is Linux-only at this phase.
    pub async fn check_prefix(&self, _prefix: &Prefix) -> Result<PrefixHealth, RuntimeError> {
        Err(RuntimeError::Unsupported {
            what: "runner management is Linux-only at this phase",
        })
    }

    /// Runner management is Linux-only at this phase.
    pub async fn repair_prefix(
        &self,
        _prefix: &Prefix,
        _issues: &[HealthIssue],
        _cancel: &tokio_util::sync::CancellationToken,
        _progress: &Progress,
    ) -> Result<PrefixHealth, RuntimeError> {
        Err(RuntimeError::Unsupported {
            what: "runner management is Linux-only at this phase",
        })
    }

    /// Runner management is Linux-only at this phase.
    pub async fn recreate_prefix(
        &self,
        _prefix: &Prefix,
        _cancel: &tokio_util::sync::CancellationToken,
        _progress: &Progress,
    ) -> Result<Prefix, RuntimeError> {
        Err(RuntimeError::Unsupported {
            what: "runner management is Linux-only at this phase",
        })
    }

    /// Runner management is Linux-only at this phase.
    pub async fn install_dxvk(
        &self,
        _dxvk: &DxvkEntry,
        _prefix: &Prefix,
        _nvapi: bool,
        _cancel: &tokio_util::sync::CancellationToken,
        _progress: &Progress,
    ) -> Result<(), RuntimeError> {
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
    use std::collections::BTreeMap;
    use std::path::PathBuf;
    use std::time::Duration;

    /// See the Linux implementation.
    pub async fn prefix_processes(
        _prefix: &crate::Prefix,
        _program_name: &str,
    ) -> Result<Vec<i32>, crate::RuntimeError> {
        Err(crate::RuntimeError::Unsupported {
            what: "reading the process table",
        })
    }

    /// What to run and where (see the Linux implementation).
    #[derive(Debug, Clone)]
    pub struct CompanionSpec {
        _program: PathBuf,
    }

    impl CompanionSpec {
        /// A companion run directly on the host.
        #[must_use]
        pub fn host(program: impl Into<PathBuf>, _args: Vec<String>) -> Self {
            Self {
                _program: program.into(),
            }
        }

        /// A companion run inside a prefix through its runner.
        #[must_use]
        pub fn in_prefix(
            program: impl Into<PathBuf>,
            args: Vec<String>,
            _prefix: &crate::Prefix,
        ) -> Self {
            Self::host(program, args)
        }

        /// Add environment variables for the child.
        #[must_use]
        pub fn env(self, _env: BTreeMap<String, String>) -> Self {
            self
        }

        /// Set the child's working directory.
        #[must_use]
        pub fn working_dir(self, _dir: impl Into<PathBuf>) -> Self {
            self
        }

        /// The prefix this companion runs in.
        #[must_use]
        pub fn prefix_ref(&self) -> Option<&crate::Prefix> {
            None
        }
    }

    /// How a companion process ended (see the Linux implementation).
    #[derive(Debug, Clone, PartialEq, Eq)]
    #[non_exhaustive]
    pub struct CompanionExit {
        /// The exit status, or `None` when the process was ended by a signal.
        pub code: Option<i32>,
    }

    /// A running companion. Constructed only by the Linux spawn path; here it is uninhabited, so it
    /// exists solely to satisfy cross-platform consumers.
    pub struct Companion(std::convert::Infallible);

    impl Companion {
        /// The unix PID of the spawned process.
        #[must_use]
        pub fn pid(&self) -> i32 {
            match self.0 {}
        }

        /// Wait for the companion to exit.
        pub async fn wait(&mut self) -> Result<CompanionExit, crate::RuntimeError> {
            match self.0 {}
        }

        /// The companion's exit if it has already ended.
        pub fn try_wait(&mut self) -> Result<Option<CompanionExit>, crate::RuntimeError> {
            match self.0 {}
        }

        /// Wait for the companion and its process group.
        pub async fn wait_group(&mut self) -> Result<CompanionExit, crate::RuntimeError> {
            match self.0 {}
        }

        /// Stop the companion and everything it started.
        pub async fn stop(&mut self, _grace: Duration) -> Result<(), crate::RuntimeError> {
            match self.0 {}
        }
    }

    impl std::fmt::Debug for Companion {
        fn fmt(&self, _f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match self.0 {}
        }
    }

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

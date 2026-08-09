//! The launch backend that drives `apogee-runtime`.
//!
//! `SystemWine` synthesizes a thin runner directory whose `wine`/`wineserver` shim to the host
//! tools, then adopts it as a custom runner (no download). `Managed` runners are fetched and verified
//! from the signed catalog. The plan the flow hands over is spawned as it stands, and the real game
//! process supervised: what it launches was settled before it got here.

use std::path::{Path, PathBuf};

use apogee_runtime::{
    Catalog, DxvkEnv, GameSession, HostCaps, LaunchPlan, Prefix, Progress, RunnerKind, Runtime,
    RuntimeError, RuntimeEvent,
};
use tokio::sync::mpsc::{self, UnboundedSender};
use tokio_util::sync::CancellationToken;
use url::Url;

use super::{Examined, GameHandle, LaunchBackend, Prepared};
use crate::command::{Event, LaunchProgramExit, Progress as CoreProgress};
use crate::error::CoreError;
use crate::model::RunnerSelection;

/// Whether a prefix has been created at `dir`, by the record every prepared one carries.
fn prefix_exists(dir: &Path) -> bool {
    dir.join(apogee_runtime::PREFIX_JSON).is_file()
}

/// The real launch backend over `apogee-runtime`.
pub(crate) struct RuntimeLauncher {
    runtime: Runtime,
    runners_dir: PathBuf,
}

impl RuntimeLauncher {
    /// Construct over an already-built runtime and the runners directory (where the system-wine
    /// wrapper is synthesized).
    pub(crate) fn new(runtime: Runtime, runners_dir: PathBuf) -> Self {
        Self {
            runtime,
            runners_dir,
        }
    }

    /// Bring the prefix's graphics translation up to what the catalog publishes, and describe what it
    /// ended up with.
    ///
    /// Never fails a launch. Translation is an improvement to a launch rather than a precondition for
    /// one, so a catalog that cannot be reached, or an install that goes wrong, leaves the game to
    /// start on whatever the prefix already had. `catalog` is the one already fetched to resolve a
    /// managed runner; `None` means fetch it, which is why an unreachable one has to be survivable.
    ///
    /// Installing is gated on what the prefix records, because the install itself is not idempotent:
    /// it re-downloads and re-copies every time it runs, and a launch is not the place for that.
    async fn ensure_dxvk(
        &self,
        prefix: &Prefix,
        catalog: Option<&Catalog>,
        force: bool,
        cancel: &CancellationToken,
        progress: &Progress,
    ) -> Result<Option<DxvkEnv>, CoreError> {
        let fetched;
        let catalog = match catalog {
            Some(catalog) => catalog,
            None => {
                let (manifest, signature) = catalog_urls()?;
                match self
                    .runtime
                    .fetch_catalog(&manifest, &signature, cancel)
                    .await
                {
                    Ok(catalog) => {
                        fetched = catalog;
                        &fetched
                    }
                    // A stop is the user's decision, not a catalog that could not be reached.
                    Err(error) if error.is_cancellation() => return Err(error.into()),
                    Err(error) => {
                        tracing::info!(%error, "no catalog reached; leaving the prefix as it is");
                        return Ok(self.recorded_dxvk(prefix));
                    }
                }
            }
        };
        // A catalog that publishes none leaves whatever is already there active, rather than
        // deactivating an install an earlier build made.
        let Some(entry) = catalog.default_dxvk() else {
            return Ok(self.recorded_dxvk(prefix));
        };

        let installed = prefix
            .metadata()
            .ok()
            .flatten()
            .and_then(|meta| meta.dxvk)
            .is_some_and(|dxvk| dxvk.version == entry.version);
        // Whatever the prefix already decided about the companion is kept: turning it off here would
        // stop overriding libraries that are sitting in the prefix.
        let nvapi = prefix
            .metadata()
            .ok()
            .flatten()
            .and_then(|meta| meta.dxvk)
            .is_some_and(|dxvk| dxvk.nvapi);
        // `force` is the repair case: the record says the right version is installed and the files
        // are not there, which is the one situation where the version gate is the wrong answer.
        if force || !installed {
            match self
                .runtime
                .install_dxvk(entry, prefix, nvapi, cancel, progress)
                .await
            {
                Ok(()) => {}
                // A stopped install stops the launch. Carrying on would spawn the game while the
                // user was still waiting for the thing they asked to stop.
                Err(error) if error.is_cancellation() => return Err(error.into()),
                Err(error) => {
                    tracing::warn!(%error, "graphics translation was not installed");
                    return Ok(self.recorded_dxvk(prefix));
                }
            }
        }
        Ok(Some(self.dxvk_env(prefix, nvapi)))
    }

    /// What the prefix already records, for the paths that could not install anything.
    fn recorded_dxvk(&self, prefix: &Prefix) -> Option<DxvkEnv> {
        let recorded = prefix.metadata().ok().flatten()?.dxvk?;
        Some(self.dxvk_env(prefix, recorded.nvapi))
    }

    /// The environment that activates a prefix's translation, with its shader cache kept beside the
    /// prefix it belongs to rather than in a location shared between prefixes.
    fn dxvk_env(&self, prefix: &Prefix, nvapi: bool) -> DxvkEnv {
        let cache = prefix.path().join("dxvk_cache");
        // Created here because the translation opens a file inside it rather than creating the path,
        // so a directory that is not there is a cache that silently never persists.
        if let Err(error) = std::fs::create_dir_all(&cache) {
            tracing::warn!(%error, path = %cache.display(), "no shader cache directory");
            return DxvkEnv {
                state_cache: None,
                nvapi,
            };
        }
        DxvkEnv {
            state_cache: Some(cache),
            nvapi,
        }
    }

    /// Prepare the prefix for `runner`, downloading a managed runner (and its umu tool) when needed.
    async fn prepare_prefix(
        &self,
        runner: &RunnerSelection,
        prefix_dir: &Path,
        cancel: &CancellationToken,
        progress: &Progress,
    ) -> Result<Prepared, CoreError> {
        // The host's own capabilities, before the runner narrows them.
        let host = HostCaps::detect();
        match runner {
            RunnerSelection::SystemWine => {
                let dir = synthesize_system_wine(&self.runners_dir)?;
                let prefix = self
                    .runtime
                    .prepare_custom(
                        &dir,
                        RunnerKind::Wine,
                        "system-wine",
                        prefix_dir,
                        cancel,
                        progress,
                    )
                    .await?;
                // The host's own wine is not a catalog row, so nothing declares what it supports.
                // Unstated reads as no for the same reason a row's silence does: ntsync is chosen by
                // setting no variable, so believing in it wrongly leaves the prefix with no
                // accelerated synchronization at all, while disbelieving it wrongly costs fsync.
                let dxvk = self.recorded_dxvk(&prefix);
                Ok(Prepared {
                    prefix: Some(prefix),
                    caps: HostCaps {
                        ntsync: false,
                        ..host
                    },
                    dxvk,
                    catalog: None,
                })
            }
            RunnerSelection::Managed { name, version } => {
                let (manifest, signature) = catalog_urls()?;
                let catalog = self
                    .runtime
                    .fetch_catalog(&manifest, &signature, cancel)
                    .await?;
                let entry = catalog
                    .runner(name, version)
                    .ok_or_else(|| {
                        CoreError::from(RuntimeError::RunnerUnavailable {
                            name: name.clone(),
                            version: version.clone(),
                        })
                    })?
                    .clone();
                if entry.kind == RunnerKind::ProtonUmu
                    && let Some(tool) = catalog.tool("umu-launcher")
                {
                    self.runtime.ensure_tool(tool, cancel, progress).await?;
                }
                let prefix = self
                    .runtime
                    .prepare(&entry, prefix_dir, cancel, progress)
                    .await?;
                let dxvk = self.recorded_dxvk(&prefix);
                Ok(Prepared {
                    prefix: Some(prefix),
                    caps: host.for_runner(&entry),
                    dxvk,
                    catalog: Some(catalog),
                })
            }
        }
    }
}

#[async_trait::async_trait]
impl LaunchBackend for RuntimeLauncher {
    async fn prepare(
        &self,
        runner: &RunnerSelection,
        prefix_dir: &Path,
        cancel: &CancellationToken,
        events: &UnboundedSender<Event>,
    ) -> Result<Prepared, CoreError> {
        let progress = relay_progress(events);
        let mut prepared = self
            .prepare_prefix(runner, prefix_dir, cancel, &progress)
            .await?;
        if let Some(prefix) = &prepared.prefix {
            prepared.dxvk = self
                .ensure_dxvk(prefix, prepared.catalog.as_ref(), false, cancel, &progress)
                .await?;
        }
        Ok(prepared)
    }

    async fn check_prefix(
        &self,
        runner: &RunnerSelection,
        prefix_dir: &Path,
        cancel: &CancellationToken,
        events: &UnboundedSender<Event>,
    ) -> Result<Option<Examined>, CoreError> {
        // A prefix that was never created has no drift, and building one to say so would be a
        // question about what is wrong creating the thing it asked about.
        if !prefix_exists(prefix_dir) {
            return Ok(None);
        }
        let progress = relay_progress(events);
        let prepared = self
            .prepare_prefix(runner, prefix_dir, cancel, &progress)
            .await?;
        let Some(prefix) = prepared.prefix else {
            return Ok(None);
        };
        let health = self.runtime.check_prefix(&prefix).await?;
        Ok(Some(Examined {
            prefix: Some(prefix),
            health,
        }))
    }

    async fn fix_prefix(
        &self,
        runner: &RunnerSelection,
        prefix_dir: &Path,
        cancel: &CancellationToken,
        events: &UnboundedSender<Event>,
    ) -> Result<Option<Examined>, CoreError> {
        let progress = relay_progress(events);
        let prepared = self
            .prepare_prefix(runner, prefix_dir, cancel, &progress)
            .await?;
        let Some(prefix) = prepared.prefix else {
            return Ok(None);
        };
        let health = self.runtime.check_prefix(&prefix).await?;
        if health.is_healthy() {
            return Ok(Some(Examined {
                prefix: Some(prefix),
                health,
            }));
        }
        if health
            .issues
            .iter()
            .any(|issue| matches!(issue, apogee_runtime::HealthIssue::MissingDxvkDll { .. }))
        {
            self.ensure_dxvk(&prefix, prepared.catalog.as_ref(), true, cancel, &progress)
                .await?;
        }
        let residual = self
            .runtime
            .repair_prefix(&prefix, &health.issues, cancel, &progress)
            .await?;
        Ok(Some(Examined {
            prefix: Some(prefix),
            health: residual,
        }))
    }

    async fn recreate_prefix(
        &self,
        runner: &RunnerSelection,
        prefix_dir: &Path,
        cancel: &CancellationToken,
        events: &UnboundedSender<Event>,
    ) -> Result<Option<apogee_runtime::Prefix>, CoreError> {
        let progress = relay_progress(events);
        // Preparing an absent prefix already builds a fresh one, so tearing it down to build it
        // again would be paying twice for the same result.
        let existed = prefix_exists(prefix_dir);
        let prepared = self
            .prepare_prefix(runner, prefix_dir, cancel, &progress)
            .await?;
        let Some(prefix) = prepared.prefix else {
            return Ok(None);
        };
        let prefix = if existed {
            self.runtime
                .recreate_prefix(&prefix, cancel, &progress)
                .await?
        } else {
            prefix
        };
        self.ensure_dxvk(&prefix, prepared.catalog.as_ref(), false, cancel, &progress)
            .await?;
        Ok(Some(prefix))
    }

    async fn launch(
        &self,
        plan: LaunchPlan,
        cancel: &CancellationToken,
        events: &UnboundedSender<Event>,
    ) -> Result<Box<dyn GameHandle>, CoreError> {
        let progress = relay_progress(events);
        let session = self.runtime.launch(plan, cancel, &progress).await?;
        Ok(Box::new(RuntimeGameHandle { session }))
    }
}

/// Wraps `apogee-runtime`'s supervised session, normalizing the opaque exit marker to `()`.
struct RuntimeGameHandle {
    session: GameSession,
}

#[async_trait::async_trait]
impl GameHandle for RuntimeGameHandle {
    fn prefix(&self) -> Option<apogee_runtime::Prefix> {
        Some(self.session.prefix().clone())
    }

    fn game_pid(&self) -> i32 {
        self.session.game_pid()
    }

    async fn wait(&self) -> Result<(), CoreError> {
        self.session.wait().await?;
        Ok(())
    }

    async fn kill(&self) -> Result<(), CoreError> {
        self.session.kill().await?;
        Ok(())
    }
}

/// Spawn a task relaying the runtime's stream onto `events`, returning the runtime progress sink to
/// hand to `apogee-runtime`.
///
/// The task outlives the call it was made for. A launch keeps a clone of the sink alive to report the
/// status of the program it spawned, which is not something the launch can wait for, so the relay ends
/// when that report lands rather than when `launch` returns.
fn relay_progress(events: &UnboundedSender<Event>) -> Progress {
    let (tx, mut rx) = mpsc::unbounded_channel();
    let events = events.clone();
    tokio::spawn(async move {
        while let Some(event) = rx.recv().await {
            if let Some(event) = to_core_event(event) {
                let _ = events.send(event);
            }
        }
    });
    Progress::new(tx)
}

/// The core event one runtime event becomes, or `None` for one the shell has no use for.
///
/// Most of the stream is the runtime narrating its own steps to itself; what crosses this seam is what
/// a user waits on (bytes) or has to be told (a companion's own report about whether it loaded).
fn to_core_event(event: RuntimeEvent) -> Option<Event> {
    match event {
        RuntimeEvent::Download(p) => Some(Event::Progress(CoreProgress {
            completed: p.bytes_done,
            total: p.total.unwrap_or(0),
        })),
        // Passed through with the status untouched. This layer knows a program was redirected and not
        // which companion did it, so it adds nothing and hides nothing.
        RuntimeEvent::LaunchProgramExited { program, status } => {
            Some(Event::LaunchProgramExited(LaunchProgramExit {
                program,
                status,
            }))
        }
        _ => None,
    }
}

/// Resolve the runner catalog manifest and signature URLs. The catalog is hosted at a fixed HTTPS
/// location with the detached signature beside it under the same name plus `.sig`.
/// `APOGEE_RUNNER_CATALOG_URL` overrides the manifest URL for a mirror or a pre-deploy test. The
/// override cannot weaken trust: the Ed25519 signature over the manifest is the authenticity gate
/// regardless of origin, and the fetcher refuses plain `http`.
fn catalog_urls() -> Result<(Url, Url), CoreError> {
    let manifest = std::env::var("APOGEE_RUNNER_CATALOG_URL")
        .unwrap_or_else(|_| "https://soleynn.github.io/apogee/runners/manifest.json".to_owned());
    let signature = format!("{manifest}.sig");
    Ok((parse_url(&manifest)?, parse_url(&signature)?))
}

fn parse_url(raw: &str) -> Result<Url, CoreError> {
    Url::parse(raw).map_err(|e| CoreError::Launch {
        detail: format!("catalog url {raw:?}: {e}"),
    })
}

/// Create (idempotently) a thin runner directory whose `wine`/`wineserver` shim to the host tools,
/// so the system wine can be adopted as a custom runner. Returns the runner directory.
fn synthesize_system_wine(runners_dir: &Path) -> Result<PathBuf, CoreError> {
    let dir = runners_dir.join("system-wine");
    let bin = dir.join("bin");
    std::fs::create_dir_all(&bin).map_err(launch_io(&bin))?;
    write_shim(&bin.join("wine"), "wine")?;
    write_shim(&bin.join("wineserver"), "wineserver")?;
    Ok(dir)
}

/// Write an executable `#!/bin/sh` shim that execs the host `tool`.
fn write_shim(path: &Path, tool: &str) -> Result<(), CoreError> {
    let script = format!("#!/bin/sh\nexec {tool} \"$@\"\n");
    std::fs::write(path, script).map_err(launch_io(path))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755))
            .map_err(launch_io(path))?;
    }
    Ok(())
}

fn launch_io(path: &Path) -> impl Fn(std::io::Error) -> CoreError + '_ {
    move |source| CoreError::Launch {
        detail: format!("{}: {source}", path.display()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn synthesize_system_wine_writes_executable_shims() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = synthesize_system_wine(tmp.path()).unwrap();

        let wine = dir.join("bin/wine");
        let wineserver = dir.join("bin/wineserver");
        assert!(wine.is_file());
        assert!(wineserver.is_file());
        assert!(
            std::fs::read_to_string(&wine)
                .unwrap()
                .contains("exec wine")
        );

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&wine).unwrap().permissions().mode();
            assert_eq!(mode & 0o111, 0o111, "wine shim must be executable");
        }

        // Idempotent: a second call over the same directory succeeds.
        assert_eq!(synthesize_system_wine(tmp.path()).unwrap(), dir);
    }

    /// The one report a launch cannot reconstruct from anything else has to cross the seam, and cross it
    /// with the status as it was read. A relay that dropped it is the hole this arm exists to close.
    #[test]
    fn a_launch_programs_status_reaches_the_shell_uninterpreted() {
        let event = to_core_event(RuntimeEvent::LaunchProgramExited {
            program: "/loader/Loader.exe".to_owned(),
            status: apogee_runtime::ProgramStatus::Code(3),
        });

        let Some(Event::LaunchProgramExited(exit)) = event else {
            panic!("the status did not reach the shell: {event:?}");
        };
        assert_eq!(exit.program, "/loader/Loader.exe");
        assert_eq!(exit.status, apogee_runtime::ProgramStatus::Code(3));
    }

    /// The rest of the runtime's stream is it narrating its own steps. Forwarding those would put a line
    /// in front of the user for every prefix and every scan, none of which is theirs to act on.
    #[test]
    fn the_runtimes_own_steps_stop_at_the_seam() {
        assert!(to_core_event(RuntimeEvent::GameResolved { pid: 42 }).is_none());
        assert!(to_core_event(RuntimeEvent::PrefixReady).is_none());
    }
}

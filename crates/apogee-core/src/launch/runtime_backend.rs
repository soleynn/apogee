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

use super::{GameHandle, LaunchBackend, Prepared};
use crate::command::{Event, Progress as CoreProgress};
use crate::error::CoreError;
use crate::model::RunnerSelection;

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
        cancel: &CancellationToken,
        progress: &Progress,
    ) -> Option<DxvkEnv> {
        let fetched;
        let catalog = match catalog {
            Some(catalog) => catalog,
            None => {
                let (manifest, signature) = catalog_urls().ok()?;
                match self
                    .runtime
                    .fetch_catalog(&manifest, &signature, cancel)
                    .await
                {
                    Ok(catalog) => {
                        fetched = catalog;
                        &fetched
                    }
                    Err(error) => {
                        tracing::info!(%error, "no catalog reached; leaving the prefix as it is");
                        return self.recorded_dxvk(prefix);
                    }
                }
            }
        };
        let entry = catalog.default_dxvk()?;

        let installed = prefix
            .metadata()
            .ok()
            .flatten()
            .and_then(|meta| meta.dxvk)
            .is_some_and(|dxvk| dxvk.version == entry.version);
        if !installed {
            // Companion translation stays off until something asks for it: it is only useful on one
            // vendor's hardware, and nothing here knows which is present.
            if let Err(error) = self
                .runtime
                .install_dxvk(entry, prefix, false, cancel, progress)
                .await
            {
                tracing::warn!(%error, "graphics translation was not installed");
                return self.recorded_dxvk(prefix);
            }
        }
        Some(self.dxvk_env(prefix, false))
    }

    /// What the prefix already records, for the paths that could not install anything.
    fn recorded_dxvk(&self, prefix: &Prefix) -> Option<DxvkEnv> {
        let recorded = prefix.metadata().ok().flatten()?.dxvk?;
        Some(self.dxvk_env(prefix, recorded.nvapi))
    }

    /// The environment that activates a prefix's translation, with its shader cache kept beside the
    /// prefix it belongs to rather than in a location shared between prefixes.
    fn dxvk_env(&self, prefix: &Prefix, nvapi: bool) -> DxvkEnv {
        DxvkEnv {
            state_cache: Some(prefix.path().join("dxvk_cache")),
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
                let dxvk = self.ensure_dxvk(&prefix, None, cancel, progress).await;
                Ok(Prepared {
                    prefix: Some(prefix),
                    caps: HostCaps {
                        ntsync: false,
                        ..host
                    },
                    dxvk,
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
                let dxvk = self
                    .ensure_dxvk(&prefix, Some(&catalog), cancel, progress)
                    .await;
                Ok(Prepared {
                    prefix: Some(prefix),
                    caps: host.for_runner(&entry),
                    dxvk,
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
        self.prepare_prefix(runner, prefix_dir, cancel, &progress)
            .await
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

/// Spawn a task relaying runner download progress onto `events` as core progress, returning the
/// runtime progress sink to hand to `apogee-runtime`.
fn relay_progress(events: &UnboundedSender<Event>) -> Progress {
    let (tx, mut rx) = mpsc::unbounded_channel();
    let events = events.clone();
    tokio::spawn(async move {
        while let Some(event) = rx.recv().await {
            if let RuntimeEvent::Download(p) = event {
                let _ = events.send(Event::Progress(CoreProgress {
                    completed: p.bytes_done,
                    total: p.total.unwrap_or(0),
                }));
            }
        }
    });
    Progress::new(tx)
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
}

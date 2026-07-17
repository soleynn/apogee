//! The launch backend that drives `apogee-runtime`.
//!
//! `SystemWine` synthesizes a thin runner directory whose `wine`/`wineserver` shim to the host
//! tools, then adopts it as a custom runner (no download). `Managed` runners are fetched and verified
//! from the signed catalog. The prepared prefix is launched and the real game process supervised.

use std::path::{Path, PathBuf};

use apogee_runtime::{
    GameSession, LaunchPlan, Prefix, Progress, RunnerKind, Runtime, RuntimeError, RuntimeEvent,
};
use tokio::sync::mpsc::{self, UnboundedSender};
use tokio_util::sync::CancellationToken;
use url::Url;

use super::{GameHandle, LaunchBackend, LaunchRequest};
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

    /// Prepare the prefix for `runner`, downloading a managed runner (and its umu tool) when needed.
    async fn prepare_prefix(
        &self,
        runner: &RunnerSelection,
        prefix_dir: &Path,
        cancel: &CancellationToken,
        progress: &Progress,
    ) -> Result<Prefix, CoreError> {
        match runner {
            RunnerSelection::SystemWine => {
                let dir = synthesize_system_wine(&self.runners_dir)?;
                Ok(self
                    .runtime
                    .prepare_custom(&dir, RunnerKind::Wine, "system-wine", prefix_dir)
                    .await?)
            }
            RunnerSelection::Managed { name, version } => {
                // Where the signed runner catalog is fetched from. Hosting and the production signing
                // key are still being settled; the system-wine path needs neither and covers launch
                // today.
                let manifest = parse_url("https://apogee.example.invalid/runners/manifest.json")?;
                let signature =
                    parse_url("https://apogee.example.invalid/runners/manifest.json.sig")?;
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
                Ok(self
                    .runtime
                    .prepare(&entry, prefix_dir, cancel, progress)
                    .await?)
            }
        }
    }
}

#[async_trait::async_trait]
impl LaunchBackend for RuntimeLauncher {
    async fn launch(
        &self,
        req: LaunchRequest,
        cancel: &CancellationToken,
        events: &UnboundedSender<Event>,
    ) -> Result<Box<dyn GameHandle>, CoreError> {
        let progress = relay_progress(events);
        let prefix = self
            .prepare_prefix(&req.runner, &req.prefix_dir, cancel, &progress)
            .await?;
        let mut plan = LaunchPlan::new(req.program, req.encrypted_args, req.env)
            .prefix(&prefix)
            .working_dir(req.working_dir);
        if !req.wrappers.is_empty() {
            plan = plan.wrappers(req.wrappers);
        }
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

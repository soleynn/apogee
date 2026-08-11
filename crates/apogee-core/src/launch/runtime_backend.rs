//! The launch backend that drives `apogee-runtime`.
//!
//! `SystemWine` synthesizes a thin runner directory whose `wine`/`wineserver` shim to the host
//! tools, then adopts it as a custom runner (no download). `Managed` runners are fetched and verified
//! from the signed catalog. The plan the flow hands over is spawned as it stands, and the real game
//! process supervised: what it launches was settled before it got here.

use std::path::{Path, PathBuf};

use apogee_runtime::{
    Catalog, DxvkEnv, DxvkRef, GameSession, HostCaps, LaunchPlan, Prefix, PrefixWants, Progress,
    RunnerKind, Runtime, RuntimeError, RuntimeEvent,
};
use tokio::sync::mpsc::{self, UnboundedSender};
use tokio_util::sync::CancellationToken;
use url::Url;

use super::{Examined, GameHandle, LaunchBackend, PrefixRequest, Prepared};
use crate::command::{Event, LaunchProgramExit, Progress as CoreProgress};
use crate::error::CoreError;
use crate::model::RunnerSelection;

/// Whether a prefix has been created at `dir`, by the record every prepared one carries.
fn prefix_exists(dir: &Path) -> bool {
    dir.join(apogee_runtime::PREFIX_JSON).is_file()
}

/// The half of a health check the prefix cannot answer about itself: what the profile asked of it.
///
/// The runtime diagnoses a prefix against its own record, which says what the prefix *has*, so a
/// profile that wants the companion on a prefix without it reads as nothing wrong unless the wish is
/// handed down. This is the same composition as [`PrefixReport`](crate::PrefixReport), one layer
/// lower: the runtime holds the facts about the prefix, this crate holds the profile, and putting
/// them together is what a composition root is for.
fn wants(request: &PrefixRequest) -> PrefixWants {
    PrefixWants {
        nvapi: request.nvapi,
    }
}

/// Whether a check's findings need the DXVK install re-run, and whether it has to be forced past the
/// version gate. `None` is nothing for the install to do.
///
/// Two problems resolve this way rather than by a repair, and only one of them wants the force. A DLL
/// the record claims and the prefix does not have is the one case where the version gate is the wrong
/// answer, since the record already says the published version is installed. A companion that was
/// asked for and never placed is *not* current by that same gate, so it installs on its own; forcing
/// there would re-download the whole of DXVK to reach a conclusion the gate had already reached.
fn dxvk_install_for(issues: &[apogee_runtime::HealthIssue]) -> Option<bool> {
    use apogee_runtime::HealthIssue;
    let missing_dll = issues
        .iter()
        .any(|issue| matches!(issue, HealthIssue::MissingDxvkDll { .. }));
    let missing_nvapi = issues
        .iter()
        .any(|issue| matches!(issue, HealthIssue::MissingNvapi));
    (missing_dll || missing_nvapi).then_some(missing_dll)
}

/// Whether the prefix already has everything an install would place: the version the catalog
/// publishes, and the `dxvk-nvapi` companion where one was asked for *and* the catalog pins one.
///
/// A free function so each half is reachable on its own. The companion half is the one with no other
/// way to be noticed: a prefix on the published version whose profile has just opted into the
/// companion passes a version-only gate, and passing it means the companion's DLLs are never placed,
/// because the install that would place them is the only thing that ever does.
///
/// `nvapi` is what the *catalog* can deliver rather than what the profile asked for, since an install
/// only ever records what it placed. Reading the profile's wish here instead makes a row that pins no
/// companion re-download and re-copy the whole of DXVK on every single launch, chasing a record the
/// install cannot write.
fn dxvk_is_current(recorded: Option<&DxvkRef>, version: &str, nvapi: bool) -> bool {
    let Some(recorded) = recorded else {
        return false;
    };
    recorded.version == version && (recorded.nvapi || !nvapi)
}

/// Whether this launch overrides the prefix's nvapi DLLs onto the companion.
///
/// Both halves are required, and they are different facts. The record is what the prefix physically
/// has, which an install honors only where the catalog pins a companion to honor it with; the flag is
/// what the profile asked for. Overriding onto DLLs that were never placed is a prefix that will not
/// start, and overriding because they happen to be there hands a profile a companion it turned off,
/// which is also the only way one can ever be turned off again: nothing uninstalls it.
fn activates_nvapi(recorded: Option<&DxvkRef>, nvapi: bool) -> bool {
    nvapi && recorded.is_some_and(|dxvk| dxvk.nvapi)
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
    ///
    /// `nvapi` is the profile's opt-in to the `dxvk-nvapi` companion. It decides two separate things:
    /// whether an install places the companion's DLLs, and whether this launch overrides onto them.
    /// Only the first is permanent, which is what lets two profiles share one prefix and disagree.
    async fn ensure_dxvk(
        &self,
        prefix: &Prefix,
        catalog: Option<&Catalog>,
        nvapi: bool,
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
                        return Ok(self.recorded_dxvk(prefix, nvapi));
                    }
                }
            }
        };
        // A catalog that publishes none leaves whatever is already there active, rather than
        // deactivating an install an earlier build made.
        let Some(entry) = catalog.default_dxvk() else {
            return Ok(self.recorded_dxvk(prefix, nvapi));
        };

        let recorded = prefix.metadata().ok().flatten().and_then(|meta| meta.dxvk);
        // What the install would actually place: the companion only where the row pins one.
        let places_nvapi = nvapi && entry.nvapi.is_some();
        let installed = dxvk_is_current(recorded.as_ref(), &entry.version, places_nvapi);
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
                    return Ok(self.recorded_dxvk(prefix, nvapi));
                }
            }
        }
        // Read again rather than reusing what the gate saw: an install rewrites the record, and what
        // it wrote is the only account of whether the companion was actually placed.
        let recorded = prefix.metadata().ok().flatten().and_then(|meta| meta.dxvk);
        Ok(Some(self.dxvk_env(
            prefix,
            activates_nvapi(recorded.as_ref(), nvapi),
        )))
    }

    /// What the prefix already records, for the paths that could not install anything. `nvapi` is the
    /// profile's opt-in, resolved against the record by [`activates_nvapi`].
    fn recorded_dxvk(&self, prefix: &Prefix, nvapi: bool) -> Option<DxvkEnv> {
        let recorded = prefix.metadata().ok().flatten()?.dxvk?;
        Some(self.dxvk_env(prefix, activates_nvapi(Some(&recorded), nvapi)))
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

    /// Prepare the prefix `request` asks for, downloading a managed runner (and its umu tool) when
    /// needed.
    async fn prepare_prefix(
        &self,
        request: &PrefixRequest,
        prefix_dir: &Path,
        cancel: &CancellationToken,
        progress: &Progress,
    ) -> Result<Prepared, CoreError> {
        // The host's own capabilities, before the runner narrows them.
        let host = HostCaps::detect();
        match &request.runner {
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
                let dxvk = self.recorded_dxvk(&prefix, request.nvapi);
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
                let dxvk = self.recorded_dxvk(&prefix, request.nvapi);
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
        request: &PrefixRequest,
        prefix_dir: &Path,
        cancel: &CancellationToken,
        events: &UnboundedSender<Event>,
    ) -> Result<Prepared, CoreError> {
        let progress = relay_progress(events);
        let mut prepared = self
            .prepare_prefix(request, prefix_dir, cancel, &progress)
            .await?;
        if let Some(prefix) = &prepared.prefix {
            prepared.dxvk = self
                .ensure_dxvk(
                    prefix,
                    prepared.catalog.as_ref(),
                    request.nvapi,
                    false,
                    cancel,
                    &progress,
                )
                .await?;
        }
        Ok(prepared)
    }

    async fn check_prefix(
        &self,
        request: &PrefixRequest,
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
            .prepare_prefix(request, prefix_dir, cancel, &progress)
            .await?;
        let Some(prefix) = prepared.prefix else {
            return Ok(None);
        };
        let health = self.runtime.check_prefix(&prefix, &wants(request)).await?;
        Ok(Some(Examined {
            prefix: Some(prefix),
            health,
        }))
    }

    async fn fix_prefix(
        &self,
        request: &PrefixRequest,
        prefix_dir: &Path,
        cancel: &CancellationToken,
        events: &UnboundedSender<Event>,
    ) -> Result<Option<Examined>, CoreError> {
        let progress = relay_progress(events);
        let prepared = self
            .prepare_prefix(request, prefix_dir, cancel, &progress)
            .await?;
        let Some(prefix) = prepared.prefix else {
            return Ok(None);
        };
        let health = self.runtime.check_prefix(&prefix, &wants(request)).await?;
        if health.is_healthy() {
            return Ok(Some(Examined {
                prefix: Some(prefix),
                health,
            }));
        }
        if let Some(force) = dxvk_install_for(&health.issues) {
            self.ensure_dxvk(
                &prefix,
                prepared.catalog.as_ref(),
                request.nvapi,
                force,
                cancel,
                &progress,
            )
            .await?;
        }
        let residual = self
            .runtime
            .repair_prefix(&prefix, &health.issues, &wants(request), cancel, &progress)
            .await?;
        Ok(Some(Examined {
            prefix: Some(prefix),
            health: residual,
        }))
    }

    async fn recreate_prefix(
        &self,
        request: &PrefixRequest,
        prefix_dir: &Path,
        cancel: &CancellationToken,
        events: &UnboundedSender<Event>,
    ) -> Result<Option<apogee_runtime::Prefix>, CoreError> {
        let progress = relay_progress(events);
        // Preparing an absent prefix already builds a fresh one, so tearing it down to build it
        // again would be paying twice for the same result.
        let existed = prefix_exists(prefix_dir);
        let prepared = self
            .prepare_prefix(request, prefix_dir, cancel, &progress)
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
        self.ensure_dxvk(
            &prefix,
            prepared.catalog.as_ref(),
            request.nvapi,
            false,
            cancel,
            &progress,
        )
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
/// The task outlives the call it was made for: a launch keeps a clone of the sink alive to report the
/// status of the program it spawned, and under a container-style runner that program outlives the whole
/// session. So the relay holds a **weak** sender. A strong one would keep the flow's event stream open
/// for as long as that program ran, and a launcher told to detach once the game is up would sit there
/// for the rest of the session instead, looking like it had hung.
///
/// Upgrading per send is also what implements "a late status is dropped rather than held for": once the
/// flow has finished and let go of its sender there is nobody left to tell, so the report goes nowhere.
/// The flow holds its sender across every call that relays here, so nothing in flight is lost.
fn relay_progress(events: &UnboundedSender<Event>) -> Progress {
    let (tx, mut rx) = mpsc::unbounded_channel();
    let events = events.downgrade();
    tokio::spawn(async move {
        while let Some(event) = rx.recv().await {
            let Some(event) = to_core_event(event) else {
                continue;
            };
            let Some(sender) = events.upgrade() else {
                break;
            };
            let _ = sender.send(event);
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
            recoveries: p.recoveries,
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

    /// A download's recovery tally survives the seam into the core event stream.
    ///
    /// This is the exact conversion that has always dropped `phase`, and it drops it silently
    /// because nothing here has to acknowledge the field. The tally would have gone the same way.
    #[test]
    fn a_download_relays_its_recovery_tally_to_the_shell() {
        let mut progress = apogee_fetch::Progress::default();
        progress.bytes_done = 4096;
        progress.total = Some(8192);
        progress.recoveries.retries = 3;
        progress.recoveries.stalls = 1;
        progress.recoveries.demoted = true;

        let event = to_core_event(RuntimeEvent::Download(progress));

        let Some(Event::Progress(relayed)) = event else {
            panic!("a download must relay as a progress event, got {event:?}");
        };
        assert_eq!(relayed.completed, 4096);
        assert_eq!(relayed.total, 8192);
        assert_eq!(relayed.recoveries.retries, 3);
        assert_eq!(relayed.recoveries.stalls, 1);
        assert!(relayed.recoveries.demoted);
    }

    /// The ordinary case still arrives clean, so the field above is the transfer's own trouble and
    /// not something this seam invents.
    #[test]
    fn a_healthy_download_relays_a_clean_tally() {
        let mut progress = apogee_fetch::Progress::default();
        progress.bytes_done = 1024;
        progress.total = Some(1024);
        let Some(Event::Progress(relayed)) = to_core_event(RuntimeEvent::Download(progress)) else {
            panic!("a download must relay as a progress event");
        };
        assert!(relayed.recoveries.is_clean());
    }

    /// A record for `version`, with or without the companion.
    fn recorded(version: &str, nvapi: bool) -> DxvkRef {
        DxvkRef {
            version: version.to_owned(),
            nvapi,
        }
    }

    /// The version gate on its own: a prefix on the published build has nothing to do, and one on an
    /// older build or none at all does.
    #[test]
    fn the_published_version_is_installed_only_when_the_prefix_is_behind_it() {
        assert!(dxvk_is_current(Some(&recorded("2.7", false)), "2.7", false));
        assert!(!dxvk_is_current(
            Some(&recorded("2.6", false)),
            "2.7",
            false
        ));
        assert!(!dxvk_is_current(None, "2.7", false));
    }

    /// Opting into the companion on a prefix that is already on the published version still installs.
    ///
    /// The version gate passes here, and passing it is the whole problem: the install is the only
    /// thing that ever places the companion's DLLs, so a gate that reads the version alone leaves
    /// the opt-in unable to take effect on any prefix that is up to date, which is all of them.
    #[test]
    fn asking_for_the_companion_installs_though_the_version_already_matches() {
        assert!(!dxvk_is_current(Some(&recorded("2.7", false)), "2.7", true));
    }

    /// Once it is there, asking for it again is nothing to do: the install re-downloads and re-copies
    /// every time it runs, and every launch would pay for it.
    #[test]
    fn a_prefix_that_already_has_the_companion_installs_nothing() {
        assert!(dxvk_is_current(Some(&recorded("2.7", true)), "2.7", true));
    }

    /// Not asking for it does not reinstall to take it away. The DLLs stay where they are and the
    /// launch simply does not override onto them, so the profile that shares this prefix and does
    /// want them keeps working.
    #[test]
    fn not_asking_for_the_companion_leaves_an_installed_one_alone() {
        assert!(dxvk_is_current(Some(&recorded("2.7", true)), "2.7", false));
    }

    /// A launch overrides onto the companion only where both halves agree.
    ///
    /// The prefix's half is the one that cannot be argued with: a launch that overrides `nvapi64` onto
    /// a DLL no install ever placed is a game that does not start. The profile's half is the only way
    /// the companion is ever turned back off, because nothing uninstalls it: the DLLs stay in
    /// `system32` and the override is what stops pointing at them.
    #[rstest::rstest]
    #[case(Some(&recorded("2.7", true)), true, true)]
    #[case(Some(&recorded("2.7", true)), false, false)]
    #[case(Some(&recorded("2.7", false)), true, false)]
    #[case(None, true, false)]
    fn the_companion_is_activated_only_where_the_prefix_has_it_and_the_profile_asked(
        #[case] recorded: Option<&DxvkRef>,
        #[case] nvapi: bool,
        #[case] expected: bool,
    ) {
        assert_eq!(activates_nvapi(recorded, nvapi), expected);
    }

    /// A catalog row that pins no companion is nothing to chase.
    ///
    /// The gate reads what an install would place, not what the profile asked for, and this is why: an
    /// install only records what it placed, so a wish it cannot honor would leave the record short of
    /// the gate forever. Every launch would then re-download and re-copy the whole of DXVK to write
    /// the same record again.
    #[test]
    fn a_catalog_with_no_companion_settles_instead_of_reinstalling_every_launch() {
        // What `ensure_dxvk` computes for a row whose `nvapi` pin is absent.
        let places_nvapi = false;
        assert!(dxvk_is_current(
            Some(&recorded("2.7", false)),
            "2.7",
            places_nvapi
        ));
    }

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

    /// A launch holds its progress sink open until the program it spawned exits, which under a
    /// container-style runner is the whole session. The relay must not turn that into a hold on the
    /// flow's own stream: a launcher told to detach once the game is up would stay attached for hours,
    /// which is indistinguishable from having hung.
    #[tokio::test]
    async fn the_event_stream_closes_though_a_launchs_program_is_still_running() {
        let (tx, mut rx) = mpsc::unbounded_channel();
        let progress = relay_progress(&tx);

        // The flow finished and let go of its sender; the launch's sink is still alive.
        drop(tx);

        let ended = tokio::time::timeout(std::time::Duration::from_secs(5), rx.recv()).await;
        assert!(
            matches!(ended, Ok(None)),
            "the stream was held open by the relay: {ended:?}"
        );
        drop(progress);
    }
}

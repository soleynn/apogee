//! Installing what the signed manifest offers, and turning what is installed into a launch.
//!
//! Three things hold across this module.
//!
//! Installing is idempotent, and the prefix's own `prefix.json` is what makes it so. Nothing here keeps
//! a list of its own about what a prefix has, because a second list is a second thing that can be wrong
//! about a prefix somebody else also writes into.
//!
//! One component failing costs the user that component. The call fails as a whole only for something
//! structural, like a name no row offers; a download that breaks or a verb that a wine refuses is
//! recorded against its own name and the rest of the set continues.
//!
//! A component's caveats reach the caller as events while it installs, not as a field on the report.
//! The whole reason they exist is to be read at the moment the thing is set up.

mod artifact;
mod event;
mod plan;
mod verb;

use std::path::{Path, PathBuf};

use apogee_fetch::Fetcher;
use apogee_runtime::{Prefix, Runtime};
use tokio_util::sync::CancellationToken;
use url::Url;

pub use event::{ComponentEvent, ComponentEvents};
pub use plan::{EnsurePlan, PlanStep, StepAction, StepKind};

use crate::external::{ExternalAddon, RunIn};
use crate::manifest::{ComponentManifest, ToolEntry, ToolKind};
use crate::{AddonError, AddonPaths, Result};

/// Where a native component's install marker lives, so a component shared by two profiles is fetched
/// once rather than once per prefix. Outside the extracted tree, so an archive entry cannot plant one
/// and a half-finished extraction cannot leave a stale one.
const NATIVE_INSTALLED_DIR: &str = ".installed";

/// What became of one component.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ComponentState {
    /// Installed now, and recorded in the prefix.
    Installed,
    /// The prefix already recorded it, so nothing was done.
    AlreadyPresent,
    /// Could not be installed. The rest of the set is unaffected.
    Failed { reason: String },
    /// Offered by the manifest but not something this build drives.
    Unsupported { what: String },
}

/// One component and what became of it.
#[derive(Debug, Clone)]
pub struct ComponentOutcome {
    pub name: String,
    pub state: ComponentState,
}

/// Everything one ensure did.
#[derive(Debug, Clone, Default)]
pub struct ComponentReport {
    /// One per planned step, in plan order, which includes the verbs a tool pulled in.
    pub outcomes: Vec<ComponentOutcome>,
}

impl ComponentReport {
    /// Whether anything failed. What that is worth is the caller's decision.
    #[must_use]
    pub fn any_failed(&self) -> bool {
        self.outcomes
            .iter()
            .any(|o| matches!(o.state, ComponentState::Failed { .. }))
    }

    /// The names that are now installed, whether this run put them there or found them.
    #[must_use]
    pub fn present(&self) -> Vec<&str> {
        self.outcomes
            .iter()
            .filter(|o| {
                matches!(
                    o.state,
                    ComponentState::Installed | ComponentState::AlreadyPresent
                )
            })
            .map(|o| o.name.as_str())
            .collect()
    }
}

/// Fetch the signed manifest and its detached signature over HTTPS, then verify against the compiled-in
/// key. The manifest's own bytes are not pinned ahead of time; the signature is the authenticity gate.
pub(crate) async fn fetch_manifest(
    fetcher: &Fetcher,
    manifest_url: &Url,
    signature_url: &Url,
    cache_dir: &Path,
    cancel: &CancellationToken,
) -> Result<ComponentManifest> {
    tokio::fs::create_dir_all(cache_dir)
        .await
        .map_err(|source| artifact::io_failed("manifest", "cache", cache_dir, source))?;
    let manifest_path = cache_dir.join("components.json");
    let signature_path = cache_dir.join("components.json.sig");
    download_unverified(fetcher, manifest_url, &manifest_path, cancel).await?;
    download_unverified(fetcher, signature_url, &signature_path, cancel).await?;

    let manifest = tokio::fs::read(&manifest_path)
        .await
        .map_err(|source| artifact::io_failed("manifest", "read", &manifest_path, source))?;
    let signature = tokio::fs::read(&signature_path)
        .await
        .map_err(|source| artifact::io_failed("manifest", "read", &signature_path, source))?;
    Ok(ComponentManifest::verify_default(&manifest, &signature)?)
}

/// The last manifest a fetch verified and left in `cache_dir`, re-verified before it is handed back.
///
/// `None` when nothing has been fetched yet. A signature check stands between the cache and every caller,
/// so this is a freshness fallback and never a trust one: the worst it can serve is yesterday's rows,
/// which for a launch beats starting no companions at all. Whether that trade is the right one is the
/// caller's to make, which is why fetching and reading the cache are separate calls.
pub(crate) async fn cached_manifest(cache_dir: &Path) -> Result<Option<ComponentManifest>> {
    let manifest_path = cache_dir.join("components.json");
    let signature_path = cache_dir.join("components.json.sig");
    let (Ok(manifest), Ok(signature)) = (
        tokio::fs::read(&manifest_path).await,
        tokio::fs::read(&signature_path).await,
    ) else {
        return Ok(None);
    };
    Ok(Some(ComponentManifest::verify_default(
        &manifest, &signature,
    )?))
}

/// Download `url` to `dest` over HTTPS with no content pin, because the caller authenticates these bytes
/// with an Ed25519 signature instead. The fetcher refuses this over plain `http`.
async fn download_unverified(
    fetcher: &Fetcher,
    url: &Url,
    dest: &Path,
    cancel: &CancellationToken,
) -> Result<()> {
    let spec =
        apogee_fetch::DownloadSpec::builder(url.clone(), dest, apogee_fetch::Validator::None)
            .allow_unverified()
            .build()?;
    fetcher.download(&spec, None, cancel.clone()).await?;
    Ok(())
}

/// Install every component in `wanted` into `prefix`, applying the verbs they ask for first.
///
/// # Errors
/// [`AddonError::UnknownComponent`] if a name is in no list, or [`AddonError::PrefixJson`]'s runtime
/// equivalent if the prefix's record cannot be read: without it there is no way to tell an install that
/// is needed from one that is not, and re-running everything against a live prefix is worse than
/// stopping.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn ensure(
    runtime: &Runtime,
    fetcher: &Fetcher,
    paths: &AddonPaths,
    manifest: &ComponentManifest,
    prefix: &Prefix,
    wanted: &[String],
    cancel: &CancellationToken,
    events: &ComponentEvents,
) -> Result<ComponentReport> {
    let installed = prefix.components().map_err(|source| AddonError::Install {
        component: "prefix".to_owned(),
        step: "read the prefix record",
        source: Box::new(source),
    })?;
    let plan = EnsurePlan::build(manifest, wanted, &installed)?;

    // One scratch directory per prefix, so two installs into different prefixes cannot clobber each
    // other's staging, and removed at the end whatever happened.
    let work = artifact::work_dir(prefix.path());
    let mut report = ComponentReport::default();

    for step in plan.steps() {
        match &step.action {
            StepAction::AlreadyPresent => {
                events.emit(ComponentEvent::AlreadyPresent {
                    component: step.name.clone(),
                });
                report.outcomes.push(ComponentOutcome {
                    name: step.name.clone(),
                    state: ComponentState::AlreadyPresent,
                });
            }
            StepAction::Unsupported { what } => {
                events.emit(ComponentEvent::Unsupported {
                    component: step.name.clone(),
                    what: (*what).to_owned(),
                });
                report.outcomes.push(ComponentOutcome {
                    name: step.name.clone(),
                    state: ComponentState::Unsupported {
                        what: (*what).to_owned(),
                    },
                });
            }
            StepAction::Install => {
                let outcome = match step.kind {
                    StepKind::Verb => {
                        apply_verb(
                            runtime, fetcher, manifest, prefix, &step.name, &work, cancel, events,
                        )
                        .await
                    }
                    StepKind::Tool(_) => {
                        install_tool(
                            fetcher, paths, manifest, prefix, &step.name, &work, cancel, events,
                        )
                        .await
                    }
                };
                let state = match outcome {
                    Ok(()) => ComponentState::Installed,
                    Err(err) => {
                        let reason = describe(&err);
                        events.emit(ComponentEvent::Failed {
                            component: step.name.clone(),
                            reason: reason.clone(),
                        });
                        ComponentState::Failed { reason }
                    }
                };
                report.outcomes.push(ComponentOutcome {
                    name: step.name.clone(),
                    state,
                });
            }
        }
    }

    let _ = tokio::fs::remove_dir_all(&work).await;
    Ok(report)
}

/// Apply one verb and record it. Recorded only on success, so a failed apply is retried next time
/// rather than remembered as done.
#[allow(clippy::too_many_arguments)]
async fn apply_verb(
    runtime: &Runtime,
    fetcher: &Fetcher,
    manifest: &ComponentManifest,
    prefix: &Prefix,
    name: &str,
    work: &Path,
    cancel: &CancellationToken,
    events: &ComponentEvents,
) -> Result<()> {
    let row = manifest
        .verb(name)
        .ok_or_else(|| AddonError::UnknownComponent {
            name: name.to_owned(),
        })?;
    events.emit(ComponentEvent::Applying {
        verb: row.name.clone(),
        reason: row.reason.clone(),
    });
    verb::apply(runtime, fetcher, prefix, row, work, cancel, events).await?;
    record(prefix, name, None)?;
    events.emit(ComponentEvent::Applied {
        verb: row.name.clone(),
    });
    Ok(())
}

/// Install one tool and record it.
#[allow(clippy::too_many_arguments)]
async fn install_tool(
    fetcher: &Fetcher,
    paths: &AddonPaths,
    manifest: &ComponentManifest,
    prefix: &Prefix,
    name: &str,
    work: &Path,
    cancel: &CancellationToken,
    events: &ComponentEvents,
) -> Result<()> {
    let tool = manifest
        .tool(name)
        .ok_or_else(|| AddonError::UnknownComponent {
            name: name.to_owned(),
        })?;
    // Emitted before the work, so a user reading along sees what they are about to be told about.
    for note in &tool.caveats {
        events.emit(ComponentEvent::Caveat {
            component: tool.name.clone(),
            note: note.clone(),
        });
    }
    events.emit(ComponentEvent::Installing {
        component: tool.name.clone(),
        version: tool.version.clone(),
    });

    let dest = destination(paths, prefix, tool);
    match tool.kind {
        ToolKind::PrefixTool => {
            artifact::install(
                fetcher,
                &tool.artifact,
                &tool.name,
                work,
                &dest,
                cancel,
                events,
            )
            .await?;
        }
        ToolKind::ExternalNative => {
            install_native(fetcher, paths, tool, &dest, work, cancel, events).await?;
        }
    }
    if let Some(register) = &tool.register {
        // A host program the launcher is about to exec has to be executable, and the archives these
        // come in are built on Windows: the one shipped launcher script here arrives mode 644. A
        // program inside the prefix needs nothing, since the runner is what executes it.
        if tool.kind == ToolKind::ExternalNative {
            make_executable(&dest.join(register.program.as_path()), &tool.name)?;
        }
    }
    record(prefix, &tool.name, Some(&tool.version))?;
    events.emit(ComponentEvent::Installed {
        component: tool.name.clone(),
    });
    Ok(())
}

/// Install a native component, skipping the fetch when the host directory already holds this version.
///
/// The host component directory is shared by every profile, so without this a second profile wanting the
/// same companion would re-download tens of megabytes to produce the identical tree. A prefix tool gets
/// no such marker on purpose: its files live in one prefix, and re-laying them is how a damaged install
/// is repaired.
#[allow(clippy::too_many_arguments)]
async fn install_native(
    fetcher: &Fetcher,
    paths: &AddonPaths,
    tool: &ToolEntry,
    dest: &Path,
    work: &Path,
    cancel: &CancellationToken,
    events: &ComponentEvents,
) -> Result<()> {
    let marker_dir = paths.components.join(NATIVE_INSTALLED_DIR);
    let marker = marker_dir.join(format!("{}-{}", tool.name, tool.version));
    if marker.is_file() {
        return Ok(());
    }
    artifact::install(
        fetcher,
        &tool.artifact,
        &tool.name,
        work,
        dest,
        cancel,
        events,
    )
    .await?;
    tokio::fs::create_dir_all(&marker_dir)
        .await
        .map_err(|source| artifact::io_failed(&tool.name, "seal", &marker_dir, source))?;
    tokio::fs::write(&marker, b"")
        .await
        .map_err(|source| artifact::io_failed(&tool.name, "seal", &marker, source))?;
    Ok(())
}

/// Where a tool's files go: under the prefix's `C:` for a prefix tool, under the host component
/// directory for a native one.
fn destination(paths: &AddonPaths, prefix: &Prefix, tool: &ToolEntry) -> PathBuf {
    let root = match tool.kind {
        ToolKind::PrefixTool => prefix.drive_c(),
        ToolKind::ExternalNative => paths.components.clone(),
    };
    root.join(tool.into.as_path())
}

/// Mark `path` executable, keeping whatever else its mode says.
fn make_executable(path: &Path, component: &str) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(path)
            .map_err(|source| artifact::io_failed(component, "register", path, source))?
            .permissions()
            .mode();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode | 0o100))
            .map_err(|source| artifact::io_failed(component, "register", path, source))?;
    }
    #[cfg(not(unix))]
    {
        let _ = (path, component);
    }
    Ok(())
}

/// Note a component or verb in the prefix's record.
fn record(prefix: &Prefix, name: &str, version: Option<&str>) -> Result<()> {
    let result = match version {
        Some(version) => prefix.record_component(name, Some(version)),
        None => prefix.record_verb(name),
    };
    result.map(|_| ()).map_err(|source| AddonError::Install {
        component: name.to_owned(),
        step: "record it in the prefix",
        source: Box::new(source),
    })
}

/// A failure as one line, with its cause chain, because the outer message alone is usually the least
/// specific part of it.
fn describe(err: &AddonError) -> String {
    let mut text = err.to_string();
    let mut source = std::error::Error::source(err);
    while let Some(cause) = source {
        text.push_str(": ");
        text.push_str(&cause.to_string());
        source = cause.source();
    }
    text
}

/// The launch-time records for whichever of `wanted` are registered tools installed under `paths`.
///
/// # Errors
/// [`AddonError::InvalidAddon`] if a row's program path cannot be run as written.
pub(crate) fn registrations(
    paths: &AddonPaths,
    manifest: &ComponentManifest,
    prefix: &Prefix,
    wanted: &[String],
) -> Result<Vec<ExternalAddon>> {
    let mut addons = Vec::new();
    for name in wanted {
        let Some(tool) = manifest.tool(name) else {
            continue;
        };
        let Some(register) = &tool.register else {
            continue;
        };
        let run_in = match tool.kind {
            ToolKind::PrefixTool => RunIn::Prefix,
            ToolKind::ExternalNative => RunIn::Host,
        };
        let program = destination(paths, prefix, tool).join(register.program.as_path());
        addons.push(ExternalAddon::new(
            program,
            register.args.clone(),
            run_in,
            register.trigger,
        )?);
    }
    Ok(addons)
}

#[cfg(test)]
mod tests;

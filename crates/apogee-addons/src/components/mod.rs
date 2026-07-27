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
//! recorded against its own name and the rest of the set continues. Cancellation is the other whole-call
//! failure, and deliberately not a set of failed components: what is missing after it is missing because
//! it was asked to stop.
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
use ed25519_dalek::VerifyingKey;
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

/// The names the manifest and its detached signature are cached under.
const MANIFEST_FILE: &str = "components.json";
const SIGNATURE_FILE: &str = "components.json.sig";
/// Where a fetch in progress writes, cleared before every attempt.
const STAGING_DIR: &str = ".fetching";

/// Fetch the signed manifest and its detached signature over HTTPS, then verify against `key`. The
/// manifest's own bytes are not pinned ahead of time; the signature is the authenticity gate.
///
/// The key is passed in rather than read here, so the shipping entry point can hand over the compiled-in
/// one while a test hands over a key it can also sign with. Nothing else about the path changes: whatever
/// key arrives is the only thing that can admit a manifest.
///
/// Two things about *where* it downloads are load-bearing rather than tidiness.
///
/// It downloads into a staging directory that is removed first. A manifest is fetched with no content
/// pin and no declared length, and under those terms the fetcher treats any existing file at the
/// destination as already satisfying the request (correctly, since it has nothing to check it against).
/// Downloading straight onto the cache path would therefore serve the first manifest ever fetched back
/// forever, and a manifest edit would never reach this build. That is the opposite of the point of
/// keeping components in signed data.
///
/// And it publishes into the cache only after the signature verifies, so what
/// [`cached_manifest`] later offers as a fallback is a manifest that once verified, and a bad or
/// truncated fetch cannot destroy the last good one.
pub(crate) async fn fetch_manifest(
    fetcher: &Fetcher,
    manifest_url: &Url,
    signature_url: &Url,
    cache_dir: &Path,
    key: &VerifyingKey,
    cancel: &CancellationToken,
) -> Result<ComponentManifest> {
    let staging = cache_dir.join(STAGING_DIR);
    let _ = tokio::fs::remove_dir_all(&staging).await;
    tokio::fs::create_dir_all(&staging)
        .await
        .map_err(|source| artifact::io_failed("manifest", "cache", &staging, source))?;
    let manifest_path = staging.join(MANIFEST_FILE);
    let signature_path = staging.join(SIGNATURE_FILE);
    download_unverified(fetcher, manifest_url, &manifest_path, cancel).await?;
    download_unverified(fetcher, signature_url, &signature_path, cancel).await?;

    let manifest = tokio::fs::read(&manifest_path)
        .await
        .map_err(|source| artifact::io_failed("manifest", "read", &manifest_path, source))?;
    let signature = tokio::fs::read(&signature_path)
        .await
        .map_err(|source| artifact::io_failed("manifest", "read", &signature_path, source))?;
    let parsed = ComponentManifest::parse_and_verify(&manifest, &signature, key)?;

    publish(&staging, cache_dir).await?;
    Ok(parsed)
}

/// Move a verified manifest and its signature from `staging` into the cache.
///
/// Two renames rather than one, so a crash between them can leave a manifest beside the previous
/// signature. That is survivable rather than silent: [`cached_manifest`] verifies what it reads, so a
/// mismatched pair is refused like any other unusable cache.
async fn publish(staging: &Path, cache_dir: &Path) -> Result<()> {
    tokio::fs::create_dir_all(cache_dir)
        .await
        .map_err(|source| artifact::io_failed("manifest", "cache", cache_dir, source))?;
    for name in [MANIFEST_FILE, SIGNATURE_FILE] {
        let from = staging.join(name);
        let to = cache_dir.join(name);
        tokio::fs::rename(&from, &to)
            .await
            .map_err(|source| artifact::io_failed("manifest", "cache", &to, source))?;
    }
    let _ = tokio::fs::remove_dir_all(staging).await;
    Ok(())
}

/// The last manifest a fetch verified and left in `cache_dir`, re-verified against `key` before it is
/// handed back.
///
/// `None` when nothing has been fetched yet. A signature check stands between the cache and every caller,
/// so this is a freshness fallback and never a trust one: the worst it can serve is yesterday's rows,
/// which for a launch beats starting no companions at all. Whether that trade is the right one is the
/// caller's to make, which is why fetching and reading the cache are separate calls.
pub(crate) async fn cached_manifest(
    cache_dir: &Path,
    key: &VerifyingKey,
) -> Result<Option<ComponentManifest>> {
    let manifest_path = cache_dir.join(MANIFEST_FILE);
    let signature_path = cache_dir.join(SIGNATURE_FILE);
    let (Ok(manifest), Ok(signature)) = (
        tokio::fs::read(&manifest_path).await,
        tokio::fs::read(&signature_path).await,
    ) else {
        return Ok(None);
    };
    Ok(Some(ComponentManifest::parse_and_verify(
        &manifest, &signature, key,
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
/// A tool whose prerequisite verb failed in this run is not installed. A verb a tool declares is the
/// prefix setup that tool needs, so installing it anyway would leave a component in place that cannot
/// work while the prefix records it as installed, which is worse than not having it, because the next
/// run would skip both.
///
/// # Errors
/// [`AddonError::UnknownComponent`] if a name is in no list, or [`AddonError::Install`] wrapping the
/// runtime's error if the prefix's record cannot be read: without it there is no way to tell an install
/// that is needed from one that is not, and re-running everything against a live prefix is worse than
/// stopping. [`AddonError::Cancelled`] if the token fired, which ends the run rather than failing the
/// components it did not get to.
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
    // A verb the record claims but whose effect is gone has to be applied again, so the check happens
    // before the plan is built rather than being discovered halfway through it.
    let stale = stale_verbs(manifest, prefix, &installed);
    let plan = EnsurePlan::build(manifest, wanted, &installed, &stale)?;

    // One scratch directory per prefix, so two installs into different prefixes cannot clobber each
    // other's staging, and removed at the end whatever happened.
    let work = artifact::work_dir(prefix.path());
    let mut report = ComponentReport::default();
    // What failed so far, so a tool is not installed over prefix setup that did not apply.
    let mut failed: Vec<String> = Vec::new();
    let mut cancelled = false;

    for step in plan.steps() {
        // Cancellation ends the run here rather than being left to each step to notice. Every remaining
        // step would otherwise be attempted and fail: a download returns cancelled the moment it starts,
        // and a verb's run op spawns a process before it races the token. The report would then be a set
        // of failures, which is what a caller counts to decide the install did not work, for a run the
        // user stopped themselves.
        if cancel.is_cancelled() {
            cancelled = true;
            break;
        }
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
                    StepKind::Tool(_) => match blocking_verb(manifest, &step.name, &failed) {
                        Some(verb) => Err(artifact::install_failed(
                            &step.name,
                            "prerequisite",
                            format!("the prefix setup it needs ({verb}) did not apply"),
                        )),
                        None => {
                            install_tool(
                                fetcher, paths, manifest, prefix, &step.name, &work, cancel, events,
                            )
                            .await
                        }
                    },
                };
                // The step that was in flight when the token fired is the one the check above cannot
                // catch: it ran before the step started. So the token is read again here, ahead of
                // whatever the step made of being interrupted, and for both ways a step can come back
                // rather than only the failing one. A half-finished download reports an error and a
                // step that got as far as its last write reports success, but neither is evidence
                // about the component: the reason the run stopped is the same one either way. Reading
                // only the error is how a run stopped during its last step ends as a full report of
                // installed components, which is precisely the "it worked" a stopped run must not say.
                //
                // A step that did finish keeps what it recorded in the prefix. That record is written
                // by the step itself, out of work that landed, and from here there is no telling a
                // step that ran to the end from one a callee cut short and called done, so taking it
                // back would throw away real installs on every stop. What this loop can answer for is
                // the run, and a run somebody stopped is stopped however far it got.
                if cancel.is_cancelled() {
                    cancelled = true;
                    break;
                }
                let state = match outcome {
                    Ok(()) => ComponentState::Installed,
                    Err(err) => {
                        let reason = describe(&err);
                        events.emit(ComponentEvent::Failed {
                            component: step.name.clone(),
                            reason: reason.clone(),
                        });
                        failed.push(step.name.clone());
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

    // The scratch directory goes either way: a run that stopped early has no more claim on it than one
    // that finished.
    let _ = tokio::fs::remove_dir_all(&work).await;
    if cancelled {
        return Err(AddonError::Cancelled);
    }
    Ok(report)
}

/// The recorded components whose effect the manifest says is checkable and which no longer have it.
///
/// Only verbs, and only those naming something to look for. A tool's presence is not re-derived from its
/// files: a component's own updater rewrites its tree, so absence of a particular file there means little,
/// whereas a verb states exactly what its effect is.
fn stale_verbs(
    manifest: &ComponentManifest,
    prefix: &Prefix,
    installed: &[apogee_runtime::InstalledComponent],
) -> Vec<String> {
    installed
        .iter()
        .filter_map(|record| manifest.verb(record.name()))
        .filter(|verb| verb::missing(prefix, verb).is_some())
        .map(|verb| verb.name.clone())
        .collect()
}

/// The first verb `tool` requires that is among `failed`, if any.
fn blocking_verb<'m>(
    manifest: &'m ComponentManifest,
    tool: &str,
    failed: &[String],
) -> Option<&'m str> {
    manifest
        .tool(tool)?
        .verbs
        .iter()
        .find(|verb| failed.iter().any(|f| f == *verb))
        .map(String::as_str)
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
            let required = tool
                .register
                .as_ref()
                .map(|r| dest.join(r.program.as_path()));
            install_native(
                fetcher,
                paths,
                tool,
                &dest,
                required.as_deref(),
                work,
                cancel,
                events,
            )
            .await?;
        }
    }
    if let Some(register) = &tool.register {
        let program = dest.join(register.program.as_path());
        // A registration naming a program the archive does not contain is a manifest mistake, and it is
        // checked here so it reads as "that row is wrong" rather than turning up at the next launch as a
        // spawn failure with a path in it. Checked for both kinds: a prefix tool's program is a real file
        // on this side too, since the runner is handed its host path.
        if !program.is_file() {
            return Err(artifact::install_failed(
                &tool.name,
                "register",
                format!(
                    "the archive holds no {} to register",
                    register.program.as_path().display()
                ),
            ));
        }
        // A host program the launcher execs itself has to be executable, and a component archive is built
        // on Windows, where nothing carries an executable bit: whatever mode its entry point arrives at
        // is not one this side can run. A program inside the prefix needs nothing, since the runner is
        // what executes it.
        if tool.kind == ToolKind::ExternalNative {
            make_executable(&program, &tool.name)?;
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
///
/// `required` is the program the caller will go on to register, when there is one. The skip has to be at
/// least as strict as what the caller then demands, or a directory that lost that one file would be
/// skipped, fail the registration check, and take the same path on every retry forever.
///
/// The skip consults the token too, which the paths that download get for free. What it stands between
/// is a cancelled run and the prefix record: `ensure` re-reads the token after every step and stops
/// before an outcome is pushed, so a skip cannot reach the report either way, but nothing else keeps it
/// out of a record that outlives the run that wrote it. Doing no work is not having done the work.
#[allow(clippy::too_many_arguments)]
async fn install_native(
    fetcher: &Fetcher,
    paths: &AddonPaths,
    tool: &ToolEntry,
    dest: &Path,
    required: Option<&Path>,
    work: &Path,
    cancel: &CancellationToken,
    events: &ComponentEvents,
) -> Result<()> {
    let marker_dir = paths.components.join(NATIVE_INSTALLED_DIR);
    let marker = marker_dir.join(format!("{}-{}", tool.name, tool.version));
    let intact = dest.is_dir() && required.is_none_or(Path::is_file);
    if marker.is_file() && intact {
        if cancel.is_cancelled() {
            return Err(AddonError::Cancelled);
        }
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

/// The launch-time records for whichever of `wanted` are registered tools the prefix records as
/// installed.
///
/// The prefix's record is consulted, not just the manifest. A component a profile has enabled but never
/// installed has no files, so registering it would hand the launch a program that is not there and turn
/// one un-run setup step into a spawn failure at every launch.
///
/// # Errors
/// [`AddonError::InvalidAddon`] if a row's program path cannot be run as written, or
/// [`AddonError::Install`] if the prefix's record cannot be read.
pub(crate) fn registrations(
    paths: &AddonPaths,
    manifest: &ComponentManifest,
    prefix: &Prefix,
    wanted: &[String],
) -> Result<Vec<ExternalAddon>> {
    let installed = prefix.components().map_err(|source| AddonError::Install {
        component: "prefix".to_owned(),
        step: "read the prefix record",
        source: Box::new(source),
    })?;
    let mut addons = Vec::new();
    for name in wanted {
        let Some(tool) = manifest.tool(name) else {
            continue;
        };
        let Some(register) = &tool.register else {
            continue;
        };
        if !installed.iter().any(|c| c.name() == name) {
            continue;
        }
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

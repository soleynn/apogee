//! The signed catalog of prefix setup, and applying what a prefix is missing.
//!
//! Three things hold across this module.
//!
//! Applying is idempotent, and the prefix's own `prefix.json` is what makes it so. Nothing here
//! keeps a list of its own about what a prefix has, because a second list is a second thing that can
//! be wrong about a prefix somebody else also writes into.
//!
//! One verb failing costs the prefix that verb. A verb a wine refuses is recorded against its own
//! name and the rest continue, because a launch that is otherwise fine should not be stopped by one
//! piece of hygiene. Cancellation is the whole-call failure instead, and deliberately not a set of
//! failed verbs: what is missing after it is missing because the pass was asked to stop.
//!
//! Nothing chooses which verbs run. The manifest's list is the setup, so a pass applies what the
//! prefix does not already have rather than what somebody remembered to switch on.
//!
//! # Examples
//!
//! A pass narrates onto a [`SetupEvents`] stream and returns what became of every verb:
//!
//! ```
//! # use apogee_addons::{Addons, SetupEvent, SetupEvents, VerifiedManifest};
//! # use apogee_runtime::Prefix;
//! # use tokio_util::sync::CancellationToken;
//! # async fn demo(
//! #     addons: &Addons,
//! #     manifest: &VerifiedManifest,
//! #     prefix: &Prefix,
//! #     cancel: &CancellationToken,
//! # ) -> apogee_addons::Result<()> {
//! let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
//! let report = addons
//!     .apply_setup(manifest, prefix, cancel, &SetupEvents::new(tx))
//!     .await?;
//!
//! // A verb the prefix already recorded, applied again because its effect was gone.
//! let mut came_back: Vec<String> = Vec::new();
//! while let Ok(event) = rx.try_recv() {
//!     if let SetupEvent::Reapplying { verb, .. } = event {
//!         came_back.push(verb);
//!     }
//! }
//!
//! // A verb that failed is in the report, not in the error: the rest of the pass still ran.
//! let still_missing = report.failed();
//! # Ok(())
//! # }
//! ```

mod artifact;
mod event;
mod plan;
mod verb;

use std::path::Path;

use apogee_fetch::Fetcher;
use apogee_runtime::{Prefix, Runtime};
use tokio_util::sync::CancellationToken;
use url::Url;

pub use event::{SetupEvent, SetupEvents};

// The plan is how this module decides, not something a caller composes: it borrows rows out of the
// manifest it was built from, and every consumer of the decision reads the report or the missing list
// instead.
pub(crate) use plan::{SetupPlan, StepAction};

use crate::manifest::{ComponentManifest, ProgramEntry, Verb, VerifiedManifest};
use crate::program::record;
use crate::{AddonError, Result};

/// What became of one verb.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum SetupState {
    /// Applied now, and recorded in the prefix.
    Applied,
    /// Applied now, over a record that already claimed it, because its effect had gone.
    ///
    /// Distinct from [`Self::Applied`] because the two mean different things about the prefix: one is
    /// setup that was missing, the other is setup that came back. A verb in this state on every pass
    /// is either something in the prefix undoing it each time or a reading of the prefix that is
    /// wrong, and a report that called it `Applied` would show neither.
    #[non_exhaustive]
    Reapplied {
        /// The reading that says the effect had gone.
        because: String,
    },
    /// The prefix already recorded it, so nothing was done.
    AlreadyPresent,
    /// It could not be applied. The rest of the pass is unaffected.
    #[non_exhaustive]
    Failed {
        /// The failure and its causes, as one line.
        reason: String,
    },
}

/// One verb and what became of it.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct SetupOutcome {
    /// The verb, by the name the manifest gives it.
    pub name: String,
    /// What became of it.
    pub state: SetupState,
}

/// Everything one setup pass did.
///
/// # Examples
///
/// ```
/// # use apogee_addons::setup::SetupReport;
/// # fn demo(report: &SetupReport) {
/// if report.any_failed() {
///     let (applied, missing) = (report.present(), report.failed());
/// }
/// # }
/// ```
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct SetupReport {
    /// One per planned verb, in plan order.
    pub outcomes: Vec<SetupOutcome>,
}

impl SetupReport {
    /// Whether anything failed. What that is worth is the caller's decision.
    #[must_use]
    pub fn any_failed(&self) -> bool {
        self.outcomes
            .iter()
            .any(|o| matches!(o.state, SetupState::Failed { .. }))
    }

    /// The verbs that are now applied, whether this pass applied them or found them.
    #[must_use]
    pub fn present(&self) -> Vec<&str> {
        self.outcomes
            .iter()
            .filter(|o| {
                matches!(
                    o.state,
                    SetupState::Applied | SetupState::Reapplied { .. } | SetupState::AlreadyPresent
                )
            })
            .map(|o| o.name.as_str())
            .collect()
    }

    /// The verbs this pass could not apply, which are the ones the prefix is still missing.
    ///
    /// The complement of [`Self::present`] over a pass that considered every verb the manifest
    /// defines, so a caller reporting what a prefix still needs does not have to read the prefix a
    /// second time to find out.
    #[must_use]
    pub fn failed(&self) -> Vec<&str> {
        self.outcomes
            .iter()
            .filter(|o| matches!(o.state, SetupState::Failed { .. }))
            .map(|o| o.name.as_str())
            .collect()
    }
}

/// The names the manifest and its detached signature are cached under.
const MANIFEST_FILE: &str = "components.json";
const SIGNATURE_FILE: &str = "components.json.sig";
/// The highest manifest serial this cache has verified, beside the manifest it came from.
const SERIAL_FILE: &str = "serial";
/// Where a fetch in progress writes, cleared before every attempt.
const STAGING_DIR: &str = ".fetching";
/// What a failure on the catalog's own filesystem steps is reported against.
const CATALOG: &str = "the signed catalog";

/// Fetch the signed manifest and its detached signature over HTTPS, then verify the manifest against
/// `keys`.
///
/// The manifest's own bytes are not pinned ahead of time: the Ed25519 signature is the authenticity
/// gate, and whatever arrives in `keys` is the only thing that can admit a manifest. The keys are
/// passed in rather than read here so that the shipping entry point can hand over the compiled-in
/// one while a test hands over a key it can also sign with.
///
/// The download stages, and publishes into `cache_dir` only once the signature verifies, so what
/// [`cached_manifest`] later offers as a fallback is a manifest that once verified and a bad or
/// truncated fetch cannot destroy the last good one.
///
/// # Errors
/// [`AddonError::Io`] for any of its own filesystem steps, [`AddonError::Spec`] for a URL that is
/// not http(s), [`AddonError::Download`] if a download does not complete (a fired `cancel` arrives
/// this way, as a cancelled fetch), and [`AddonError::Manifest`] if what was served does not verify
/// against any key in `keys`, does not parse once it has, or carries a serial lower than one this cache
/// has already verified ([`ManifestError::Rollback`](crate::ManifestError::Rollback)).
pub(crate) async fn fetch_manifest(
    fetcher: &Fetcher,
    manifest_url: &Url,
    signature_url: &Url,
    cache_dir: &Path,
    keys: &[[u8; 32]],
    cancel: &CancellationToken,
) -> Result<VerifiedManifest> {
    // Into a staging directory that is removed first, and not straight onto the cache path. The
    // fetcher's `overwrite` knob could force the re-fetch on its own, but staging buys the part
    // that knob cannot: the manifest and its signature verify as a pair before either replaces the
    // last good copy, so a fetch that lands one file and fails the other (or serves bytes that do
    // not verify) never leaves a half-updated cache behind.
    let staging = cache_dir.join(STAGING_DIR);
    let _ = tokio::fs::remove_dir_all(&staging).await;
    tokio::fs::create_dir_all(&staging)
        .await
        .map_err(|source| {
            artifact::io_failed(CATALOG, "make a staging directory", &staging, source)
        })?;
    let manifest_path = staging.join(MANIFEST_FILE);
    let signature_path = staging.join(SIGNATURE_FILE);
    download_unverified(fetcher, manifest_url, &manifest_path, cancel).await?;
    download_unverified(fetcher, signature_url, &signature_path, cancel).await?;

    let manifest = tokio::fs::read(&manifest_path).await.map_err(|source| {
        artifact::io_failed(CATALOG, "read what it downloaded", &manifest_path, source)
    })?;
    let signature = tokio::fs::read(&signature_path).await.map_err(|source| {
        artifact::io_failed(CATALOG, "read what it downloaded", &signature_path, source)
    })?;
    // Which key admitted it travels on the proof and nothing here reads it. An overlap window exists so
    // that a launch does not have to care which side of a rotation it is on; the re-sign it is waiting
    // for is a maintainer's business, asserted where the hosted file is embedded rather than on a
    // user's machine.
    let verified = VerifiedManifest::verify(&manifest, &signature, keys)?;
    // Refused before it is published, so a replayed manifest never replaces the newer one it is
    // older than.
    let found = verified.rows().serial.unwrap_or(0);
    let highest = check_serial(cache_dir, found).await?;

    publish(&staging, cache_dir).await?;
    if found > highest {
        record_serial(cache_dir, found).await?;
    }
    Ok(verified)
}

/// Refuse `found` if it is older than the highest serial verified into `cache_dir`, returning that
/// highest.
///
/// The record is an ordinary file in the launcher's own data directory, so it stops a superseded
/// manifest replayed from the network or a stale mirror, not a local process running as the same
/// user, which could rewrite the record as easily as the cache. An unreadable or garbled record is
/// read as none for the same reason: whoever can garble it can also delete it.
///
/// # Errors
/// [`AddonError::Manifest`] wrapping [`ManifestError::Rollback`](crate::ManifestError::Rollback).
async fn check_serial(cache_dir: &Path, found: u64) -> Result<u64> {
    let highest = tokio::fs::read_to_string(cache_dir.join(SERIAL_FILE))
        .await
        .ok()
        .and_then(|text| text.trim().parse::<u64>().ok())
        .unwrap_or(0);
    if found < highest {
        return Err(crate::ManifestError::Rollback { found, highest }.into());
    }
    Ok(highest)
}

/// Record `serial` as the highest verified into `cache_dir`. Written beside and renamed over, so an
/// interrupted write leaves the previous record rather than a truncated one.
///
/// # Errors
/// [`AddonError::Io`] if the record cannot be written.
async fn record_serial(cache_dir: &Path, serial: u64) -> Result<()> {
    let path = cache_dir.join(SERIAL_FILE);
    let staged = cache_dir.join(format!("{SERIAL_FILE}.new"));
    tokio::fs::write(&staged, serial.to_string())
        .await
        .map_err(|source| artifact::io_failed(CATALOG, "record its serial", &staged, source))?;
    tokio::fs::rename(&staged, &path)
        .await
        .map_err(|source| artifact::io_failed(CATALOG, "record its serial", &path, source))
}

/// Move a verified manifest and its signature from `staging` into the cache.
///
/// Two renames rather than one, so a crash between them can leave a manifest beside the previous
/// signature. That is survivable rather than silent: [`cached_manifest`] verifies what it reads, so
/// a mismatched pair is refused like any other unusable cache.
///
/// # Errors
/// [`AddonError::Io`] if the cache directory cannot be made or either rename fails.
async fn publish(staging: &Path, cache_dir: &Path) -> Result<()> {
    tokio::fs::create_dir_all(cache_dir)
        .await
        .map_err(|source| {
            artifact::io_failed(CATALOG, "make its cache directory", cache_dir, source)
        })?;
    for name in [MANIFEST_FILE, SIGNATURE_FILE] {
        let from = staging.join(name);
        let to = cache_dir.join(name);
        tokio::fs::rename(&from, &to)
            .await
            .map_err(|source| artifact::io_failed(CATALOG, "publish what verified", &to, source))?;
    }
    let _ = tokio::fs::remove_dir_all(staging).await;
    Ok(())
}

/// The last manifest a fetch verified and left in `cache_dir`, re-verified against `keys` before it
/// is handed back.
///
/// `None` when nothing has been fetched yet, or when either cached file cannot be read. A signature
/// check stands between the cache and every caller, so this is a freshness fallback and never a
/// trust one: the worst it can serve is yesterday's rows, which for a launch beats applying no
/// prefix setup at all. Whether that trade is the right one is the caller's to make, which is why
/// fetching and reading the cache are separate calls.
///
/// # Errors
/// [`AddonError::Manifest`] if what is cached no longer verifies against `keys`, no longer parses, or
/// is older than a manifest this cache has already verified.
pub(crate) async fn cached_manifest(
    cache_dir: &Path,
    keys: &[[u8; 32]],
) -> Result<Option<VerifiedManifest>> {
    let manifest_path = cache_dir.join(MANIFEST_FILE);
    let signature_path = cache_dir.join(SIGNATURE_FILE);
    let (Ok(manifest), Ok(signature)) = (
        tokio::fs::read(&manifest_path).await,
        tokio::fs::read(&signature_path).await,
    ) else {
        return Ok(None);
    };
    let verified = VerifiedManifest::verify(&manifest, &signature, keys)?;
    check_serial(cache_dir, verified.rows().serial.unwrap_or(0)).await?;
    Ok(Some(verified))
}

/// Download `url` to `dest` over HTTPS with no content pin, because the caller authenticates these
/// bytes with an Ed25519 signature instead. The spec builder refuses an unpinned download over
/// plain `http`.
///
/// # Errors
/// [`AddonError::Spec`] if `url` is not http(s) or is plain `http`, [`AddonError::Download`] if the
/// fetch does not complete.
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
    fetcher
        .download(&spec, None, cancel.clone())
        .await
        .map_err(|source| AddonError::from_fetch(source, CATALOG, dest))?;
    Ok(())
}

/// Apply every verb `manifest` defines that `prefix` is missing, narrating each step onto `events`.
///
/// A verb that could not be applied is a [`SetupState::Failed`] in the returned report rather than
/// an error here, so one refusal costs the prefix that verb and nothing else.
///
/// # Errors
/// [`AddonError::Io`] wrapping the runtime's error if the prefix's record cannot be read: without it
/// there is no way to tell setup that is needed from setup that is not, and re-running everything
/// against a live prefix is worse than stopping. [`AddonError::Cancelled`] if `cancel` fired, which
/// ends the pass rather than failing the verbs it did not get to.
pub(crate) async fn apply_verbs(
    runtime: &Runtime,
    fetcher: &Fetcher,
    manifest: &VerifiedManifest,
    prefix: &Prefix,
    cancel: &CancellationToken,
    events: &SetupEvents,
) -> Result<SetupReport> {
    apply_for(runtime, fetcher, manifest, prefix, None, cancel, events).await
}

/// Which programs a pass installs, and where it keeps what their steps placed.
pub(crate) struct ProgramScope<'a> {
    /// The programs a profile enabled, by row name.
    pub enabled: &'a [&'a str],
    /// The addons root, under which each prefix's install records live.
    pub addons_root: &'a Path,
}

/// [`apply_verbs`], and then the steps of every program `programs` enables.
///
/// A program's steps run in order after the base verbs. One that fails stops the rest of that
/// program's steps, which are reported as failed without being tried: a later step lays files over an
/// earlier one's, and applying it over a half-installed program records a state nothing installed. A
/// program whose steps are all present is recorded in the prefix at its row's version, which is what
/// the start gate reads. An enabled program the catalog has no usable row for is a failure in the
/// report, under its name.
///
/// # Errors
/// As [`apply_verbs`].
// One loop, kept whole: its length is the reasoning about where a cancellation lands, and splitting it
// would put the two reads of the token in different functions from the step they bracket.
#[allow(clippy::too_many_lines)]
pub(crate) async fn apply_for(
    runtime: &Runtime,
    fetcher: &Fetcher,
    manifest: &VerifiedManifest,
    prefix: &Prefix,
    programs: Option<&ProgramScope<'_>>,
    cancel: &CancellationToken,
    events: &SetupEvents,
) -> Result<SetupReport> {
    let mut report = SetupReport::default();
    let rows = enabled_rows(manifest.rows(), programs, |name, why| {
        let reason = why.to_string();
        events.emit(SetupEvent::Failed {
            what: name.to_owned(),
            reason: reason.clone(),
        });
        report.outcomes.push(SetupOutcome {
            name: name.to_owned(),
            state: SetupState::Failed { reason },
        });
    });
    let records = programs.map(|scope| record::records_dir(scope.addons_root, prefix.path()));

    // The proof stops here, at the last thing that decides *whether* to write. Below this the rows are
    // ordinary data and the functions that read them are private to this crate.
    let Planned { plan, stale } = plan_for(manifest.rows(), prefix, &rows, records.as_deref())?;

    // One scratch directory per prefix, so two passes over different prefixes cannot clobber each
    // other's staging, and removed at the end whatever happened.
    let work = artifact::work_dir(prefix.path());
    let mut cancelled = false;
    // Programs a step of which failed in this pass; their later steps are not tried.
    let mut broken: Vec<&str> = Vec::new();

    for step in plan.steps() {
        // Cancellation ends the pass here rather than being left to each step to notice. Every
        // remaining step would otherwise be attempted and fail: a download returns cancelled the moment
        // it starts. The report would then be a set of failures, which is what a caller counts to decide
        // the setup did not work, for a pass the user stopped themselves.
        if cancel.is_cancelled() {
            cancelled = true;
            break;
        }
        match step.action {
            StepAction::AlreadyPresent => {
                events.emit(SetupEvent::AlreadyPresent {
                    what: step.verb.name.clone(),
                });
                report.outcomes.push(SetupOutcome {
                    name: step.verb.name.clone(),
                    state: SetupState::AlreadyPresent,
                });
            }
            StepAction::Apply
                if let Some(program) = step.program
                    && broken.contains(&program.name.as_str()) =>
            {
                let reason = format!("an earlier step of {} did not apply", program.name);
                events.emit(SetupEvent::Failed {
                    what: step.verb.name.clone(),
                    reason: reason.clone(),
                });
                report.outcomes.push(SetupOutcome {
                    name: step.verb.name.clone(),
                    state: SetupState::Failed { reason },
                });
            }
            StepAction::Apply => {
                // Said before it is done, and only for a verb the record already claimed: a verb
                // reapplied on every launch is what a wrong reading of the prefix looks like from
                // outside, and the reading is the only thing that tells it from something in the
                // prefix genuinely undoing the verb each time. Inside the loop rather than beside the
                // plan, so a pass that stops early does not announce work it never reached.
                let stale_because = stale
                    .iter()
                    .find(|s| s.name == step.verb.name)
                    .map(|entry| entry.because.clone());
                if let Some(because) = &stale_because {
                    events.emit(SetupEvent::Reapplying {
                        verb: step.verb.name.clone(),
                        because: because.clone(),
                    });
                }
                let target = match (step.program, records.as_deref()) {
                    (Some(program), Some(dir)) => Target::Program {
                        program,
                        seeded: step.seeded,
                        records: dir,
                    },
                    _ => Target::Verb,
                };
                let outcome = apply_verb(
                    runtime, fetcher, prefix, step.verb, target, &work, cancel, events,
                )
                .await;
                // The step that was in flight when the token fired is the one the check above cannot
                // catch: it ran before the step started. So the token is read again here, ahead of
                // whatever the step made of being interrupted, and for both ways a step can come back
                // rather than only the failing one. A half-finished download reports an error and a
                // step that got as far as its last write reports success, but neither is evidence about
                // the verb: the reason the pass stopped is the same one either way. Reading only the
                // error is how a pass stopped during its last step ends as a full report of applied
                // verbs, which is precisely the "it worked" a stopped pass must not say.
                //
                // A step that did finish keeps what it recorded in the prefix. That record is written by
                // the step itself, out of work that landed, and from here there is no telling a step
                // that ran to the end from one a callee cut short and called done, so taking it back
                // would throw away real work on every stop.
                if cancel.is_cancelled() {
                    cancelled = true;
                    break;
                }
                let state = match outcome {
                    Ok(()) => stale_because.map_or(SetupState::Applied, |because| {
                        SetupState::Reapplied { because }
                    }),
                    Err(err) => {
                        let reason = err.chain();
                        events.emit(SetupEvent::Failed {
                            what: step.verb.name.clone(),
                            reason: reason.clone(),
                        });
                        if let Some(program) = step.program {
                            broken.push(&program.name);
                        }
                        SetupState::Failed { reason }
                    }
                };
                report.outcomes.push(SetupOutcome {
                    name: step.verb.name.clone(),
                    state,
                });
            }
        }
    }

    // The scratch directory goes either way: a pass that stopped early has no more claim on it than one
    // that finished.
    artifact::clear_work_dirs(prefix.path()).await;
    if cancelled {
        // Said on the stream as well as returned, because the two reach different places: the error
        // goes to whoever called this, and the stream is what a user is watching.
        events.emit(SetupEvent::Stopped {
            applied: report.outcomes.len(),
        });
        return Err(AddonError::Cancelled);
    }
    record_programs(prefix, &rows, &broken, &mut report, events);
    Ok(report)
}

/// The rows of the programs `programs` enables, in row order, reporting each enabled name the
/// manifest has no usable row for.
fn enabled_rows<'m>(
    manifest: &'m ComponentManifest,
    programs: Option<&ProgramScope<'_>>,
    missing: impl FnMut(&str, crate::SkipReason),
) -> Vec<&'m ProgramEntry> {
    let Some(scope) = programs else {
        return Vec::new();
    };
    crate::program::requested(manifest, scope.enabled, missing)
        .into_iter()
        .filter_map(|name| manifest.program(name))
        .collect()
}

/// Record each program whose steps are all present at its row's version, once.
///
/// Only when the record is not already that, because recording appends to the prefix's history and
/// a launch that changed nothing should leave nothing behind.
fn record_programs(
    prefix: &Prefix,
    rows: &[&ProgramEntry],
    broken: &[&str],
    report: &mut SetupReport,
    events: &SetupEvents,
) {
    let installed = prefix.components().unwrap_or_default();
    for program in rows {
        if broken.contains(&program.name.as_str()) {
            continue;
        }
        let present = report.present();
        if !program
            .steps
            .iter()
            .all(|step| present.contains(&step.verb.name.as_str()))
        {
            continue;
        }
        let current = installed
            .iter()
            .any(|c| c.name() == program.name && c.version() == Some(program.version.as_str()));
        if current {
            continue;
        }
        match prefix.record_component(&program.name, Some(&program.version)) {
            Ok(_) => events.emit(SetupEvent::Installed {
                what: program.name.clone(),
            }),
            Err(source) => {
                let reason = crate::chain_of(&source);
                events.emit(SetupEvent::Failed {
                    what: program.name.clone(),
                    reason: reason.clone(),
                });
                report.outcomes.push(SetupOutcome {
                    name: program.name.clone(),
                    state: SetupState::Failed { reason },
                });
            }
        }
    }
}

/// A recorded verb whose effect was checked and is gone, with the reading that says so.
struct StaleVerb {
    name: String,
    because: String,
}

/// What a pass over a prefix would do, and why anything the record already claimed is in it.
///
/// The reasons travel in the decision rather than being announced while it is made, because the same
/// decision answers a question ([`missing_verbs`]) and drives a pass ([`apply_verbs`]), and a
/// question about a prefix must not report work as happening.
struct Planned<'m> {
    plan: SetupPlan<'m>,
    stale: Vec<StaleVerb>,
}

/// What a pass over `prefix` would do about every verb `manifest` defines.
///
/// The one place the decision is made, so what [`missing_verbs`] names and what [`apply_verbs`]
/// applies are the same answer rather than two readings of the same prefix that can disagree.
///
/// # Errors
/// [`AddonError::Io`] if the prefix's record cannot be read.
fn plan_for<'m>(
    manifest: &'m ComponentManifest,
    prefix: &Prefix,
    programs: &[&'m ProgramEntry],
    records: Option<&Path>,
) -> Result<Planned<'m>> {
    let installed = prefix.components().map_err(|source| AddonError::Io {
        what: "this prefix".to_owned(),
        step: "read what setup it already has",
        path: prefix.metadata_path(),
        source: Box::new(source),
    })?;
    // A verb the record claims but whose effect is gone has to be applied again, so the check happens
    // before the plan is built rather than being discovered halfway through it.
    let mut stale = stale_verbs(manifest, prefix, &installed);
    stale.extend(stale_program_steps(programs, prefix, &installed, records));
    let names: Vec<String> = stale.iter().map(|verb| verb.name.clone()).collect();
    Ok(Planned {
        plan: SetupPlan::build_for(manifest, &installed, &names, programs),
        stale,
    })
}

/// The recorded program steps that have to be installed again, each with why.
///
/// A step whose effect has gone, as for a base verb; and a pinned step recorded at another version of
/// its row, or whose list of what it placed is missing or for another version. Without that list the
/// start gate can never pass, so a prefix whose record outlived it is reinstalled rather than left
/// claiming an install nothing can check.
fn stale_program_steps(
    programs: &[&ProgramEntry],
    prefix: &Prefix,
    installed: &[apogee_runtime::InstalledComponent],
    records: Option<&Path>,
) -> Vec<StaleVerb> {
    let mut stale = Vec::new();
    for program in programs {
        for step in &program.steps {
            let Some(found) = installed.iter().find(|c| c.name() == step.verb.name) else {
                continue;
            };
            let because = verb::stale(prefix, &step.verb).or_else(|| {
                if step.seeded {
                    return None;
                }
                match found.version() {
                    Some(version) if version == program.version => {}
                    Some(version) => {
                        return Some(format!(
                            "version {version} is installed and the catalog pins {}",
                            program.version
                        ));
                    }
                    None => return Some("it was recorded without a version".to_owned()),
                }
                let dir = records?;
                match record::read(dir, &step.verb.name) {
                    Ok(kept) if kept.version == program.version => None,
                    Ok(_) => Some("what it placed was recorded for another version".to_owned()),
                    Err(why) => Some(why),
                }
            });
            if let Some(because) = because {
                stale.push(StaleVerb {
                    name: step.verb.name.clone(),
                    because,
                });
            }
        }
    }
    stale
}

/// The verbs `manifest` defines that `prefix` does not have, in manifest order.
///
/// Reads the prefix and changes nothing, which is what makes it answerable for a question a user
/// asked about a prefix rather than only on the way to setting one up. A verb the record claims but
/// whose effect has gone counts as missing here for the same reason it is reapplied: the record is
/// not the evidence, the effect is.
///
/// # Errors
/// As [`plan_for`].
pub(crate) fn missing_verbs(manifest: &VerifiedManifest, prefix: &Prefix) -> Result<Vec<String>> {
    missing_for(manifest, prefix, None)
}

/// [`missing_verbs`], and the steps of every program `programs` enables, with an enabled program the
/// catalog has no usable row for named first.
///
/// # Errors
/// As [`plan_for`].
pub(crate) fn missing_for(
    manifest: &VerifiedManifest,
    prefix: &Prefix,
    programs: Option<&ProgramScope<'_>>,
) -> Result<Vec<String>> {
    let mut missing = Vec::new();
    let rows = enabled_rows(manifest.rows(), programs, |name, _| {
        missing.push(name.to_owned());
    });
    let records = programs.map(|scope| record::records_dir(scope.addons_root, prefix.path()));
    missing.extend(
        plan_for(manifest.rows(), prefix, &rows, records.as_deref())?
            .plan
            .steps()
            .iter()
            .filter(|step| step.action == StepAction::Apply)
            .map(|step| step.verb.name.clone()),
    );
    Ok(missing)
}

/// The recorded verbs whose effect can be checked and is no longer there, each with the reading that
/// says so.
///
/// Checked against the paths a verb states *and* against the registry its ops declare, because those
/// cover different verbs: a placement is only checkable through what the row states, and a registry
/// write states nothing because the op already says what it wrote. Only a verb that states no paths
/// and carries no registry op is left with the record as its only evidence.
///
/// Reads the prefix's registry files rather than asking a `reg query`. This runs on every launch,
/// and a query is a Windows program started through the runner: under Proton that is umu bringing
/// its container up for one answer. The file is also the more accurate of the two here, since
/// nothing has run in the prefix yet.
fn stale_verbs(
    manifest: &ComponentManifest,
    prefix: &Prefix,
    installed: &[apogee_runtime::InstalledComponent],
) -> Vec<StaleVerb> {
    installed
        .iter()
        .filter_map(|record| manifest.verb(record.name()))
        .filter_map(|verb| {
            Some(StaleVerb {
                because: verb::stale(prefix, verb)?,
                name: verb.name.clone(),
            })
        })
        .collect()
}

/// Apply one verb and record it. Recorded only on success, so a failed apply is retried next time
/// rather than remembered as done.
///
/// # Errors
/// Whatever the verb's ops failed with, or [`AddonError::Io`] if the prefix's record cannot be
/// written.
/// What a step is applied as, which decides how it is placed and recorded.
#[derive(Clone, Copy)]
enum Target<'a> {
    /// A base verb: placed straight into its destination, recorded by name.
    Verb,
    /// A program step: recorded at its row's version, and unless it is seeded, placed through staging
    /// with what it placed kept in `records`.
    Program {
        program: &'a ProgramEntry,
        seeded: bool,
        records: &'a Path,
    },
}

#[allow(clippy::too_many_arguments)]
async fn apply_verb(
    runtime: &Runtime,
    fetcher: &Fetcher,
    prefix: &Prefix,
    row: &Verb,
    target: Target<'_>,
    work: &Path,
    cancel: &CancellationToken,
    events: &SetupEvents,
) -> Result<()> {
    events.emit(SetupEvent::Applying {
        verb: row.name.clone(),
        reason: row.reason.clone(),
    });
    let staged = matches!(target, Target::Program { seeded: false, .. });
    let placed = verb::apply(runtime, fetcher, prefix, row, work, staged, cancel, events).await?;
    let recorded = match target {
        Target::Verb => prefix.record_verb(&row.name),
        Target::Program {
            program,
            seeded,
            records,
        } => {
            // The list of what it placed is written before the prefix records the step, so a step the
            // prefix calls installed always has one.
            if !seeded {
                record::write(
                    records,
                    &record::StepRecord {
                        program: program.name.clone(),
                        version: program.version.clone(),
                        step: row.name.clone(),
                        files: placed,
                    },
                )?;
            }
            prefix.record_component(&row.name, Some(&program.version))
        }
    };
    recorded.map(|_| ()).map_err(|source| AddonError::Io {
        what: row.name.clone(),
        step: "record itself in the prefix",
        path: prefix.metadata_path(),
        source: Box::new(source),
    })?;
    events.emit(SetupEvent::Applied {
        verb: row.name.clone(),
    });
    Ok(())
}

#[cfg(test)]
mod tests;

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

use crate::manifest::{ComponentManifest, Verb, VerifiedManifest};
use crate::{AddonError, Result};

/// What became of one verb.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum SetupState {
    /// Applied now, and recorded in the prefix.
    Applied,
    /// The prefix already recorded it, so nothing was done.
    AlreadyPresent,
    /// It could not be applied. The rest of the pass is unaffected.
    #[non_exhaustive]
    Failed { reason: String },
}

/// One verb and what became of it.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct SetupOutcome {
    pub name: String,
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
            .filter(|o| matches!(o.state, SetupState::Applied | SetupState::AlreadyPresent))
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
/// against any key in `keys`, or does not parse once it has.
pub(crate) async fn fetch_manifest(
    fetcher: &Fetcher,
    manifest_url: &Url,
    signature_url: &Url,
    cache_dir: &Path,
    keys: &[[u8; 32]],
    cancel: &CancellationToken,
) -> Result<VerifiedManifest> {
    // Into a staging directory that is removed first, and not straight onto the cache path. A
    // manifest is fetched with no content pin and no declared length, and under those terms the
    // fetcher treats any existing file at the destination as already satisfying the request
    // (correctly, since it has nothing to check it against), so the destination has to be a path
    // nothing is at. Downloading onto the cache path would serve the first manifest ever fetched
    // back forever, and an edit to the hosted file would never reach this build.
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

    publish(&staging, cache_dir).await?;
    Ok(verified)
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
/// [`AddonError::Manifest`] if what is cached no longer verifies against `keys`, or no longer
/// parses.
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
    Ok(Some(VerifiedManifest::verify(&manifest, &signature, keys)?))
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
    // The proof stops here, at the last thing that decides *whether* to write. Below this the rows are
    // ordinary data and the functions that read them are private to this crate.
    let Planned { plan, stale } = plan_for(manifest.rows(), prefix)?;

    // One scratch directory per prefix, so two passes over different prefixes cannot clobber each
    // other's staging, and removed at the end whatever happened.
    let work = artifact::work_dir(prefix.path());
    let mut report = SetupReport::default();
    let mut cancelled = false;

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
            StepAction::Apply => {
                // Said before it is done, and only for a verb the record already claimed: a verb
                // reapplied on every launch is what a wrong reading of the prefix looks like from
                // outside, and the reading is the only thing that tells it from something in the
                // prefix genuinely undoing the verb each time. Inside the loop rather than beside the
                // plan, so a pass that stops early does not announce work it never reached.
                if let Some(entry) = stale.iter().find(|s| s.name == step.verb.name) {
                    events.emit(SetupEvent::Reapplying {
                        verb: entry.name.clone(),
                        because: entry.because.clone(),
                    });
                }
                let outcome =
                    apply_verb(runtime, fetcher, prefix, step.verb, &work, cancel, events).await;
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
                    Ok(()) => SetupState::Applied,
                    Err(err) => {
                        let reason = err.chain();
                        events.emit(SetupEvent::Failed {
                            what: step.verb.name.clone(),
                            reason: reason.clone(),
                        });
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
        return Err(AddonError::Cancelled);
    }
    Ok(report)
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
fn plan_for<'m>(manifest: &'m ComponentManifest, prefix: &Prefix) -> Result<Planned<'m>> {
    let installed = prefix.components().map_err(|source| AddonError::Io {
        what: "this prefix".to_owned(),
        step: "read what setup it already has",
        path: prefix.metadata_path(),
        source: Box::new(source),
    })?;
    // A verb the record claims but whose effect is gone has to be applied again, so the check happens
    // before the plan is built rather than being discovered halfway through it.
    let stale = stale_verbs(manifest, prefix, &installed);
    let names: Vec<String> = stale.iter().map(|verb| verb.name.clone()).collect();
    Ok(Planned {
        plan: SetupPlan::build(manifest, &installed, &names),
        stale,
    })
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
    Ok(plan_for(manifest.rows(), prefix)?
        .plan
        .steps()
        .iter()
        .filter(|step| step.action == StepAction::Apply)
        .map(|step| step.verb.name.clone())
        .collect())
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
async fn apply_verb(
    runtime: &Runtime,
    fetcher: &Fetcher,
    prefix: &Prefix,
    row: &Verb,
    work: &Path,
    cancel: &CancellationToken,
    events: &SetupEvents,
) -> Result<()> {
    events.emit(SetupEvent::Applying {
        verb: row.name.clone(),
        reason: row.reason.clone(),
    });
    verb::apply(runtime, fetcher, prefix, row, work, cancel, events).await?;
    prefix
        .record_verb(&row.name)
        .map(|_| ())
        .map_err(|source| AddonError::Io {
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

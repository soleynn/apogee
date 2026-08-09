//! The signed catalog of prefix setup, and applying what a prefix is missing.
//!
//! Three things hold across this module.
//!
//! Applying is idempotent, and the prefix's own `prefix.json` is what makes it so. Nothing here keeps a
//! list of its own about what a prefix has, because a second list is a second thing that can be wrong
//! about a prefix somebody else also writes into.
//!
//! One verb failing costs the prefix that verb. A verb a wine refuses is recorded against its own name
//! and the rest continue, because a launch that is otherwise fine should not be stopped by one piece of
//! hygiene. Cancellation is the whole-call failure, and deliberately not a set of failed verbs: what is
//! missing after it is missing because it was asked to stop.
//!
//! Nothing chooses which verbs run. The manifest's list is the setup, so the launch path applies what
//! the prefix does not already have rather than what somebody remembered to switch on.

mod artifact;
mod event;
mod plan;
mod verb;

use std::path::Path;

use apogee_fetch::Fetcher;
use apogee_runtime::{Prefix, Runtime};
use ed25519_dalek::VerifyingKey;
use tokio_util::sync::CancellationToken;
use url::Url;

pub use event::{SetupEvent, SetupEvents};

// The plan is how this module decides, not something a caller composes: it borrows rows out of the
// manifest it was built from, and every consumer of the decision reads the report or the missing list
// instead.
pub(crate) use plan::{SetupPlan, StepAction};

use crate::manifest::{ComponentManifest, Verb};
use crate::{AddonError, Result};

/// What became of one verb.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum SetupState {
    /// Applied now, and recorded in the prefix.
    Applied,
    /// The prefix already recorded it, so nothing was done.
    AlreadyPresent,
    /// Could not be applied. The rest is unaffected.
    Failed { reason: String },
}

/// One verb and what became of it.
#[derive(Debug, Clone)]
pub struct SetupOutcome {
    pub name: String,
    pub state: SetupState,
}

/// Everything one setup pass did.
#[derive(Debug, Clone, Default)]
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
/// keeping setup in signed data.
///
/// And it publishes into the cache only after the signature verifies, so what
/// [`cached_manifest`] later offers as a fallback is a manifest that once verified, and a bad or
/// truncated fetch cannot destroy the last good one.
pub(crate) async fn fetch_manifest(
    fetcher: &Fetcher,
    manifest_url: &Url,
    signature_url: &Url,
    cache_dir: &Path,
    keys: &[VerifyingKey],
    cancel: &CancellationToken,
) -> Result<ComponentManifest> {
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
    // Which key admitted it is deliberately dropped here. An overlap window exists so that a launch
    // does not have to care which side of a rotation it is on; the re-sign it is waiting for is a
    // maintainer's business and is asserted where the hosted file is embedded, not on a user's machine.
    let (parsed, _trusted) = ComponentManifest::parse_and_verify(&manifest, &signature, keys)?;

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

/// The last manifest a fetch verified and left in `cache_dir`, re-verified against `key` before it is
/// handed back.
///
/// `None` when nothing has been fetched yet. A signature check stands between the cache and every caller,
/// so this is a freshness fallback and never a trust one: the worst it can serve is yesterday's rows,
/// which for a launch beats applying no prefix setup at all. Whether that trade is the right one is the
/// caller's to make, which is why fetching and reading the cache are separate calls.
pub(crate) async fn cached_manifest(
    cache_dir: &Path,
    keys: &[VerifyingKey],
) -> Result<Option<ComponentManifest>> {
    let manifest_path = cache_dir.join(MANIFEST_FILE);
    let signature_path = cache_dir.join(SIGNATURE_FILE);
    let (Ok(manifest), Ok(signature)) = (
        tokio::fs::read(&manifest_path).await,
        tokio::fs::read(&signature_path).await,
    ) else {
        return Ok(None);
    };
    let (parsed, _trusted) = ComponentManifest::parse_and_verify(&manifest, &signature, keys)?;
    Ok(Some(parsed))
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

/// Apply every verb `manifest` defines that `prefix` is missing.
///
/// # Errors
/// [`AddonError::Io`] wrapping the runtime's error if the prefix's record cannot be read: without it
/// there is no way to tell setup that is needed from setup that is not, and re-running everything
/// against a live prefix is worse than stopping. [`AddonError::Cancelled`] if the token fired, which
/// ends the pass rather than failing the verbs it did not get to.
pub(crate) async fn apply_verbs(
    runtime: &Runtime,
    fetcher: &Fetcher,
    manifest: &ComponentManifest,
    prefix: &Prefix,
    cancel: &CancellationToken,
    events: &SetupEvents,
) -> Result<SetupReport> {
    let plan = plan_for(manifest, prefix)?;

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

/// What a pass over `prefix` would do about every verb `manifest` defines.
///
/// The one place the decision is made, so what [`missing_verbs`] names and what [`apply_verbs`]
/// applies are the same answer rather than two readings of the same prefix that can disagree.
///
/// # Errors
/// [`AddonError::Io`] if the prefix's record cannot be read.
fn plan_for<'m>(manifest: &'m ComponentManifest, prefix: &Prefix) -> Result<SetupPlan<'m>> {
    let installed = prefix.components().map_err(|source| AddonError::Io {
        what: "this prefix".to_owned(),
        step: "read what setup it already has",
        source: Box::new(source),
    })?;
    // A verb the record claims but whose effect is gone has to be applied again, so the check happens
    // before the plan is built rather than being discovered halfway through it.
    let stale = stale_verbs(manifest, prefix, &installed);
    Ok(SetupPlan::build(manifest, &installed, &stale))
}

/// The verbs `manifest` defines that `prefix` does not have, in manifest order.
///
/// Reads the prefix and changes nothing, which is what makes it answerable for a question a user asked
/// about a prefix rather than only on the way to setting one up. A verb the record claims but whose
/// effect has gone counts as missing here for the same reason it is reapplied: the record is not the
/// evidence, the effect is.
///
/// # Errors
/// As [`plan_for`].
pub(crate) fn missing_verbs(manifest: &ComponentManifest, prefix: &Prefix) -> Result<Vec<String>> {
    Ok(plan_for(manifest, prefix)?
        .steps()
        .iter()
        .filter(|step| step.action == StepAction::Apply)
        .map(|step| step.verb.name.clone())
        .collect())
}

/// The recorded verbs whose effect the manifest says is checkable and which no longer have it.
///
/// Only those naming something to look for: a verb that states nothing has no evidence beyond the
/// record, which is the honest answer for one whose whole effect is a registry value.
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

/// Apply one verb and record it. Recorded only on success, so a failed apply is retried next time
/// rather than remembered as done.
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
            source: Box::new(source),
        })?;
    events.emit(SetupEvent::Applied {
        verb: row.name.clone(),
    });
    Ok(())
}

#[cfg(test)]
mod tests;

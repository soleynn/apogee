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
pub use plan::{PlanStep, SetupPlan, StepAction};

use crate::manifest::ComponentManifest;
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
/// which for a launch beats applying no prefix setup at all. Whether that trade is the right one is the
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

/// Apply every verb `manifest` defines that `prefix` is missing.
///
/// # Errors
/// [`AddonError::Install`] wrapping the runtime's error if the prefix's record cannot be read: without
/// it there is no way to tell setup that is needed from setup that is not, and re-running everything
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
    let installed = prefix.components().map_err(|source| AddonError::Install {
        component: "prefix".to_owned(),
        step: "read the prefix record",
        source: Box::new(source),
    })?;
    // A verb the record claims but whose effect is gone has to be applied again, so the check happens
    // before the plan is built rather than being discovered halfway through it.
    let stale = stale_verbs(manifest, prefix, &installed);
    let plan = SetupPlan::build(manifest, &installed, &stale);

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
                    what: step.name.clone(),
                });
                report.outcomes.push(SetupOutcome {
                    name: step.name.clone(),
                    state: SetupState::AlreadyPresent,
                });
            }
            StepAction::Apply => {
                let outcome = apply_verb(
                    runtime, fetcher, manifest, prefix, &step.name, &work, cancel, events,
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
                    Ok(()) => SetupState::Applied,
                    Err(err) => {
                        let reason = describe(&err);
                        events.emit(SetupEvent::Failed {
                            what: step.name.clone(),
                            reason: reason.clone(),
                        });
                        SetupState::Failed { reason }
                    }
                };
                report.outcomes.push(SetupOutcome {
                    name: step.name.clone(),
                    state,
                });
            }
        }
    }

    // The scratch directory goes either way: a pass that stopped early has no more claim on it than one
    // that finished.
    let _ = tokio::fs::remove_dir_all(&work).await;
    if cancelled {
        return Err(AddonError::Cancelled);
    }
    Ok(report)
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
#[allow(clippy::too_many_arguments)]
async fn apply_verb(
    runtime: &Runtime,
    fetcher: &Fetcher,
    manifest: &ComponentManifest,
    prefix: &Prefix,
    name: &str,
    work: &Path,
    cancel: &CancellationToken,
    events: &SetupEvents,
) -> Result<()> {
    let row = manifest
        .verb(name)
        .ok_or_else(|| AddonError::UnknownComponent {
            name: name.to_owned(),
        })?;
    events.emit(SetupEvent::Applying {
        verb: row.name.clone(),
        reason: row.reason.clone(),
    });
    verb::apply(runtime, fetcher, prefix, row, work, cancel, events).await?;
    prefix
        .record_verb(name)
        .map(|_| ())
        .map_err(|source| AddonError::Install {
            component: name.to_owned(),
            step: "record it in the prefix",
            source: Box::new(source),
        })?;
    events.emit(SetupEvent::Applied {
        verb: row.name.clone(),
    });
    Ok(())
}

/// A failure as one line, with its cause chain, because the outer message alone is usually the least
/// specific part of it.
pub(crate) fn describe(err: &AddonError) -> String {
    let mut text = err.to_string();
    let mut source = std::error::Error::source(err);
    while let Some(cause) = source {
        text.push_str(": ");
        text.push_str(&cause.to_string());
        source = cause.source();
    }
    text
}

#[cfg(test)]
mod tests;

//! Applying one curated prefix-setup step.
//!
//! Every op kind is idempotent on its own: a registry write overwrites rather than adds, a removal treats
//! "it was not there" as success, and a file placement overwrites. That is deliberate rather than
//! incidental, and it is what the verb list is curated around. The prefix's own record short-circuits a
//! verb that has already run, but a record can be lost and a run can be interrupted halfway, so the ops
//! have to converge when they are repeated instead of relying on never being repeated.
//!
//! A verb's effect is checked rather than assumed. Its ops returning success is not evidence that
//! anything landed, and what it wrote can be undone from outside by a runner upgrade. So a verb states
//! what should exist afterwards ([`Verb::verify`]), that is what decides whether the apply succeeded,
//! and the same evidence is what makes a later run notice the effect has gone.
//!
//! **What a verb states and what it can be asked are not the same set**, and the two checks here are
//! different because of it. A [`VerbOp::Files`] can only be checked against `verify`: the destination
//! is a directory, and its existing says nothing about what was supposed to be inside it. A registry
//! op needs nothing stated, because it already declares its own key, name and value, so
//! [`stale`] derives the question from the op and asks the prefix's registry files directly.
//!
//! The post-apply check ([`apply`]) is the paths only, and deliberately so. Wine flushes its registry
//! asynchronously, some time after the program that wrote it exits, so reading the file straight after
//! `reg add` returns would report a value that landed as missing. What evidences the write at that
//! moment is `reg add`'s own exit status, which `registry_set` already reads. By the time [`stale`]
//! runs, on the next launch, nothing has run in the prefix and the file is the answer.

use std::path::Path;

use apogee_fetch::Fetcher;
use apogee_runtime::{Prefix, RegistryEffect, Runtime};
use tokio_util::sync::CancellationToken;

use crate::manifest::{Verb, VerbOp};
use crate::{AddonError, Result};

use super::artifact;
use super::event::SetupEvents;

/// Apply every op in `verb` against `prefix`, in order, then check what it claimed would exist.
///
/// `work` is a scratch directory for any download an op needs; the caller owns removing it.
pub(super) async fn apply(
    runtime: &Runtime,
    fetcher: &Fetcher,
    prefix: &Prefix,
    verb: &Verb,
    work: &Path,
    cancel: &CancellationToken,
    events: &SetupEvents,
) -> Result<()> {
    for op in &verb.ops {
        run_op(runtime, fetcher, prefix, verb, op, work, cancel, events).await?;
    }
    if let Some(missing) = missing(prefix, verb) {
        return Err(AddonError::VerbFailed {
            verb: verb.name.clone(),
            source: Box::new(std::io::Error::other(format!(
                "it finished without producing {}",
                missing.display()
            ))),
        });
    }
    Ok(())
}

/// The first path `verb` promised that is not there, or `None` when every one of them is.
///
/// A verb naming nothing has no path to check, which is every verb whose effect is a registry value:
/// there is no file to look for. Those are answered by [`stale`] instead, off the ops themselves.
pub(super) fn missing<'v>(prefix: &Prefix, verb: &'v Verb) -> Option<&'v Path> {
    let drive_c = prefix.drive_c();
    verb.verify
        .iter()
        .map(crate::manifest::ComponentPath::as_path)
        .find(|path| !drive_c.join(path).exists())
}

/// Why `verb` needs applying again despite the prefix recording it, or `None` when nothing says it
/// does.
///
/// Two sources of evidence, and only one of them is stated in the manifest. The paths `verb` names are
/// checked as [`missing`] checks them, and every registry op is checked against the prefix's own
/// registry files. Anything that cannot be answered leaves the record standing: an unreadable prefix
/// reported as an absence would reapply the same verb on every launch forever.
///
/// A [`VerbOp::Files`] contributes nothing. It names a destination directory rather than what belongs
/// in it, so a directory that outlived its contents would read as intact; `verify` is what makes a
/// placement checkable, which is what it is for.
pub(super) fn stale(prefix: &Prefix, verb: &Verb) -> Option<String> {
    if let Some(path) = missing(prefix, verb) {
        return Some(format!("{} is not there", path.display()));
    }
    verb.ops.iter().find_map(|op| undone(prefix, op))
}

/// How `op`'s effect has been undone, or `None` when it is intact or unanswerable.
fn undone(prefix: &Prefix, op: &VerbOp) -> Option<String> {
    let gone = |effect: RegistryEffect| effect == RegistryEffect::Absent;
    match op {
        VerbOp::Registry(edit) => gone(prefix.registry_effect(edit))
            .then(|| format!("{}\\{} no longer holds what it wrote", edit.key, edit.name)),
        VerbOp::RegistryDelete(delete) => {
            gone(prefix.registry_removal_effect(delete)).then(|| match &delete.name {
                Some(name) => format!("{}\\{name} is back in the registry", delete.key),
                None => format!("{} is back in the registry", delete.key),
            })
        }
        VerbOp::Files { .. } => None,
    }
}

#[allow(clippy::too_many_arguments)]
async fn run_op(
    runtime: &Runtime,
    fetcher: &Fetcher,
    prefix: &Prefix,
    verb: &Verb,
    op: &VerbOp,
    work: &Path,
    cancel: &CancellationToken,
    events: &SetupEvents,
) -> Result<()> {
    let failed = |source: Box<dyn std::error::Error + Send + Sync>| AddonError::VerbFailed {
        verb: verb.name.clone(),
        source,
    };
    match op {
        VerbOp::Registry(edit) => runtime
            .registry_set(prefix, edit, cancel)
            .await
            .map_err(|source| failed(Box::new(source))),
        VerbOp::RegistryDelete(delete) => runtime
            .registry_delete(prefix, delete, cancel)
            .await
            .map_err(|source| failed(Box::new(source))),
        VerbOp::Files {
            artifact: art,
            into,
        } => {
            // Under the prefix's C: drive, never the prefix root: the root holds `prefix.json` and the
            // runner's own relocation, and neither is a verb's business.
            //
            // Passed through rather than wrapped: `install` is already told the verb's name and reports
            // against it, so wrapping would produce a chain that names the verb twice and says nothing
            // more the second time.
            let dest = prefix.drive_c().join(into.as_path());
            artifact::install(fetcher, art, &verb.name, work, &dest, cancel, events)
                .await
                .map(|_entries| ())
        }
    }
}

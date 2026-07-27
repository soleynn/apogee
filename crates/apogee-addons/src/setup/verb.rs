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

use std::path::Path;

use apogee_fetch::Fetcher;
use apogee_runtime::{Prefix, Runtime};
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
/// A verb naming nothing has nothing to check, which is the honest answer for one whose whole effect is a
/// registry value: there is no file to look for, and the prefix's record is the only evidence there is.
pub(super) fn missing<'v>(prefix: &Prefix, verb: &'v Verb) -> Option<&'v Path> {
    let drive_c = prefix.drive_c();
    verb.verify
        .iter()
        .map(crate::manifest::ComponentPath::as_path)
        .find(|path| !drive_c.join(path).exists())
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
            let dest = prefix.drive_c().join(into.as_path());
            artifact::install(fetcher, art, &verb.name, work, &dest, cancel, events)
                .await
                .map(|_entries| ())
                .map_err(|source| failed(Box::new(source)))
        }
    }
}

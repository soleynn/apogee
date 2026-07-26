//! Applying one curated prefix-setup verb.
//!
//! Every op kind is idempotent on its own: a registry write overwrites rather than adds, and a file
//! placement overwrites too. That is deliberate rather than incidental, and it is what the verb list is
//! curated around. The prefix's own record short-circuits a verb that has already run, but a record can
//! be lost and a run can be interrupted halfway, so the ops have to converge when they are repeated
//! instead of relying on never being repeated.

use std::path::Path;

use apogee_fetch::Fetcher;
use apogee_runtime::{Prefix, Runtime};
use tokio_util::sync::CancellationToken;

use crate::manifest::{Verb, VerbOp};
use crate::{AddonError, Result};

use super::artifact;
use super::event::ComponentEvents;

/// Apply every op in `verb` against `prefix`, in order.
///
/// `work` is a scratch directory for any download an op needs; the caller owns removing it.
pub(super) async fn apply(
    runtime: &Runtime,
    fetcher: &Fetcher,
    prefix: &Prefix,
    verb: &Verb,
    work: &Path,
    cancel: &CancellationToken,
    events: &ComponentEvents,
) -> Result<()> {
    for op in &verb.ops {
        match op {
            VerbOp::Registry(edit) => {
                runtime
                    .registry_set(prefix, edit, cancel)
                    .await
                    .map_err(|source| AddonError::VerbFailed {
                        verb: verb.name.clone(),
                        source: Box::new(source),
                    })?;
            }
            VerbOp::Files {
                artifact: art,
                into,
            } => {
                // Under the prefix's C: drive, never the prefix root: the root holds `prefix.json` and
                // the runner's own relocation, and neither is a verb's business.
                let dest = prefix.drive_c().join(into.as_path());
                artifact::install(fetcher, art, &verb.name, work, &dest, cancel, events)
                    .await
                    .map_err(|source| AddonError::VerbFailed {
                        verb: verb.name.clone(),
                        source: Box::new(source),
                    })?;
            }
        }
    }
    Ok(())
}

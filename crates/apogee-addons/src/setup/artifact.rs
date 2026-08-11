//! Getting a pinned artifact onto disk.
//!
//! One path for every *pinned* download, so the digest pin is checked in exactly one place and
//! nothing downstream is handed a path to bytes that failed it: the fetcher returns a
//! [`VerifiedFile`], which only it can mint, and that is what reaches extraction.
//!
//! The signed manifest itself is the one download that does not come through here, because it has
//! no pin to check: an Ed25519 signature stands in its place, and its fetch lives beside the
//! verification that gates it.

use std::path::{Path, PathBuf};
use std::time::Duration;

use apogee_fetch::{DownloadSpec, FetchError, Fetcher, Validator, VerifiedFile};
use tokio_util::sync::CancellationToken;

use super::event::{SetupEvent, SetupEvents};
use crate::manifest::Artifact;
use crate::{AddonError, Result};

/// How many times to (re)start a download before giving up, over whatever the fetcher already spent
/// on the request internally; each restart resumes from the journal rather than from zero. Worth
/// having here because the artifacts are tens of megabytes and prefix setup is not something to make
/// a user restart. Which failures are worth a restart is [`FetchError::is_transient`], answered by
/// the crate that raises them.
const MAX_DOWNLOAD_ATTEMPTS: u32 = 4;
const RETRY_DELAY: Duration = Duration::from_millis(100);

/// Download `artifact` into `work`, verify its digest, and extract it into `dest`.
///
/// `what` names whatever the caller is setting up, and is what every failure is reported against.
/// Returns the number of entries written.
///
/// # Errors
/// [`AddonError::EmptyArchive`] when the archive yields nothing under its declared layout. Zero is a
/// failure rather than an empty success: it means the row's layout is wrong, and sealing that as
/// applied would leave an empty directory that never gets fixed. Otherwise whatever [`download`]
/// failed with, or [`AddonError::Unpack`] if the archive does not unpack.
pub(super) async fn install(
    fetcher: &Fetcher,
    artifact: &Artifact,
    what: &str,
    work: &Path,
    dest: &Path,
    cancel: &CancellationToken,
    events: &SetupEvents,
) -> Result<u64> {
    let cache = work.join(format!("{what}.archive"));
    let verified = download(fetcher, artifact, what, &cache, cancel, events).await?;

    let archive = verified.path().to_path_buf();
    let layout = artifact.archive.clone();
    let target = dest.to_path_buf();
    let named = what.to_owned();
    let entries = tokio::task::spawn_blocking(move || extract(&archive, &layout, &target, &named))
        .await
        .map_err(|source| AddonError::Unpack {
            what: what.to_owned(),
            source: Box::new(source),
        })??;
    if entries == 0 {
        return Err(AddonError::EmptyArchive {
            what: what.to_owned(),
        });
    }
    let _ = tokio::fs::remove_file(&cache).await;
    Ok(entries)
}

/// Extract on a blocking thread. Split out so the non-Linux build has somewhere to say no: the
/// extractor is part of the runner surface, which is Linux-first.
///
/// # Errors
/// [`AddonError::Unpack`] if the archive does not unpack.
#[cfg(target_os = "linux")]
fn extract(
    archive: &Path,
    layout: &apogee_runtime::ArchiveLayout,
    dest: &Path,
    what: &str,
) -> Result<u64> {
    apogee_runtime::extract_archive(archive, layout, dest).map_err(|source| AddonError::Unpack {
        what: what.to_owned(),
        source: Box::new(source),
    })
}

/// Where the non-Linux build says no.
///
/// # Errors
/// Always [`AddonError::Unsupported`].
#[cfg(not(target_os = "linux"))]
fn extract(
    _archive: &Path,
    _layout: &apogee_runtime::ArchiveLayout,
    _dest: &Path,
    _what: &str,
) -> Result<u64> {
    Err(AddonError::Unsupported {
        what: "placing a verb's files goes through a prefix runner, which is Linux-only",
    })
}

/// Download and verify one artifact, relaying progress onto the setup event stream.
///
/// # Errors
/// [`AddonError::IntegrityMismatch`] if the bytes that arrived are not the ones the manifest pinned,
/// [`AddonError::Download`] if the transfer did not complete after [`MAX_DOWNLOAD_ATTEMPTS`],
/// [`AddonError::Io`] if the staging directory cannot be made, [`AddonError::Spec`] if the row's URL
/// is not one the fetcher will take.
async fn download(
    fetcher: &Fetcher,
    artifact: &Artifact,
    what: &str,
    dest: &Path,
    cancel: &CancellationToken,
    events: &SetupEvents,
) -> Result<VerifiedFile> {
    if let Some(parent) = dest.parent() {
        tokio::fs::create_dir_all(parent)
            .await
            .map_err(|source| io_failed(what, "stage a download", parent, source))?;
    }
    let spec =
        DownloadSpec::builder(artifact.url.clone(), dest, Validator::from(artifact.pin)).build()?;

    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<apogee_fetch::Progress>();
    let sink = events.clone();
    let name = what.to_owned();
    let relay = tokio::spawn(async move {
        while let Some(progress) = rx.recv().await {
            sink.emit(SetupEvent::Downloading {
                what: name.clone(),
                bytes_done: progress.bytes_done,
                total: progress.total,
                recoveries: progress.recoveries,
            });
        }
    });

    // Each pass is a fresh `download` call with its own counters, so a restart here resets the
    // recovery tally the relay above reports: it measures what one transfer recovered from, not what
    // this loop did on top. A whole-download restart is visible in the tracing log instead.
    let mut attempt = 0u32;
    let outcome: std::result::Result<VerifiedFile, FetchError> = loop {
        attempt += 1;
        match fetcher
            .download(&spec, Some(tx.clone()), cancel.clone())
            .await
        {
            Ok(verified) => break Ok(verified),
            Err(e) if attempt < MAX_DOWNLOAD_ATTEMPTS && e.is_transient() => {
                tokio::time::sleep(RETRY_DELAY).await;
            }
            Err(e) => break Err(e),
        }
    };
    // Dropped so the relay sees a closed channel and finishes.
    drop(tx);
    let _ = relay.await;

    // A pin that does not match is its own thing, not a download problem: the bytes arrived, they are
    // just not the bytes the signed manifest promised. `from_fetch` is where that is decided, for this
    // call and every other one.
    outcome.map_err(|source| AddonError::from_fetch(source, what, dest))
}

/// A filesystem step, with the path beside the error the filesystem raised rather than folded into a
/// replacement for it: `io::Error` names a kind and nothing about which file raised it.
pub(super) fn io_failed(
    what: &str,
    step: &'static str,
    path: &Path,
    source: std::io::Error,
) -> AddonError {
    AddonError::Io {
        what: what.to_owned(),
        step,
        path: path.to_path_buf(),
        source: Box::new(source),
    }
}

/// A scratch directory for one verb's download and staging, removed by the caller.
pub(super) fn work_dir(root: &Path) -> PathBuf {
    root.join(WORK_DIR)
}

/// Named for what it holds rather than for the withdrawn feature that first wrote it. A prefix an
/// older build touched can still hold the old directory; it is scratch either way, so it is swept
/// alongside the current one rather than left to accumulate.
const WORK_DIR: &str = ".apogee-setup-work";
const LEGACY_WORK_DIR: &str = ".apogee-component-work";

/// Remove this prefix's scratch directories, whichever build wrote them.
pub(super) async fn clear_work_dirs(root: &Path) {
    for name in [WORK_DIR, LEGACY_WORK_DIR] {
        let _ = tokio::fs::remove_dir_all(root.join(name)).await;
    }
}

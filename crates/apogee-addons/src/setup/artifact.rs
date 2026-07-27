//! Getting a pinned artifact onto disk.
//!
//! One path for every *pinned* download, so the sha256 pin is checked in exactly one place and nothing
//! downstream is handed a path to bytes that failed it: the fetcher returns a `VerifiedFile`, which only
//! it can mint, and that is what reaches extraction. The signed manifest itself is the one download that
//! does not come through here, because it has no pin to check: an Ed25519 signature stands in its place
//! and its fetch lives beside the verification that gates it.

use std::path::{Path, PathBuf};
use std::time::Duration;

use apogee_fetch::{DownloadSpec, FetchError, Fetcher, Validator, VerifiedFile};
use tokio_util::sync::CancellationToken;

use super::event::{SetupEvent, SetupEvents};
use crate::manifest::Artifact;
use crate::{AddonError, Result};

/// How many times to (re)start a download before giving up. The fetcher has no internal retry, so a
/// dropped connection resumes from its journal on the next attempt. Worth having here because the
/// artifacts are tens of megabytes and a component install is not something to make a user restart.
const MAX_DOWNLOAD_ATTEMPTS: u32 = 4;
const RETRY_DELAY: Duration = Duration::from_millis(100);

/// Download `artifact` into `work`, verify its sha256, and extract it into `dest`.
///
/// Returns the number of entries written. Zero is a failure rather than an empty success: an archive
/// that yields nothing under its declared strip prefix means the row's layout is wrong, and sealing
/// that as installed would leave an empty directory that never gets fixed.
pub(super) async fn install(
    fetcher: &Fetcher,
    artifact: &Artifact,
    component: &str,
    work: &Path,
    dest: &Path,
    cancel: &CancellationToken,
    events: &SetupEvents,
) -> Result<u64> {
    let cache = work.join(format!("{component}.archive"));
    let verified = download(fetcher, artifact, component, &cache, cancel, events).await?;

    let archive = verified.path().to_path_buf();
    let layout = artifact.archive.clone();
    let target = dest.to_path_buf();
    let named = component.to_owned();
    let entries = tokio::task::spawn_blocking(move || extract(&archive, &layout, &target, &named))
        .await
        .map_err(|_| install_failed(component, "extract", "the extraction task panicked"))??;
    if entries == 0 {
        return Err(install_failed(
            component,
            "extract",
            "the archive held nothing under the layout the manifest describes",
        ));
    }
    let _ = tokio::fs::remove_file(&cache).await;
    Ok(entries)
}

/// Extract on a blocking thread. Split out so the non-Linux build has somewhere to say no: the
/// extractor is part of the runner surface, which is Linux-first.
#[cfg(target_os = "linux")]
fn extract(
    archive: &Path,
    layout: &apogee_runtime::ArchiveLayout,
    dest: &Path,
    component: &str,
) -> Result<u64> {
    apogee_runtime::extract_archive(archive, layout, dest).map_err(|source| AddonError::Install {
        component: component.to_owned(),
        step: "extract",
        source: Box::new(source),
    })
}

#[cfg(not(target_os = "linux"))]
fn extract(
    _archive: &Path,
    _layout: &apogee_runtime::ArchiveLayout,
    _dest: &Path,
    _component: &str,
) -> Result<u64> {
    Err(AddonError::Unsupported {
        what: "installing components is Linux-only at this phase",
    })
}

/// Download and verify one artifact, relaying progress onto the setup event stream.
async fn download(
    fetcher: &Fetcher,
    artifact: &Artifact,
    component: &str,
    dest: &Path,
    cancel: &CancellationToken,
    events: &SetupEvents,
) -> Result<VerifiedFile> {
    if let Some(parent) = dest.parent() {
        tokio::fs::create_dir_all(parent)
            .await
            .map_err(|source| io_failed(component, "download", parent, source))?;
    }
    let spec = DownloadSpec::builder(
        artifact.url.clone(),
        dest,
        Validator::Sha256(artifact.sha256),
    )
    .build()?;

    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<apogee_fetch::Progress>();
    let sink = events.clone();
    let name = component.to_owned();
    let relay = tokio::spawn(async move {
        while let Some(progress) = rx.recv().await {
            sink.emit(SetupEvent::Downloading {
                what: name.clone(),
                bytes_done: progress.bytes_done,
                total: progress.total,
            });
        }
    });

    let mut attempt = 0u32;
    let outcome: std::result::Result<VerifiedFile, FetchError> = loop {
        attempt += 1;
        match fetcher
            .download(&spec, Some(tx.clone()), cancel.clone())
            .await
        {
            Ok(verified) => break Ok(verified),
            Err(e) if attempt < MAX_DOWNLOAD_ATTEMPTS && is_transient(&e) => {
                tokio::time::sleep(RETRY_DELAY).await;
            }
            Err(e) => break Err(e),
        }
    };
    // Dropped so the relay sees a closed channel and finishes.
    drop(tx);
    let _ = relay.await;

    match outcome {
        Ok(verified) => Ok(verified),
        // A pin that does not match is its own thing, not a download problem: the bytes arrived, they
        // are just not the bytes the signed manifest promised.
        Err(FetchError::FileVerifyFailed { expected, got }) => Err(AddonError::IntegrityMismatch {
            component: component.to_owned(),
            expected,
            got,
        }),
        Err(other) => Err(other.into()),
    }
}

fn is_transient(e: &FetchError) -> bool {
    matches!(
        e,
        FetchError::Transport { .. } | FetchError::Connect { .. } | FetchError::Stalled { .. }
    )
}

pub(super) fn install_failed(
    component: &str,
    step: &'static str,
    detail: impl Into<String>,
) -> AddonError {
    AddonError::Install {
        component: component.to_owned(),
        step,
        source: Box::new(std::io::Error::other(detail.into())),
    }
}

pub(super) fn io_failed(
    component: &str,
    step: &'static str,
    path: &Path,
    source: std::io::Error,
) -> AddonError {
    AddonError::Install {
        component: component.to_owned(),
        step,
        source: Box::new(std::io::Error::new(
            source.kind(),
            format!("{}: {source}", path.display()),
        )),
    }
}

/// A scratch directory for one component's download and staging, removed by the caller.
pub(super) fn work_dir(root: &Path) -> PathBuf {
    root.join(".apogee-component-work")
}

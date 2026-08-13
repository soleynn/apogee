//! Installing DXVK, and its `dxvk-nvapi` companion, into a prefix.
//!
//! The pinned archives are downloaded and extracted through the injected fetcher, their 64- and
//! 32-bit DLLs are copied into the prefix's `system32` and `syswow64`, and the result is recorded
//! in `prefix.json`. Placing the DLLs is all this does: what overrides them to native at launch is
//! the environment matrix.

use std::collections::VecDeque;
use std::ffi::OsStr;
use std::path::{Path, PathBuf};

use apogee_fetch::{DigestPin, Fetcher};
use tokio_util::sync::CancellationToken;
use url::Url;

use crate::catalog::{ArchiveFormat, ArchiveLayout, DxvkEntry};
use crate::env::DXVK_DLL_STEMS;
use crate::error::RuntimeError;
use crate::extract::extract_archive;
use crate::install::download_verified;
use crate::metadata::{DxvkRef, PrefixMetadata, RunnerRef, SetupRecord};
use crate::plan::Prefix;
use crate::progress::{Progress, RuntimeEvent};
use crate::{SetupStep, error::HealthIssue, error::PrefixWants};

/// The 64-bit `dxvk-nvapi` DLL, the one the health check requires when nvapi was installed.
const NVAPI_DLL: &str = "nvapi64.dll";
/// The per-prefix scratch directory for downloads and extraction, removed after every install.
const WORK_DIR: &str = ".apogee-dxvk";

/// Install `dxvk` into `prefix`, with `dxvk-nvapi` if asked for, and record it in `prefix.json`.
///
/// `nvapi` is honored only where the catalog entry actually carries a pinned nvapi artifact.
///
/// # Errors
///
/// Whatever [`download_verified`] raises, including a [`RuntimeError::Download`] carrying the
/// cancellation ([`RuntimeError::is_cancellation`] recognizes it). [`RuntimeError::Extract`] if an
/// archive cannot be extracted or holds no `x64`/`x32` DLLs, [`RuntimeError::Io`] if a DLL cannot be
/// written or an existing record cannot be read, and [`RuntimeError::PrefixJson`] if that record is
/// corrupt or the updated one cannot be serialized.
pub(crate) async fn install(
    fetcher: &Fetcher,
    dxvk: &DxvkEntry,
    prefix: &Prefix,
    nvapi: bool,
    cancel: &CancellationToken,
    progress: &Progress,
) -> Result<(), RuntimeError> {
    let install_nvapi = nvapi && dxvk.nvapi.is_some();
    progress.emit(RuntimeEvent::DxvkInstalling {
        version: dxvk.version.clone(),
        nvapi: install_nvapi,
    });

    let wine_root = prefix.wine_root();
    let system32 = wine_root.join("drive_c/windows/system32");
    let syswow64 = wine_root.join("drive_c/windows/syswow64");
    // A per-prefix scratch dir keeps concurrent installs into *different* prefixes from clobbering a
    // shared staging directory or download cache.
    let work = wine_root.join(WORK_DIR);

    let outcome = install_all(
        fetcher,
        dxvk,
        install_nvapi,
        &system32,
        &syswow64,
        &work,
        cancel,
        progress,
    )
    .await;
    // Remove the scratch dir whether the install succeeded or failed, so nothing is left behind.
    let _ = tokio::fs::remove_dir_all(&work).await;
    outcome?;

    record(prefix, &dxvk.version, install_nvapi)?;
    progress.emit(RuntimeEvent::DxvkReady {
        version: dxvk.version.clone(),
    });
    Ok(())
}

/// The DLL file names the health check requires, given what `prefix.json` recorded.
///
/// Derived from the same [`DXVK_DLL_STEMS`] the environment matrix overrides, so the set placed and
/// the set verified cannot diverge.
pub(crate) fn expected_dlls(dxvk: &DxvkRef) -> Vec<String> {
    let mut dlls: Vec<String> = DXVK_DLL_STEMS
        .iter()
        .map(|stem| format!("{stem}.dll"))
        .collect();
    if dxvk.nvapi {
        dlls.push(NVAPI_DLL.to_owned());
    }
    dlls
}

/// Whether the prefix lacks the companion that was asked for.
///
/// Reads the record rather than the DLLs, and has to: a Proton prefix carries its runner's own
/// `nvapi64.dll` from the moment it is built (measured byte-identical to GE-Proton 11-1's
/// `files/lib/wine/nvapi/x86_64-windows/nvapi64.dll` on a prefix recording `nvapi: false`), so a
/// file check would call the companion installed on every Proton prefix and never report the one
/// thing this exists to report.
// A free function rather than a branch inside `check`, so it goes red on its own.
pub(crate) fn nvapi_missing(recorded: Option<&DxvkRef>, wanted: bool) -> bool {
    wanted && !recorded.is_some_and(|dxvk| dxvk.nvapi)
}

/// Report what the prefix recorded and does not have.
///
/// Appends a [`HealthIssue`] for every recorded DXVK DLL missing from `system32`, and one for a
/// companion that was wanted and is not recorded. The DLL half is scoped to the 64-bit `system32`
/// on purpose: the game (`ffxiv_dx11.exe`) is 64-bit, so a missing `syswow64` copy cannot affect a
/// launch and is not a health problem.
pub(crate) fn check(
    wine_root: &Path,
    recorded: Option<&DxvkRef>,
    wants: &PrefixWants,
    issues: &mut Vec<HealthIssue>,
) {
    if let Some(dxvk) = recorded {
        let system32 = wine_root.join("drive_c/windows/system32");
        for dll in expected_dlls(dxvk) {
            let path = system32.join(&dll);
            if !path.exists() {
                issues.push(HealthIssue::MissingDxvkDll { dll, path });
            }
        }
    }
    if nvapi_missing(recorded, wants.nvapi) {
        issues.push(HealthIssue::MissingNvapi);
    }
}

/// Install the DXVK archive, then the nvapi one when requested. The caller owns `work` and its
/// cleanup.
///
/// # Errors
///
/// As [`install_dlls`].
#[allow(clippy::too_many_arguments)]
async fn install_all(
    fetcher: &Fetcher,
    dxvk: &DxvkEntry,
    install_nvapi: bool,
    system32: &Path,
    syswow64: &Path,
    work: &Path,
    cancel: &CancellationToken,
    progress: &Progress,
) -> Result<(), RuntimeError> {
    install_dlls(
        fetcher,
        &dxvk.url,
        dxvk.pin,
        dxvk.format,
        "dxvk",
        system32,
        syswow64,
        work,
        cancel,
        progress,
    )
    .await?;
    if install_nvapi {
        // Present by construction of `install_nvapi`.
        if let Some(nv) = &dxvk.nvapi {
            install_dlls(
                fetcher,
                &nv.url,
                nv.pin,
                nv.format,
                "dxvk-nvapi",
                system32,
                syswow64,
                work,
                cancel,
                progress,
            )
            .await?;
        }
    }
    Ok(())
}

/// Download, extract, and copy one artifact's `x64` and `x32` DLLs into `system32` and `syswow64`.
///
/// `name` labels the artifact in the scratch paths and in the error for an archive with no DLLs.
///
/// # Errors
///
/// Whatever [`download_verified`] raises, [`RuntimeError::Extract`] if the extraction fails or
/// panics or the archive yields no DLLs at all, and [`RuntimeError::Io`] from [`copy_arch_dlls`].
#[allow(clippy::too_many_arguments)]
async fn install_dlls(
    fetcher: &Fetcher,
    url: &Url,
    pin: DigestPin,
    format: ArchiveFormat,
    name: &str,
    system32: &Path,
    syswow64: &Path,
    work: &Path,
    cancel: &CancellationToken,
    progress: &Progress,
) -> Result<(), RuntimeError> {
    let cache = work.join(format!("{name}.archive"));
    let verified = download_verified(fetcher, url, pin, &cache, cancel, progress).await?;

    let staging = work.join(format!("{name}.stage"));
    let _ = tokio::fs::remove_dir_all(&staging).await; // clear any partial prior extraction
    let archive = verified.path().to_path_buf();
    let staging_for_task = staging.clone();
    let archive_for_err = archive.clone();
    let layout = ArchiveLayout {
        format,
        strip_prefix: None,
    };
    tokio::task::spawn_blocking(move || extract_archive(&archive, &layout, &staging_for_task))
        .await
        .map_err(|_| RuntimeError::Extract {
            archive: archive_for_err.clone(),
            source: std::io::Error::other("extraction task panicked"),
        })??;

    let copied =
        copy_arch_dlls(&staging, "x64", system32)? + copy_arch_dlls(&staging, "x32", syswow64)?;
    if copied == 0 {
        return Err(RuntimeError::Extract {
            archive: archive_for_err,
            source: std::io::Error::other(format!("{name} archive contained no x64/x32 DLLs")),
        });
    }
    Ok(())
}

/// Copy every `.dll` from the extracted tree's `arch` directory into `dest`, returning the count.
///
/// A missing `arch` directory copies nothing and is not an error: an nvapi build with no 32-bit
/// half is the ordinary case.
///
/// # Errors
///
/// [`RuntimeError::Io`] if `dest` cannot be created, the source directory cannot be read, or a copy
/// fails.
fn copy_arch_dlls(staging: &Path, arch: &str, dest: &Path) -> Result<usize, RuntimeError> {
    let Some(src) = find_dir(staging, arch) else {
        return Ok(0);
    };
    std::fs::create_dir_all(dest).map_err(|source| RuntimeError::Io {
        path: dest.to_path_buf(),
        source,
    })?;
    let mut copied = 0;
    for entry in std::fs::read_dir(&src).map_err(|source| RuntimeError::Io {
        path: src.clone(),
        source,
    })? {
        let entry = entry.map_err(|source| RuntimeError::Io {
            path: src.clone(),
            source,
        })?;
        let path = entry.path();
        if path
            .extension()
            .is_some_and(|e| e.eq_ignore_ascii_case("dll"))
        {
            let target = dest.join(entry.file_name());
            std::fs::copy(&path, &target).map_err(|source| RuntimeError::Io {
                path: target,
                source,
            })?;
            copied += 1;
        }
    }
    Ok(copied)
}

/// The shallowest directory named exactly `name` in the extracted tree, if there is one.
///
/// Breadth-first because an archive may or may not wrap its `x64` and `x32` directories in a
/// top-level version directory. An unreadable subdirectory is skipped rather than fatal.
fn find_dir(root: &Path, name: &str) -> Option<PathBuf> {
    let mut queue = VecDeque::from([root.to_path_buf()]);
    while let Some(dir) = queue.pop_front() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            if entry.file_type().is_ok_and(|t| t.is_dir()) {
                if entry.file_name() == OsStr::new(name) {
                    return Some(entry.path());
                }
                queue.push_back(entry.path());
            }
        }
    }
    None
}

/// Record the install in `prefix.json`: set the `dxvk` field and append a setup step.
///
/// # Errors
///
/// [`RuntimeError::PrefixJson`] if the existing file is corrupt or the new one cannot be
/// serialized, [`RuntimeError::Io`] if the existing one cannot be read or the new one cannot be
/// written.
fn record(prefix: &Prefix, version: &str, nvapi: bool) -> Result<(), RuntimeError> {
    let path = prefix.metadata_path();
    let mut meta = PrefixMetadata::load(&path)?
        .unwrap_or_else(|| PrefixMetadata::new(RunnerRef::from(prefix.runner())));
    meta.dxvk = Some(DxvkRef {
        version: version.to_owned(),
        nvapi,
    });
    meta.record(SetupRecord::ok_with(SetupStep::DxvkInstall, version));
    meta.save(&path)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn recorded(nvapi: bool) -> DxvkRef {
        DxvkRef {
            version: "3.0.2".to_owned(),
            nvapi,
        }
    }

    /// Both halves of the comparison, including the two that are not drift.
    ///
    /// A prefix that has the companion nobody asked for is not a problem: the record is per prefix
    /// and the wish is per profile, so two profiles sharing one prefix disagree by design, and the
    /// launch that does not want it says so in its environment instead.
    #[test]
    fn the_companion_is_missing_only_where_it_was_wanted_and_is_not_recorded() {
        assert!(nvapi_missing(Some(&recorded(false)), true));
        assert!(nvapi_missing(None, true));
        assert!(!nvapi_missing(Some(&recorded(true)), true));
        assert!(!nvapi_missing(Some(&recorded(true)), false));
        assert!(!nvapi_missing(Some(&recorded(false)), false));
        assert!(!nvapi_missing(None, false));
    }
}

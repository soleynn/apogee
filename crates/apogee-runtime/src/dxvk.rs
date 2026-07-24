//! Installing DXVK (and its `dxvk-nvapi` companion) into a prefix: the pinned tarballs are downloaded
//! and extracted through the injected fetcher, their 64- and 32-bit DLLs copied into the prefix's
//! `system32`/`syswow64`, and the result recorded in `prefix.json`. The environment matrix
//! ([`crate::env`]) is what overrides the DLLs to native at launch; this only places them.

use std::collections::VecDeque;
use std::ffi::OsStr;
use std::path::{Path, PathBuf};

use apogee_fetch::Fetcher;
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
use crate::{SetupStep, error::HealthIssue};

/// The 64-bit `dxvk-nvapi` DLL, checked additionally when nvapi was installed.
const NVAPI_DLL: &str = "nvapi64.dll";
/// A per-prefix scratch directory for downloads and extraction, removed after each install.
const WORK_DIR: &str = ".apogee-dxvk";

/// Install `dxvk` into `prefix`, optionally including `dxvk-nvapi`, and record it in `prefix.json`.
/// `nvapi` is honored only if the catalog entry actually carries a pinned nvapi artifact.
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

/// The DXVK DLLs the health check requires in `system32`, given what `prefix.json` recorded. Derived
/// from the same [`DXVK_DLL_STEMS`] the environment matrix overrides, so the two cannot diverge.
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

/// Report any recorded DXVK DLL missing from the prefix's 64-bit `system32`. Intentionally scoped to
/// the 64-bit DLLs the game (`ffxiv_dx11.exe`) actually loads; the 32-bit `syswow64` copies do not
/// affect a 64-bit launch, so a missing one is not treated as a health problem.
pub(crate) fn check(wine_root: &Path, dxvk: &DxvkRef, issues: &mut Vec<HealthIssue>) {
    let system32 = wine_root.join("drive_c/windows/system32");
    for dll in expected_dlls(dxvk) {
        let path = system32.join(&dll);
        if !path.exists() {
            issues.push(HealthIssue::MissingDxvkDll { dll, path });
        }
    }
}

/// Install the DXVK tarball, then the nvapi one if requested. The caller owns cleanup of `work`.
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
        dxvk.sha256,
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
                nv.sha256,
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

/// Download, extract, and copy one artifact's `x64`/`x32` DLLs into `system32`/`syswow64`.
#[allow(clippy::too_many_arguments)]
async fn install_dlls(
    fetcher: &Fetcher,
    url: &Url,
    sha256: [u8; 32],
    format: ArchiveFormat,
    name: &str,
    system32: &Path,
    syswow64: &Path,
    work: &Path,
    cancel: &CancellationToken,
    progress: &Progress,
) -> Result<(), RuntimeError> {
    let cache = work.join(format!("{name}.archive"));
    let verified = download_verified(fetcher, url, sha256, &cache, cancel, progress).await?;

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

/// Copy every `.dll` from the `arch` subdirectory of the extracted tree into `dest`, returning the
/// count. A missing `arch` directory (e.g. an nvapi build with no 32-bit half) copies nothing.
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

/// Find the shallowest directory named exactly `name` in the extracted tree (breadth-first, since the
/// tarball may or may not wrap its `x64`/`x32` dirs in a top-level version directory). An unreadable
/// subdirectory is skipped, not fatal.
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

/// Record the DXVK install in `prefix.json`: set the `dxvk` field and append a setup step.
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

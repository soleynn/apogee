//! Downloading and extracting runners and supporting tools through the injected fetcher, plus
//! fetching the signed catalog itself.

use std::path::{Path, PathBuf};
use std::time::Duration;

use apogee_fetch::{DownloadSpec, FetchError, Fetcher, Validator, VerifiedFile};
use ed25519_dalek::VerifyingKey;
use tokio_util::sync::CancellationToken;
use url::Url;

use crate::catalog::{ArchiveLayout, CATALOG_PUBLIC_KEY, Catalog, Runner, ToolEntry};
use crate::error::{CatalogError, RuntimeError};
use crate::extract::extract_archive;
use crate::progress::{Progress, RuntimeEvent};

/// A marker written into a runner/tool directory once its extraction completed, so a re-run skips a
/// finished install but retries an interrupted one. It lives outside the extracted tree so an
/// archive entry cannot plant it and a partial extraction cannot leave a stale one.
const INSTALLED_DIR: &str = ".installed";

/// How many times to (re)start a download before giving up. The injected fetcher has no internal
/// retry, so a dropped connection resumes from its journal on the next attempt.
const MAX_DOWNLOAD_ATTEMPTS: u32 = 4;
const RETRY_DELAY: Duration = Duration::from_millis(100);

/// Ensure `runner` is installed under `runners_root`, returning its directory.
pub(crate) async fn install_runner(
    fetcher: &Fetcher,
    runner: &Runner,
    runners_root: &Path,
    cancel: &CancellationToken,
    progress: &Progress,
) -> Result<PathBuf, RuntimeError> {
    let dir = install_artifact(
        fetcher,
        &runner.name,
        &runner.version,
        &runner.url,
        runner.sha256,
        &runner.archive,
        runners_root,
        cancel,
        progress,
    )
    .await?;
    progress.emit(RuntimeEvent::RunnerReady {
        name: runner.name.clone(),
        version: runner.version.clone(),
    });
    Ok(dir)
}

/// Ensure `tool` (e.g. `umu-launcher`) is installed under `tools_root`, returning its directory.
pub(crate) async fn install_tool(
    fetcher: &Fetcher,
    tool: &ToolEntry,
    tools_root: &Path,
    cancel: &CancellationToken,
    progress: &Progress,
) -> Result<PathBuf, RuntimeError> {
    let dir = install_artifact(
        fetcher,
        &tool.name,
        &tool.version,
        &tool.url,
        tool.sha256,
        &tool.archive,
        tools_root,
        cancel,
        progress,
    )
    .await?;
    progress.emit(RuntimeEvent::ToolReady {
        name: tool.name.clone(),
        version: tool.version.clone(),
    });
    Ok(dir)
}

#[allow(clippy::too_many_arguments)]
async fn install_artifact(
    fetcher: &Fetcher,
    name: &str,
    version: &str,
    url: &Url,
    sha256: [u8; 32],
    layout: &ArchiveLayout,
    root: &Path,
    cancel: &CancellationToken,
    progress: &Progress,
) -> Result<PathBuf, RuntimeError> {
    let dir = root.join(format!("{name}-{version}"));
    let installed_dir = root.join(INSTALLED_DIR);
    let marker = installed_dir.join(format!("{name}-{version}"));
    if marker.is_file() {
        return Ok(dir);
    }
    let cache = root.join(".cache").join(format!("{name}-{version}.tar"));
    let verified = download_verified(fetcher, url, sha256, &cache, cancel, progress).await?;

    progress.emit(RuntimeEvent::Extracting {
        name: name.to_owned(),
        version: version.to_owned(),
    });
    let archive = verified.path().to_path_buf();
    let layout = layout.clone();
    let target = dir.clone();
    let archive_for_err = archive.clone();
    let entries = tokio::task::spawn_blocking(move || extract_archive(&archive, &layout, &target))
        .await
        .map_err(|_| RuntimeError::Extract {
            archive: archive_for_err.clone(),
            source: std::io::Error::other("extraction task panicked"),
        })??;
    // A verified archive that yields nothing under the strip prefix (a mismatched prefix, an empty
    // tarball) must not be sealed as a finished install, or the empty directory is cached forever.
    if entries == 0 {
        return Err(RuntimeError::Extract {
            archive: archive_for_err,
            source: std::io::Error::other("archive contained no entries under the expected prefix"),
        });
    }

    tokio::fs::create_dir_all(&installed_dir)
        .await
        .map_err(|e| io_err(&installed_dir, e))?;
    tokio::fs::write(&marker, b"")
        .await
        .map_err(|e| io_err(&marker, e))?;
    let _ = tokio::fs::remove_file(&cache).await;
    Ok(dir)
}

/// Download `url` to `dest`, verifying its whole-file sha256 and relaying download progress into the
/// runtime event stream. A dropped connection resumes from the fetcher's journal on the next attempt.
pub(crate) async fn download_verified(
    fetcher: &Fetcher,
    url: &Url,
    sha256: [u8; 32],
    dest: &Path,
    cancel: &CancellationToken,
    progress: &Progress,
) -> Result<VerifiedFile, RuntimeError> {
    if let Some(parent) = dest.parent() {
        tokio::fs::create_dir_all(parent)
            .await
            .map_err(|e| io_err(parent, e))?;
    }
    let spec = DownloadSpec::builder(url.clone(), dest, Validator::Sha256(sha256)).build()?;

    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<apogee_fetch::Progress>();
    let sink = progress.clone();
    let relay = tokio::spawn(async move {
        while let Some(p) = rx.recv().await {
            sink.emit(RuntimeEvent::Download(p));
        }
    });

    let mut attempt = 0u32;
    let outcome: Result<VerifiedFile, FetchError> = loop {
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
    // Drop our sender so the relay observes the closed channel and finishes.
    drop(tx);
    let _ = relay.await;
    Ok(outcome?)
}

/// Fetch the signed catalog: download the manifest and its detached signature over HTTPS, then verify
/// against the compiled-in key. The manifest's own bytes are not sha-pinned ahead of time; the
/// Ed25519 signature is the authenticity gate.
pub(crate) async fn fetch_catalog(
    fetcher: &Fetcher,
    manifest_url: &Url,
    signature_url: &Url,
    cache_dir: &Path,
    cancel: &CancellationToken,
) -> Result<Catalog, RuntimeError> {
    tokio::fs::create_dir_all(cache_dir)
        .await
        .map_err(|e| io_err(cache_dir, e))?;
    let manifest_path = cache_dir.join("catalog.json");
    let signature_path = cache_dir.join("catalog.json.sig");
    download_unverified(fetcher, manifest_url, &manifest_path, cancel).await?;
    download_unverified(fetcher, signature_url, &signature_path, cancel).await?;

    let manifest = tokio::fs::read(&manifest_path)
        .await
        .map_err(|e| io_err(&manifest_path, e))?;
    let signature = tokio::fs::read(&signature_path)
        .await
        .map_err(|e| io_err(&signature_path, e))?;
    let key =
        VerifyingKey::from_bytes(&CATALOG_PUBLIC_KEY).map_err(|_| CatalogError::BadSignature)?;
    Ok(Catalog::parse_and_verify(&manifest, &signature, &key)?)
}

/// Download `url` to `dest` over HTTPS without a content pin (the caller authenticates the bytes some
/// other way, e.g. an Ed25519 signature). Refused over plain `http`.
async fn download_unverified(
    fetcher: &Fetcher,
    url: &Url,
    dest: &Path,
    cancel: &CancellationToken,
) -> Result<(), RuntimeError> {
    if let Some(parent) = dest.parent() {
        tokio::fs::create_dir_all(parent)
            .await
            .map_err(|e| io_err(parent, e))?;
    }
    let spec = DownloadSpec::builder(url.clone(), dest, Validator::None)
        .allow_unverified()
        .build()?;
    fetcher.download(&spec, None, cancel.clone()).await?;
    Ok(())
}

fn is_transient(e: &FetchError) -> bool {
    matches!(
        e,
        FetchError::Transport { .. } | FetchError::Connect { .. } | FetchError::Stalled { .. }
    )
}

fn io_err(path: &Path, source: std::io::Error) -> RuntimeError {
    RuntimeError::Io {
        path: path.to_path_buf(),
        source,
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use apogee_test_support::chaos::{ChaosServer, generated_vec, sha256_of};
    use tokio_util::sync::CancellationToken;

    use super::install_runner;
    use crate::catalog::{ArchiveFormat, ArchiveLayout, Runner, RunnerKind};
    use crate::progress::Progress;

    /// A gzip'd tar with one file under `top/files/bin/`, carrying `payload`. These tests exercise the
    /// download/extract path directly (not the full `prepare`, which would go on to `wineboot` a fake
    /// runner), so the payload is an opaque blob, not a real wine binary.
    fn runner_targz(top: &str, payload: &[u8]) -> std::io::Result<Vec<u8>> {
        let mut builder = tar::Builder::new(Vec::new());
        let mut header = tar::Header::new_gnu();
        header.set_size(payload.len() as u64);
        header.set_mode(0o755);
        header.set_entry_type(tar::EntryType::Regular);
        builder.append_data(&mut header, format!("{top}/files/bin/wine"), payload)?;
        let tar = builder.into_inner()?;
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        encoder.write_all(&tar)?;
        encoder.finish()
    }

    #[tokio::test]
    async fn install_downloads_resumes_and_extracts_a_runner() {
        // An incompressible payload keeps the gz sizable, so a mid-stream drop is meaningful.
        let payload = generated_vec(42, 0, 256 * 1024);
        let tar = runner_targz("runner-1.0", &payload).expect("build archive");
        let sha = sha256_of(&tar);
        let len = tar.len() as u64;

        let server = ChaosServer::serving(tar)
            .etag("\"r1\"")
            .drop_after(100 * 1024)
            .chunk(32 * 1024)
            .start()
            .await
            .expect("server");

        let root = tempfile::tempdir().expect("tempdir");
        let runners_root = root.path().join("runners");
        let fetcher = apogee_fetch::Fetcher::builder().build().expect("fetcher");
        let runner = Runner {
            name: "runner".to_owned(),
            version: "1.0".to_owned(),
            kind: RunnerKind::Wine,
            url: server.url("runner.tar.gz"),
            sha256: sha,
            archive: ArchiveLayout {
                format: ArchiveFormat::TarGz,
                strip_prefix: Some("runner-1.0".to_owned()),
            },
        };

        let runner_dir = install_runner(
            &fetcher,
            &runner,
            &runners_root,
            &CancellationToken::new(),
            &Progress::none(),
        )
        .await
        .expect("install");

        assert_eq!(runner_dir, runners_root.join("runner-1.0"));
        assert!(runner_dir.join("files/bin/wine").is_file());
        assert_eq!(
            std::fs::read(runner_dir.join("files/bin/wine")).expect("payload"),
            payload
        );
        assert!(
            server.stats().bytes_served() < 2 * len,
            "resume must not refetch the whole file"
        );
        assert!(
            server.stats().requests() >= 2,
            "the drop should have forced a resume request"
        );
    }

    #[tokio::test]
    async fn a_finished_install_re_downloads_nothing() {
        let payload = generated_vec(7, 0, 8 * 1024);
        let tar = runner_targz("r-2", &payload).expect("build archive");
        let sha = sha256_of(&tar);
        let server = ChaosServer::serving(tar).start().await.expect("server");

        let root = tempfile::tempdir().expect("tempdir");
        let runners_root = root.path().join("runners");
        let fetcher = apogee_fetch::Fetcher::builder().build().expect("fetcher");
        let runner = Runner {
            name: "r".to_owned(),
            version: "2".to_owned(),
            kind: RunnerKind::Wine,
            url: server.url("r.tar.gz"),
            sha256: sha,
            archive: ArchiveLayout {
                format: ArchiveFormat::TarGz,
                strip_prefix: Some("r-2".to_owned()),
            },
        };

        install_runner(
            &fetcher,
            &runner,
            &runners_root,
            &CancellationToken::new(),
            &Progress::none(),
        )
        .await
        .expect("first install");
        let after_first = server.stats().requests();
        install_runner(
            &fetcher,
            &runner,
            &runners_root,
            &CancellationToken::new(),
            &Progress::none(),
        )
        .await
        .expect("second install");

        assert_eq!(
            server.stats().requests(),
            after_first,
            "a completed install must not re-download"
        );
    }
}

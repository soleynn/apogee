//! Downloading and extracting runners and supporting tools through the injected fetcher, plus
//! fetching the signed catalog itself.

use std::path::{Path, PathBuf};
use std::time::Duration;

use apogee_fetch::{DigestPin, DownloadSpec, FetchError, Fetcher, Validator, VerifiedFile};
use ed25519_dalek::VerifyingKey;
use tokio_util::sync::CancellationToken;
use url::Url;

use crate::catalog::{ArchiveLayout, Catalog, Runner, ToolEntry};
use crate::error::RuntimeError;
use crate::extract::extract_archive;
use crate::progress::{Progress, RuntimeEvent};

/// A marker written into a runner/tool directory once its extraction completed, so a re-run skips a
/// finished install but retries an interrupted one. It lives outside the extracted tree so an
/// archive entry cannot plant it and a partial extraction cannot leave a stale one.
const INSTALLED_DIR: &str = ".installed";

/// How many times to (re)start a download before giving up, over whatever the injected fetcher
/// already spent on the request internally; each restart resumes from the journal rather than from
/// zero. Which failures are worth a restart is [`FetchError::is_transient`], answered by the crate
/// that raises them.
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
        runner.pin,
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
        tool.pin,
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
    pin: DigestPin,
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
    let verified = download_verified(fetcher, url, pin, &cache, cancel, progress).await?;

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

/// Download `url` to `dest`, verifying its whole-file digest and relaying download progress into the
/// runtime event stream. A dropped connection resumes from the fetcher's journal on the next attempt.
pub(crate) async fn download_verified(
    fetcher: &Fetcher,
    url: &Url,
    pin: DigestPin,
    dest: &Path,
    cancel: &CancellationToken,
    progress: &Progress,
) -> Result<VerifiedFile, RuntimeError> {
    if let Some(parent) = dest.parent() {
        tokio::fs::create_dir_all(parent)
            .await
            .map_err(|e| io_err(parent, e))?;
    }
    let spec = DownloadSpec::builder(url.clone(), dest, Validator::from(pin)).build()?;

    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<apogee_fetch::Progress>();
    let sink = progress.clone();
    let relay = tokio::spawn(async move {
        while let Some(p) = rx.recv().await {
            sink.emit(RuntimeEvent::Download(p));
        }
    });

    // Each pass is a fresh `download` call with its own counters, so a restart here resets the
    // recovery tally the relay above reports: it measures what one transfer recovered from, not what
    // this loop did on top. A whole-download restart is visible in the tracing log instead.
    let mut attempt = 0u32;
    let outcome: Result<VerifiedFile, FetchError> = loop {
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
    // Drop our sender so the relay observes the closed channel and finishes.
    drop(tx);
    let _ = relay.await;
    outcome.map_err(RuntimeError::from_fetch)
}

/// The names a fetched catalog and its detached signature are cached under.
const CATALOG_FILES: [&str; 2] = ["catalog.json", "catalog.json.sig"];
/// Where a catalog fetch in progress writes, cleared before every attempt.
const CATALOG_STAGING: &str = ".fetching";

/// Fetch the signed catalog: download the manifest and its detached signature over HTTPS, then verify
/// against `key`. The manifest's own bytes are not sha-pinned ahead of time; the Ed25519 signature is
/// the authenticity gate. The key is a parameter rather than read here, so the caller decides what the
/// catalog is trusted against (a shipping caller passes the compiled-in one) and a test can drive this
/// path with a signature it can produce.
///
/// It downloads into a staging directory that is removed first, and that is load-bearing rather than
/// tidiness. The fetcher's `overwrite` knob could force the re-fetch on its own (an unpinned
/// destination is otherwise served back forever, which is exactly the property "a runner bump is a
/// manifest edit" denies), but staging buys the part that knob cannot: the catalog and its detached
/// signature verify as a pair before either replaces the last good copy, so a failed, truncated, or
/// unverifiable fetch never leaves a half-updated cache behind.
pub(crate) async fn fetch_catalog(
    fetcher: &Fetcher,
    manifest_url: &Url,
    signature_url: &Url,
    cache_dir: &Path,
    key: &VerifyingKey,
    cancel: &CancellationToken,
) -> Result<Catalog, RuntimeError> {
    let staging = cache_dir.join(CATALOG_STAGING);
    let _ = tokio::fs::remove_dir_all(&staging).await;
    tokio::fs::create_dir_all(&staging)
        .await
        .map_err(|e| io_err(&staging, e))?;
    let manifest_path = staging.join(CATALOG_FILES[0]);
    let signature_path = staging.join(CATALOG_FILES[1]);
    download_unverified(fetcher, manifest_url, &manifest_path, cancel).await?;
    download_unverified(fetcher, signature_url, &signature_path, cancel).await?;

    let manifest = tokio::fs::read(&manifest_path)
        .await
        .map_err(|e| io_err(&manifest_path, e))?;
    let signature = tokio::fs::read(&signature_path)
        .await
        .map_err(|e| io_err(&signature_path, e))?;
    let catalog = Catalog::parse_and_verify(&manifest, &signature, key)?;

    // Only bytes that verified reach the cache. Two renames rather than one, so a crash between them can
    // leave a manifest beside the previous signature; nothing reads the cache without verifying it, so
    // that is a refused pair rather than a trusted one.
    tokio::fs::create_dir_all(cache_dir)
        .await
        .map_err(|e| io_err(cache_dir, e))?;
    for name in CATALOG_FILES {
        let to = cache_dir.join(name);
        tokio::fs::rename(staging.join(name), &to)
            .await
            .map_err(|e| io_err(&to, e))?;
    }
    let _ = tokio::fs::remove_dir_all(&staging).await;
    Ok(catalog)
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
    fetcher
        .download(&spec, None, cancel.clone())
        .await
        .map_err(RuntimeError::from_fetch)?;
    Ok(())
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

    use apogee_fetch::{DigestPin, FetchError, RetryPolicy};
    use apogee_test_support::chaos::{ChaosServer, RetryAfter, blake3_of, generated_vec};
    use tokio_util::sync::CancellationToken;

    use super::install_runner;
    use crate::catalog::{ArchiveFormat, ArchiveLayout, Runner, RunnerKind};
    use crate::error::RuntimeError;
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
        let pin = DigestPin::Blake3(blake3_of(&tar));
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
            pin,
            archive: ArchiveLayout {
                format: ArchiveFormat::TarGz,
                strip_prefix: Some("runner-1.0".to_owned()),
            },
            ntsync: None,
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
        let pin = DigestPin::Blake3(blake3_of(&tar));
        let server = ChaosServer::serving(tar).start().await.expect("server");

        let root = tempfile::tempdir().expect("tempdir");
        let runners_root = root.path().join("runners");
        let fetcher = apogee_fetch::Fetcher::builder().build().expect("fetcher");
        let runner = Runner {
            name: "r".to_owned(),
            version: "2".to_owned(),
            kind: RunnerKind::Wine,
            url: server.url("r.tar.gz"),
            pin,
            archive: ArchiveLayout {
                format: ArchiveFormat::TarGz,
                strip_prefix: Some("r-2".to_owned()),
            },
            ntsync: None,
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

    /// Ctrl-C while a runner is downloading is the one stop that arrives from the fetcher rather than
    /// from this crate's own spawn or prefix paths, and it comes back wrapped in [`RuntimeError`] like
    /// any other transfer failure. A shell reading the variant alone therefore cannot tell a stopped
    /// download from a broken mirror, so it reads the disposition off the error instead and this pins
    /// what that answers.
    ///
    /// The token is fired before the install starts, so the stop lands at the transfer's first
    /// cancellation check instead of at a chosen offset, and the outcome is the same on every run.
    #[tokio::test]
    async fn a_download_the_token_stopped_reads_as_a_cancellation() {
        let tar = runner_targz("stopped-1", b"payload").expect("build archive");
        let pin = DigestPin::Blake3(blake3_of(&tar));
        let server = ChaosServer::serving(tar).start().await.expect("server");

        let root = tempfile::tempdir().expect("tempdir");
        let runners_root = root.path().join("runners");
        let fetcher = apogee_fetch::Fetcher::builder().build().expect("fetcher");
        let runner = Runner {
            name: "stopped".to_owned(),
            version: "1".to_owned(),
            kind: RunnerKind::Wine,
            url: server.url("stopped.tar.gz"),
            pin,
            archive: ArchiveLayout {
                format: ArchiveFormat::TarGz,
                strip_prefix: Some("stopped-1".to_owned()),
            },
            ntsync: None,
        };

        let cancel = CancellationToken::new();
        cancel.cancel();
        let err = install_runner(&fetcher, &runner, &runners_root, &cancel, &Progress::none())
            .await
            .expect_err("a stopped download is not an install");

        assert!(
            matches!(err, RuntimeError::Download(FetchError::Cancelled)),
            "{err:?}"
        );
        assert!(
            err.is_cancellation(),
            "a runner download the user stopped must not read as a failed install: {err:?}"
        );
    }

    /// A host that throttles for longer than the fetcher's own budget hands the status back as a
    /// plain [`FetchError::Http`], which is the one failure whose disposition cannot be read off the
    /// variant. The restart loop here has to keep asking until the host recovers; reporting the first
    /// `503` would fail an install over a CDN node that was busy for a second.
    ///
    /// The injected fetcher gets a single attempt, so every refusal reaches that loop rather than
    /// being absorbed (and waited out) inside one `download` call.
    #[tokio::test]
    async fn a_throttled_runner_download_is_restarted_until_the_host_serves() {
        let payload = generated_vec(11, 0, 16 * 1024);
        let tar = runner_targz("throttled-1", &payload).expect("build archive");
        let pin = DigestPin::Blake3(blake3_of(&tar));
        let server = ChaosServer::serving(tar)
            .service_unavailable(2, RetryAfter::Seconds(0))
            .start()
            .await
            .expect("server");

        let root = tempfile::tempdir().expect("tempdir");
        let runners_root = root.path().join("runners");
        let fetcher = apogee_fetch::Fetcher::builder()
            .retry_policy(RetryPolicy::default().max_attempts(1))
            .build()
            .expect("fetcher");
        let runner = Runner {
            name: "throttled".to_owned(),
            version: "1".to_owned(),
            kind: RunnerKind::Wine,
            url: server.url("throttled.tar.gz"),
            pin,
            archive: ArchiveLayout {
                format: ArchiveFormat::TarGz,
                strip_prefix: Some("throttled-1".to_owned()),
            },
            ntsync: None,
        };

        let runner_dir = install_runner(
            &fetcher,
            &runner,
            &runners_root,
            &CancellationToken::new(),
            &Progress::none(),
        )
        .await
        .expect("a throttled host must not fail the install");

        assert_eq!(
            std::fs::read(runner_dir.join("files/bin/wine")).expect("payload"),
            payload
        );
        assert_eq!(
            server.stats().requests(),
            3,
            "two refusals, then the transfer that served"
        );
    }
}

//! The install pipeline: acquire ahead through fetch, apply strictly in list order.
//!
//! Fetch's scheduler runs the downloads (bounded concurrency); the apply loop consumes their
//! results in SE order so patch `k` applies only after `0..k`, even when `k` downloaded first. Only
//! an [`Admitted`] patch reaches apply: a game patch is proven by fetch's per-block SHA1, a boot
//! patch by the patcher's own chunk-CRC scan. `.ver` advances per clean patch, `.ver`→`.bck` after
//! the whole set, and a torn apply leaves the old `.ver`, so an interrupted install re-runs cleanly.

use std::future::Future;
use std::io::BufReader;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use apogee_fetch::{
    DownloadSpec, FetchError, Fetcher, HeaderPolicy, Priority, Progress, Validator, VerifiedFile,
};
use apogee_zipatch::{ApplyOptions, ApplyProgress, DiskSink, PatchReader, apply, scan_crc};
use sqex_proto::PatchListEntry;
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use url::Url;

use crate::request::{InstallRequest, Installed, SePatch};
use crate::{PatchError, PatchProgress, PatcherConfig, Repo, preflight, store};

/// Aborts any still-running download task when the orchestrator leaves early (error or cancel).
struct AbortOnDrop(Vec<JoinHandle<()>>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        for handle in &self.0 {
            handle.abort();
        }
    }
}

/// Proof a patch may be applied. A game patch arrives already verified by fetch (per-block SHA1); a
/// boot patch, which carries no patchlist hashes, is admitted by the patcher's own ZiPatch chunk-CRC
/// scan. Sealed with private construction: the only ways to make one are those two verification
/// paths, so an unadmitted patch cannot reach [`apply_one`].
struct Admitted {
    path: PathBuf,
}

impl Admitted {
    /// Wrap a game patch fetch already verified per block; its `VerifiedFile` is the proof.
    fn from_verified(verified: VerifiedFile) -> Self {
        Self {
            path: verified.path().to_path_buf(),
        }
    }

    /// Admit a boot patch by scanning every chunk CRC, its only integrity proof. Runs the whole file
    /// through the parser with CRC verification on; a parse or CRC fault rejects the patch here as
    /// [`PatchError::BootAdmission`], before any byte is applied. Synchronous and CPU/IO-bound: call
    /// it on a blocking worker.
    fn scan_boot(path: PathBuf, index: u32) -> Result<Self, PatchError> {
        let file = std::fs::File::open(&path).map_err(|source| PatchError::Io {
            path: path.clone(),
            source,
        })?;
        let mut reader = PatchReader::open(BufReader::new(file))
            .map_err(|source| PatchError::BootAdmission { index, source })?
            .verify_crc(true);
        scan_crc(&mut reader).map_err(|source| PatchError::BootAdmission { index, source })?;
        Ok(Self { path })
    }

    /// The admitted patch on disk.
    fn path(&self) -> &Path {
        &self.path
    }
}

/// Run one repo's install to completion.
pub(crate) async fn run(
    fetcher: Fetcher,
    config: PatcherConfig,
    request: InstallRequest,
    progress: mpsc::UnboundedSender<PatchProgress>,
    cancel: CancellationToken,
) -> Result<Installed, PatchError> {
    let InstallRequest {
        repo,
        game_root,
        patches,
        headers,
    } = request;

    // The store must exist so preflight can stat it and downloads can write beneath it.
    std::fs::create_dir_all(&config.patch_store).map_err(|source| PatchError::Io {
        path: config.patch_store.clone(),
        source,
    })?;

    if patches.is_empty() {
        return Ok(Installed {
            repo,
            new_version: store::read_ver(&game_root, repo),
        });
    }

    if !config.ignore_space {
        preflight::check(&config, &game_root, &patches)?;
    }

    // Build every download request first: a malformed entry fails the whole install before any task
    // is spawned, so an early return cannot leave a download running past it (spawning is done under
    // the abort guard below, after the last fallible step).
    let mut specs = Vec::with_capacity(patches.len());
    for (i, entry) in patches.iter().enumerate() {
        specs.push(build_spec(
            &config.patch_store,
            entry,
            i as u32,
            repo,
            &headers,
        )?);
    }

    // Acquire: submit every download (fetch caps the real concurrency). Each shares this run's cancel
    // token, forwards its progress, and delivers its verified result over a oneshot the ordered apply
    // loop awaits in turn. Every handle is placed under the guard so an early return aborts the rest.
    let mut results = Vec::with_capacity(specs.len());
    let mut handles = Vec::with_capacity(specs.len());
    for (i, spec) in specs.into_iter().enumerate() {
        let index = i as u32;
        let (tx, rx) = oneshot::channel();
        results.push(rx);
        let fetcher = fetcher.clone();
        let progress = progress.clone();
        let cancel = cancel.clone();
        handles.push(tokio::spawn(async move {
            let result = acquire_one(&fetcher, &spec, repo, index, &progress, cancel).await;
            let _ = tx.send(result);
        }));
    }
    let _guard = AbortOnDrop(handles);

    // Apply: strictly in list order.
    let mut last_bare = String::new();
    for (i, (result, entry)) in results.into_iter().zip(patches.iter()).enumerate() {
        let index = i as u32;
        let admitted = match result.await {
            // `acquire_one` already mapped any fetch/admission failure into the patcher taxonomy
            // (including `Cancelled`), so propagate it verbatim.
            Ok(inner) => inner?,
            // The task always sends a result and is only aborted after this loop exits (on run's
            // return, via the guard), so a missing result here means the task panicked. Surface it
            // as an i/o fault with context, matching Job's panic handling, not a false Cancelled.
            Err(_recv) => {
                return Err(PatchError::Io {
                    path: PathBuf::new(),
                    source: std::io::Error::other(format!(
                        "acquire task for patch {index} ended without a result"
                    )),
                });
            }
        };
        if cancel.is_cancelled() {
            return Err(PatchError::Cancelled);
        }

        apply_one(&admitted, &game_root, repo, index, &progress, &cancel).await?;

        last_bare = store::bare_version(&entry.version_id);
        store::write_ver(&game_root, repo, &last_bare)?;
        let _ = progress.send(PatchProgress::Applied {
            repo,
            index,
            version: last_bare.clone(),
        });

        if !config.keep_patches {
            let _ = std::fs::remove_file(admitted.path());
        }
    }

    store::backup_ver(&game_root, repo)?;
    Ok(Installed {
        repo,
        new_version: last_bare,
    })
}

/// Scheduling priority for a repo's downloads: boot data is admitted ahead of game data.
fn priority_for(repo: Repo) -> Priority {
    if matches!(repo, Repo::Boot) {
        Priority::Boot
    } else {
        Priority::Normal
    }
}

/// Turn one patchlist entry into an admissible download request.
fn build_spec(
    patch_store: &Path,
    entry: &PatchListEntry,
    index: u32,
    repo: Repo,
    headers: &SePatch,
) -> Result<DownloadSpec, PatchError> {
    let bad = |detail: String| PatchError::Patchlist { index, detail };
    // The version drives the `.ver` write; a version that strips to empty (e.g. "" or "D") would
    // persist a zero-byte `.ver` that sqex-proto's sanity gate rejects, so reject the entry here
    // rather than report a clean install with an unusable version.
    if store::bare_version(&entry.version_id).is_empty() {
        return Err(bad(format!(
            "version id {:?} has no numeric version",
            entry.version_id
        )));
    }
    let url = Url::parse(&entry.url).map_err(|e| bad(format!("invalid url: {e}")))?;
    let dest = store::patch_dest(patch_store, &url, index)?;
    if let Some(parent) = dest.parent() {
        std::fs::create_dir_all(parent).map_err(|source| PatchError::Io {
            path: parent.to_path_buf(),
            source,
        })?;
    }
    // Boot patches carry no per-block hashes: fetch delivers their length-checked bytes under the
    // external-verification marker and the patcher's chunk-CRC scan admits them (`acquire_one`).
    // Game and expansion patches verify per block during download.
    let validator = match repo {
        Repo::Boot => Validator::External,
        Repo::Game | Repo::Expansion(_) => block_sha1_validator(entry, index)?,
    };
    DownloadSpec::builder(url, dest, validator)
        .expected_len(entry.length)
        .priority(priority_for(repo))
        .header_policy(HeaderPolicy::SePatch {
            unique_id: headers.unique_id.clone(),
        })
        .build()
        .map_err(|e| bad(format!("cannot build download: {e}")))
}

/// Build the per-block SHA1 validator from a game patch's hashes. Boot patches (no hashes) are
/// admitted through the chunk-CRC gate, not here.
fn block_sha1_validator(entry: &PatchListEntry, index: u32) -> Result<Validator, PatchError> {
    let bad = |detail: String| PatchError::Patchlist { index, detail };
    let block_hashes = entry
        .hashes
        .as_ref()
        .ok_or_else(|| bad("patch carries no per-block hashes to verify".to_owned()))?;
    let block_size = u32::try_from(block_hashes.block_size).map_err(|_| {
        bad(format!(
            "block size {} exceeds u32",
            block_hashes.block_size
        ))
    })?;
    let mut hashes = Vec::with_capacity(block_hashes.hashes.len());
    for hex in &block_hashes.hashes {
        hashes
            .push(decode_sha1_hex(hex).ok_or_else(|| bad(format!("invalid sha1 digest {hex:?}")))?);
    }
    Ok(Validator::BlockSha1 { block_size, hashes })
}

/// Decode a 40-char lowercase-hex SHA1 into its 20 raw bytes.
fn decode_sha1_hex(hex: &str) -> Option<[u8; 20]> {
    if hex.len() != 40 {
        return None;
    }
    let mut out = [0u8; 20];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(hex.get(2 * i..2 * i + 2)?, 16).ok()?;
    }
    Some(out)
}

/// Acquire one patch and admit it: fetch its bytes, then prove them. A game patch comes back as a
/// fetch [`VerifiedFile`] (per-block SHA1 checked during download); a boot patch, which carries no
/// hashes, is fetched under the external-verification marker and admitted by a chunk-CRC scan on a
/// blocking worker. Either way the result is an [`Admitted`] token the apply loop consumes in order.
async fn acquire_one(
    fetcher: &Fetcher,
    spec: &DownloadSpec,
    repo: Repo,
    index: u32,
    progress: &mpsc::UnboundedSender<PatchProgress>,
    cancel: CancellationToken,
) -> Result<Admitted, PatchError> {
    match repo {
        Repo::Boot => {
            let path = with_progress_relay(
                |tx| fetcher.download_external(spec, Some(tx), cancel.clone()),
                repo,
                index,
                progress,
            )
            .await
            .map_err(acquire_err)?;
            // Chunk-CRC admission reads the whole patch: run it off the async runtime.
            tokio::task::spawn_blocking(move || Admitted::scan_boot(path, index))
                .await
                .map_err(|join| PatchError::Io {
                    path: PathBuf::new(),
                    source: std::io::Error::other(join),
                })?
        }
        Repo::Game | Repo::Expansion(_) => {
            let verified = with_progress_relay(
                |tx| fetcher.download(spec, Some(tx), cancel.clone()),
                repo,
                index,
                progress,
            )
            .await
            .map_err(acquire_err)?;
            Ok(Admitted::from_verified(verified))
        }
    }
}

/// Map a fetch failure into the patcher taxonomy: a cancellation stays [`PatchError::Cancelled`],
/// everything else is an [`PatchError::Acquire`] carrying fetch's block/offset/attempt context.
fn acquire_err(err: FetchError) -> PatchError {
    match err {
        FetchError::Cancelled => PatchError::Cancelled,
        other => PatchError::Acquire(other),
    }
}

/// Drive a fetch transfer while forwarding its progress onto the aggregate stream.
///
/// The forwarding is inline (not a detached task): the returned future resolves exactly when the
/// transfer settles, and dropping it (on cancel/abort) drops the fetch progress sender with it, so no
/// relay task can outlive the download holding a stream handle open. `make` is handed the fetch
/// progress sender and returns the transfer future, so this works for both the verified
/// (`download`) and externally-verified (`download_external`) paths.
async fn with_progress_relay<T, Fut>(
    make: impl FnOnce(mpsc::UnboundedSender<Progress>) -> Fut,
    repo: Repo,
    index: u32,
    progress: &mpsc::UnboundedSender<PatchProgress>,
) -> T
where
    Fut: Future<Output = T>,
{
    let relay = |p: Progress| {
        let _ = progress.send(PatchProgress::Downloading {
            repo,
            index,
            bytes_done: p.bytes_done,
            total: p.total,
        });
    };
    let (tx, mut rx) = mpsc::unbounded_channel::<Progress>();
    let transfer = make(tx);
    tokio::pin!(transfer);
    loop {
        tokio::select! {
            biased;
            result = &mut transfer => {
                // Relay any progress buffered before the transfer settled, then finish.
                while let Ok(p) = rx.try_recv() {
                    relay(p);
                }
                return result;
            }
            Some(p) = rx.recv() => relay(p),
        }
    }
}

/// Apply one admitted patch on a blocking thread, relaying its progress and honoring cancellation.
///
/// Takes the [`Admitted`] token by reference, not a bare path, so the verified-before-apply invariant
/// is carried by the type into the one place that writes bytes, not just by the call site.
async fn apply_one(
    admitted: &Admitted,
    game_root: &Path,
    repo: Repo,
    index: u32,
    progress: &mpsc::UnboundedSender<PatchProgress>,
    cancel: &CancellationToken,
) -> Result<(), PatchError> {
    let apply_root = store::repo_root(game_root, repo);
    let patch_path = admitted.path().to_path_buf();

    // Bridge the async cancel token to zipatch's between-commands AtomicBool flag.
    let flag = Arc::new(AtomicBool::new(cancel.is_cancelled()));
    let watcher = {
        let flag = flag.clone();
        let cancel = cancel.clone();
        tokio::spawn(async move {
            cancel.cancelled().await;
            flag.store(true, Ordering::Relaxed);
        })
    };

    // Drain zipatch's synchronous progress onto our stream from a blocking task.
    let (ztx, zrx) = std::sync::mpsc::channel::<ApplyProgress>();
    let drain = {
        let progress = progress.clone();
        tokio::task::spawn_blocking(move || {
            while let Ok(p) = zrx.recv() {
                let _ = progress.send(PatchProgress::Applying {
                    repo,
                    index,
                    bytes_done: p.bytes_done,
                    total: p.total,
                });
            }
        })
    };

    let outcome = tokio::task::spawn_blocking(move || -> Result<(), PatchError> {
        let file = std::fs::File::open(&patch_path).map_err(|source| PatchError::Io {
            path: patch_path.clone(),
            source,
        })?;
        let mut reader = PatchReader::open(BufReader::new(file))?.verify_crc(false);
        let mut sink = DiskSink::new(&apply_root)?;
        let opts = ApplyOptions {
            progress: Some(&ztx),
            cancel: Some(&flag),
        };
        match apply(&mut reader, &mut sink, &opts) {
            Ok(()) => Ok(()),
            Err(apogee_zipatch::Error::Cancelled) => Err(PatchError::Cancelled),
            Err(err) => Err(PatchError::Apply(err)),
        }
    })
    .await;

    watcher.abort();
    let _ = drain.await;

    match outcome {
        Ok(inner) => inner,
        Err(join) if join.is_cancelled() => Err(PatchError::Cancelled),
        Err(join) => Err(PatchError::Io {
            path: PathBuf::new(),
            source: std::io::Error::other(join),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_sha1_hex_roundtrips_and_rejects_bad_input() {
        let hex = "0123456789abcdef0123456789abcdef01234567";
        let bytes = decode_sha1_hex(hex).unwrap();
        assert_eq!(bytes[0], 0x01);
        assert_eq!(bytes[19], 0x67);
        assert_eq!(decode_sha1_hex("tooshort"), None);
        assert_eq!(decode_sha1_hex(&"zz".repeat(20)), None);
    }

    #[test]
    fn build_spec_rejects_an_entry_whose_version_strips_to_empty() {
        // A hostile entry whose version_id is all-alphabetic ("D") strips to an empty `.ver` value;
        // reject it before download rather than persist a version sqex-proto's gate refuses.
        let entry = PatchListEntry {
            length: 64,
            version_id: "D".to_owned(),
            url: "https://patch.example.invalid/game/4e9a232b/D.patch".to_owned(),
            hashes: Some(sqex_proto::BlockHashes {
                hash_type: "sha1".to_owned(),
                block_size: 64,
                hashes: vec!["ab".repeat(20)],
            }),
        };
        let err = build_spec(
            std::path::Path::new("/nonexistent-store"),
            &entry,
            3,
            Repo::Game,
            &SePatch::new("s"),
        )
        .unwrap_err();
        assert!(
            matches!(err, PatchError::Patchlist { index: 3, .. }),
            "got {err:?}"
        );
    }
}

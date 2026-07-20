//! The single-connection streaming download state machine.
//!
//! A download streams the body to a `.part` sidecar, hashing as it writes, and flushes the journal
//! watermark only after the corresponding bytes are `fsync`ed, so a crash never leaves the journal
//! naming bytes that are not on disk. On success the file is verified, atomically renamed onto its
//! destination, and the journal removed. An interrupted transfer resumes from the journal watermark
//! with `Range` + `If-Range`; a source that changed (a `200` where a `206` was asked for) restarts
//! cleanly from zero. An existing destination is re-hashed against the validator, not trusted on its
//! path, so a `VerifiedFile` is never minted over unverified bytes.

use std::ffi::OsString;
use std::fmt::Write as _;
use std::io::SeekFrom;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use futures_util::StreamExt;
use reqwest::header::{CONTENT_RANGE, ETAG, IF_RANGE, LAST_MODIFIED, RANGE};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use url::Url;

use crate::error::FetchError;
use crate::journal::{self, Identity, Journal};
use crate::limiter::LimitHandle;
use crate::progress::{Phase, Progress};
use crate::scheduler::Scheduler;
use crate::spec::DownloadSpec;
use crate::validator::{Validator, VerifiedFile};

/// How many bytes are streamed between `fsync` + journal-commit points, and the size of the in-memory
/// write buffer: the trade of throughput (one large write and one fsync per batch) against the bytes a
/// kill can cost (a resume re-fetches at most this much).
const BATCH: u64 = 1024 * 1024;
/// The buffer size for reading a file back to hash it (resume re-seed, existing-dest verification).
const READ_CHUNK: usize = 64 * 1024;

/// Run one single-connection download to completion.
///
/// The transfer draws `limiter` tokens on the bytes it reads off the socket and holds one connection
/// slot from `scheduler` for its lifetime, so it counts against the global connection cap the same as
/// a segment does.
pub(crate) async fn run(
    client: &reqwest::Client,
    spec: &DownloadSpec,
    progress: Option<mpsc::UnboundedSender<Progress>>,
    cancel: CancellationToken,
    limiter: &LimitHandle,
    scheduler: &Arc<Scheduler>,
) -> Result<VerifiedFile, FetchError> {
    let expected_sha = expected_sha(spec.validator())?;

    let dest = spec.dest();
    let part = sidecar(dest, ".part");
    let apdl = sidecar(dest, ".apdl");

    if let Some(verified) =
        check_existing_dest(dest, expected_sha, spec.expected_len(), &progress).await?
    {
        return Ok(verified);
    }

    // Hold one global connection slot for the transfer, so a single-connection download counts against
    // the same cap as a segment. Released when this scope ends.
    let _conn = scheduler.acquire_connection().await;

    let core_identity = Identity {
        url: spec.url().as_str().to_owned(),
        expected_len: spec.expected_len(),
        validator_digest: spec.validator().config_digest(),
        etag: None,
        last_modified: None,
    };

    // Reconcile a prior attempt: resume only when the journal matches this request, records real
    // progress, and the `.part` is at least that long.
    let mut start = 0u64;
    let mut if_range: Option<Vec<u8>> = None;
    let mut journal_identity = core_identity.clone();
    if spec.resume()
        && let Some(loaded) = journal::load(&apdl)
            .await
            .map_err(|e| FetchError::io(&apdl, e))?
        && loaded.identity.matches(&core_identity)
        && loaded.watermark() > 0
        && let Ok(meta) = tokio::fs::metadata(&part).await
        && meta.is_file()
        && meta.len() >= loaded.watermark()
    {
        start = loaded.watermark();
        if_range = loaded
            .identity
            .etag
            .clone()
            .or_else(|| loaded.identity.last_modified.clone());
        journal_identity = loaded.identity;
    }

    let mut hasher: Option<Sha256> = expected_sha.map(|_| Sha256::new());
    let mut part_file = open_part(&part, start, hasher.as_mut()).await?;
    let mut journal: Option<Journal> = if spec.resume() && start > 0 {
        Some(
            Journal::open_append(&apdl)
                .await
                .map_err(|e| FetchError::io(&apdl, e))?,
        )
    } else {
        None
    };

    let resp = obtain_response(
        client,
        spec,
        &part,
        &mut part_file,
        &mut hasher,
        &mut journal,
        &mut start,
        &mut if_range,
    )
    .await?;

    // The first progress event is emitted only after the resume disposition is settled, so
    // `bytes_done` never regresses (a 200-restart has already reset `start` to 0 here).
    emit(
        &progress,
        Progress {
            bytes_done: start,
            total: spec.expected_len(),
            phase: Phase::Connecting,
        },
    );

    if let (Some(exp), Some(cl)) = (spec.expected_len(), resp.content_length()) {
        let server_total = start.saturating_add(cl);
        if server_total != exp {
            return Err(FetchError::LengthMismatch {
                expected: exp,
                got: server_total,
            });
        }
    }
    let total = spec
        .expected_len()
        .or_else(|| resp.content_length().map(|cl| cl.saturating_add(start)));

    // A fresh start records the server's validators so a later resume can revalidate with `If-Range`.
    if spec.resume() && journal.is_none() {
        journal_identity.etag = header_bytes(&resp, &ETAG);
        journal_identity.last_modified = header_bytes(&resp, &LAST_MODIFIED);
        journal = Journal::create(&apdl, &journal_identity)
            .await
            .map_err(|e| FetchError::io(&apdl, e))?;
    }

    // Stream the body into a batch buffer: one write and one fsync+journal-commit per batch, so a
    // multi-GB transfer issues thousands of writes, not millions. Hashing reads the arriving chunk,
    // so it is unaffected by the buffering.
    let mut stream = Box::pin(resp.bytes_stream());
    let mut written = start;
    let mut batch: Vec<u8> = Vec::with_capacity(BATCH as usize);
    emit(
        &progress,
        Progress {
            bytes_done: written,
            total,
            phase: Phase::Downloading,
        },
    );
    loop {
        let item = tokio::select! {
            biased;
            () = cancel.cancelled() => {
                write_batch(&mut part_file, &part, &mut batch).await?;
                flush_and_commit(&mut part_file, &part, &mut journal, &apdl, written).await?;
                return Err(FetchError::Cancelled);
            }
            item = stream.next() => item,
        };
        let Some(chunk) = item else { break };
        let chunk = chunk.map_err(|e| transport_error(spec.url(), e))?;
        let bytes: &[u8] = chunk.as_ref();
        // Throttle on the bytes just read off the socket, before consuming more.
        limiter.acquire(bytes.len() as u64).await;
        if let Some(h) = hasher.as_mut() {
            h.update(bytes);
        }
        batch.extend_from_slice(bytes);
        written += bytes.len() as u64;
        if batch.len() as u64 >= BATCH {
            write_batch(&mut part_file, &part, &mut batch).await?;
            flush_and_commit(&mut part_file, &part, &mut journal, &apdl, written).await?;
            emit(
                &progress,
                Progress {
                    bytes_done: written,
                    total,
                    phase: Phase::Downloading,
                },
            );
        }
    }
    write_batch(&mut part_file, &part, &mut batch).await?;
    flush_and_commit(&mut part_file, &part, &mut journal, &apdl, written).await?;

    if let Some(exp) = spec.expected_len()
        && written != exp
    {
        return Err(FetchError::LengthMismatch {
            expected: exp,
            got: written,
        });
    }

    if let (Some(h), Some(exp)) = (hasher.take(), expected_sha) {
        emit(
            &progress,
            Progress {
                bytes_done: written,
                total,
                phase: Phase::Verifying,
            },
        );
        let got = digest_bytes(h);
        if got != exp {
            // Drop the journal so a retry restarts from zero instead of re-hashing the same bad bytes;
            // the .part survives for triage.
            let _ = tokio::fs::remove_file(&apdl).await;
            return Err(FetchError::FileVerifyFailed {
                expected: hex(&exp),
                got: hex(&got),
            });
        }
    }

    // Publish: durable file, then an atomic rename that replaces any existing dest in one step,
    // then a directory fsync for rename durability, then drop the journal.
    part_file
        .sync_all()
        .await
        .map_err(|e| FetchError::io(&part, e))?;
    drop(part_file);
    tokio::fs::rename(&part, dest)
        .await
        .map_err(|e| FetchError::io(dest, e))?;
    sync_parent_dir(dest).await;
    let _ = tokio::fs::remove_file(&apdl).await;

    emit(
        &progress,
        Progress {
            bytes_done: written,
            total,
            phase: Phase::Complete,
        },
    );
    Ok(VerifiedFile::mint(dest))
}

/// Send the request, handling the resume dispositions: a valid `206` continues from `start`; a `200`
/// (source changed, or the server ignored the range) restarts cleanly from zero; a `416` or an
/// unusable `206` re-requests once from zero.
#[allow(clippy::too_many_arguments)]
async fn obtain_response(
    client: &reqwest::Client,
    spec: &DownloadSpec,
    part: &Path,
    part_file: &mut tokio::fs::File,
    hasher: &mut Option<Sha256>,
    journal: &mut Option<Journal>,
    start: &mut u64,
    if_range: &mut Option<Vec<u8>>,
) -> Result<reqwest::Response, FetchError> {
    for attempt in 0..2 {
        let mut req = client.get(spec.url().clone());
        if *start > 0 {
            req = req.header(RANGE, format!("bytes={}-", *start));
            if let Some(value) = if_range.as_deref()
                && let Ok(header) = reqwest::header::HeaderValue::from_bytes(value)
            {
                req = req.header(IF_RANGE, header);
            }
        }
        let resp = req.send().await.map_err(|e| connect_error(spec.url(), e))?;
        let status = resp.status().as_u16();

        if status == 200 {
            if *start > 0 {
                reset_to_zero(part_file, part, hasher, journal, start, if_range).await?;
            }
            return Ok(resp);
        }
        if status == 206 && *start > 0 && content_range_ok(&resp, *start, spec.expected_len()) {
            return Ok(resp);
        }
        if (status == 206 || status == 416) && *start > 0 && attempt == 0 {
            reset_to_zero(part_file, part, hasher, journal, start, if_range).await?;
            continue;
        }
        return Err(FetchError::Http {
            status,
            url: spec.url().clone(),
        });
    }
    // Unreachable: the second pass always returns or errors. Report, never panic.
    Err(FetchError::Http {
        status: 0,
        url: spec.url().clone(),
    })
}

/// Open the `.part` for writing at `start`: create it fresh at zero, or truncate an existing file to
/// `start`, re-seed the running hash from its prefix, and position at the end for appending.
async fn open_part(
    part: &Path,
    start: u64,
    hasher: Option<&mut Sha256>,
) -> Result<tokio::fs::File, FetchError> {
    if start == 0 {
        return tokio::fs::File::create(part)
            .await
            .map_err(|e| FetchError::io(part, e));
    }
    let mut file = tokio::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(part)
        .await
        .map_err(|e| FetchError::io(part, e))?;
    file.set_len(start)
        .await
        .map_err(|e| FetchError::io(part, e))?;
    if let Some(h) = hasher {
        file.seek(SeekFrom::Start(0))
            .await
            .map_err(|e| FetchError::io(part, e))?;
        let mut remaining = start;
        let mut buf = vec![0u8; READ_CHUNK];
        while remaining > 0 {
            let want = usize::try_from(remaining.min(READ_CHUNK as u64)).unwrap_or(READ_CHUNK);
            let read = file
                .read(&mut buf[..want])
                .await
                .map_err(|e| FetchError::io(part, e))?;
            if read == 0 {
                break;
            }
            h.update(&buf[..read]);
            remaining -= read as u64;
        }
    }
    file.seek(SeekFrom::Start(start))
        .await
        .map_err(|e| FetchError::io(part, e))?;
    Ok(file)
}

/// Truncate the `.part`, reset the running hash, drop the journal, and clear the resume position, so
/// a fresh body streams from zero.
async fn reset_to_zero(
    part_file: &mut tokio::fs::File,
    part: &Path,
    hasher: &mut Option<Sha256>,
    journal: &mut Option<Journal>,
    start: &mut u64,
    if_range: &mut Option<Vec<u8>>,
) -> Result<(), FetchError> {
    part_file
        .set_len(0)
        .await
        .map_err(|e| FetchError::io(part, e))?;
    part_file
        .seek(SeekFrom::Start(0))
        .await
        .map_err(|e| FetchError::io(part, e))?;
    if let Some(h) = hasher.as_mut() {
        *h = Sha256::new();
    }
    *journal = None;
    *start = 0;
    *if_range = None;
    Ok(())
}

/// Flush the buffered batch to the part file.
async fn write_batch(
    part_file: &mut tokio::fs::File,
    part: &Path,
    batch: &mut Vec<u8>,
) -> Result<(), FetchError> {
    if !batch.is_empty() {
        part_file
            .write_all(batch)
            .await
            .map_err(|e| FetchError::io(part, e))?;
        batch.clear();
    }
    Ok(())
}

/// Flush the data durable, then advance the journal watermark: the record never names bytes the disk
/// has not confirmed.
async fn flush_and_commit(
    part_file: &mut tokio::fs::File,
    part: &Path,
    journal: &mut Option<Journal>,
    apdl: &Path,
    watermark: u64,
) -> Result<(), FetchError> {
    part_file
        .flush()
        .await
        .map_err(|e| FetchError::io(part, e))?;
    part_file
        .sync_data()
        .await
        .map_err(|e| FetchError::io(part, e))?;
    if let Some(j) = journal.as_mut() {
        // The single-connection path always holds the contiguous prefix, so it commits `[0, watermark)`;
        // coalescing collapses the successive prefixes back to one interval.
        j.commit_interval(0, watermark)
            .await
            .map_err(|e| FetchError::io(apdl, e))?;
    }
    Ok(())
}

/// The whole-file SHA256 a validator expects: `Some` for [`Validator::Sha256`], `None` for
/// [`Validator::None`]. Block-hash validation is not implemented on this path yet.
///
/// # Errors
/// [`FetchError::Unsupported`] for [`Validator::BlockSha1`].
pub(crate) fn expected_sha(validator: &Validator) -> Result<Option<[u8; 32]>, FetchError> {
    match validator {
        Validator::Sha256(digest) => Ok(Some(*digest)),
        Validator::None => Ok(None),
        Validator::BlockSha1 { .. } => Err(FetchError::Unsupported {
            what: "block-hash validation",
        }),
    }
}

/// Idempotent skip: return an existing destination only if it still satisfies the validator, so a
/// `VerifiedFile` is never minted over unverified or stale bytes. The re-hash reads local disk only,
/// never the network, so an unchanged file is not re-downloaded. `Ok(None)` means "not satisfied,
/// proceed with the download".
pub(crate) async fn check_existing_dest(
    dest: &Path,
    expected_sha: Option<[u8; 32]>,
    expected_len: Option<u64>,
    progress: &Option<mpsc::UnboundedSender<Progress>>,
) -> Result<Option<VerifiedFile>, FetchError> {
    if let Ok(meta) = tokio::fs::metadata(dest).await
        && meta.is_file()
        && dest_satisfies(dest, meta.len(), expected_sha, expected_len).await?
    {
        emit(
            progress,
            Progress {
                bytes_done: meta.len(),
                total: expected_len,
                phase: Phase::Complete,
            },
        );
        return Ok(Some(VerifiedFile::mint(dest)));
    }
    Ok(None)
}

/// Whether an existing destination already satisfies the request: the declared length (if any) and,
/// for a hashing validator, the whole-file digest. The digest is recomputed from disk so the skip
/// never trusts a file's path as proof.
async fn dest_satisfies(
    dest: &Path,
    len: u64,
    expected_sha: Option<[u8; 32]>,
    expected_len: Option<u64>,
) -> Result<bool, FetchError> {
    if expected_len.is_some_and(|n| n != len) {
        return Ok(false);
    }
    match expected_sha {
        None => Ok(true),
        Some(expected) => Ok(hash_file(dest).await? == expected),
    }
}

/// SHA256 a file on disk in bounded memory.
pub(crate) async fn hash_file(path: &Path) -> Result<[u8; 32], FetchError> {
    let mut file = tokio::fs::File::open(path)
        .await
        .map_err(|e| FetchError::io(path, e))?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; READ_CHUNK];
    loop {
        let read = file
            .read(&mut buf)
            .await
            .map_err(|e| FetchError::io(path, e))?;
        if read == 0 {
            break;
        }
        hasher.update(&buf[..read]);
    }
    Ok(digest_bytes(hasher))
}

/// Finalize a SHA256 into a fixed array.
fn digest_bytes(hasher: Sha256) -> [u8; 32] {
    hasher.finalize().into()
}

/// Whether a `206`'s `Content-Range` starts exactly where we resumed and (when known) reports the
/// expected total.
fn content_range_ok(resp: &reqwest::Response, start: u64, expected_len: Option<u64>) -> bool {
    let Some(value) = resp
        .headers()
        .get(CONTENT_RANGE)
        .and_then(|v| v.to_str().ok())
    else {
        return false;
    };
    let Some((range, total)) = value.strip_prefix("bytes ").and_then(|r| r.split_once('/')) else {
        return false;
    };
    let Some((first, _last)) = range.split_once('-') else {
        return false;
    };
    if first.parse::<u64>().ok() != Some(start) {
        return false;
    }
    match (expected_len, total) {
        (Some(exp), t) if t != "*" => t.parse::<u64>().ok() == Some(exp),
        _ => true,
    }
}

pub(crate) fn header_bytes(
    resp: &reqwest::Response,
    name: &reqwest::header::HeaderName,
) -> Option<Vec<u8>> {
    resp.headers().get(name).map(|v| v.as_bytes().to_vec())
}

pub(crate) async fn sync_parent_dir(path: &Path) {
    if let Some(parent) = path.parent()
        && let Ok(dir) = tokio::fs::File::open(parent).await
    {
        let _ = dir.sync_all().await;
    }
}

/// A failure establishing the connection.
pub(crate) fn connect_error(url: &Url, source: reqwest::Error) -> FetchError {
    FetchError::Connect {
        host: url.host_str().unwrap_or_default().to_owned(),
        source: std::io::Error::other(source),
    }
}

/// A failure after the connection was established (a mid-stream body error).
pub(crate) fn transport_error(url: &Url, source: reqwest::Error) -> FetchError {
    FetchError::Transport {
        url: url.clone(),
        source: std::io::Error::other(source),
    }
}

pub(crate) fn sidecar(dest: &Path, suffix: &str) -> PathBuf {
    let mut name: OsString = dest.as_os_str().to_owned();
    name.push(suffix);
    PathBuf::from(name)
}

pub(crate) fn emit(progress: &Option<mpsc::UnboundedSender<Progress>>, event: Progress) {
    if let Some(tx) = progress {
        let _ = tx.send(event);
    }
}

pub(crate) fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(out, "{b:02x}");
    }
    out
}

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

use crate::block::BlockPlan;
use crate::error::FetchError;
use crate::fetcher::Shared;
use crate::headers::apply_headers;
use crate::journal::{self, Identity, Journal};
use crate::progress::{Phase, Progress};
use crate::retry::{Class, classify_status, retry_after, sleep_or_cancel};
use crate::spec::DownloadSpec;
use crate::validator::{Validator, VerifiedFile};

/// What a download must prove before it publishes: a whole-file SHA256, a per-block SHA1 map, or
/// nothing. Derived from the [`Validator`] once via [`plan`] and threaded through both engines so the
/// two never disagree about what "verified" means.
pub(crate) struct Verify {
    pub(crate) sha: Option<[u8; 32]>,
    pub(crate) blocks: Option<Arc<BlockPlan>>,
}

/// How many bytes are streamed between `fsync` + journal-commit points, and the size of the in-memory
/// write buffer: the trade of throughput (one large write and one fsync per batch) against the bytes a
/// kill can cost (a resume re-fetches at most this much).
const BATCH: u64 = 1024 * 1024;
/// The buffer size for reading a file back to hash it (resume re-seed, existing-dest verification).
const READ_CHUNK: usize = 64 * 1024;

/// Run one single-connection download to completion.
///
/// The transfer draws the shared limiter's tokens on the bytes it reads off the socket and holds one
/// connection slot from the shared scheduler for its lifetime, so it counts against the global
/// connection cap the same as a segment does.
///
/// One attempt is one request plus the body it delivers. A connection cut off mid-body, or one that
/// goes silent past the inactivity timeout, commits what it received and re-requests the rest after a
/// backoff, so a drop at 90% costs a wait rather than the whole transfer.
pub(crate) async fn run(
    client: &reqwest::Client,
    spec: &DownloadSpec,
    verify: Verify,
    progress: Option<mpsc::UnboundedSender<Progress>>,
    cancel: CancellationToken,
    shared: &Shared,
) -> Result<VerifiedFile, FetchError> {
    let dest = spec.dest();
    let part = sidecar(dest, ".part");
    let apdl = sidecar(dest, ".apdl");

    if let Some(verified) =
        check_existing_dest(dest, &verify, spec.expected_len(), &progress).await?
    {
        return Ok(verified);
    }

    // Hold one global connection slot for the transfer, so a single-connection download counts against
    // the same cap as a segment. Released when this scope ends.
    let _conn = shared.scheduler.acquire_connection().await;

    let core_identity = base_identity(spec, spec.expected_len());

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

    // Block mode leaves the running hasher off (there is no whole-file digest on that path); its
    // per-block SHA1s are checked from disk after the stream completes.
    let mut hasher: Option<Sha256> = verify.sha.map(|_| Sha256::new());
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

    // The high-water mark every progress event is clamped to. A restart from zero re-downloads bytes
    // the consumer was already told about, and a bar that walks backwards would read as corruption;
    // the segmented engine clamps its own events the same way across a block repair.
    let mut high = start;
    let mut attempts = 0u32;
    let mut total;
    let written = loop {
        let resp = obtain_response(
            client,
            spec,
            &part,
            &mut part_file,
            &mut hasher,
            &mut journal,
            &mut start,
            &mut if_range,
            shared,
            &cancel,
            &mut attempts,
        )
        .await?;

        // The first progress event of an attempt is emitted only after the resume disposition is
        // settled, so it never names bytes a `200` has just discarded.
        high = high.max(start);
        emit(
            &progress,
            Progress {
                bytes_done: high,
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
        total = spec
            .expected_len()
            .or_else(|| resp.content_length().map(|cl| cl.saturating_add(start)));

        // A fresh start records the server's validators so a later resume can revalidate with
        // `If-Range`.
        if spec.resume() && journal.is_none() {
            journal_identity.etag = header_bytes(&resp, &ETAG);
            journal_identity.last_modified = header_bytes(&resp, &LAST_MODIFIED);
            journal = Journal::create(&apdl, &journal_identity)
                .await
                .map_err(|e| FetchError::io(&apdl, e))?;
        }
        // Pin this response's validator for the in-process retries too, even when no journal is being
        // kept: a source that changes between a dropped body and its retry then answers the
        // conditional range with a `200` and restarts cleanly, instead of stitching two files together.
        if if_range.is_none() {
            if_range = header_bytes(&resp, &ETAG).or_else(|| header_bytes(&resp, &LAST_MODIFIED));
        }

        match stream_body(
            resp,
            spec,
            &part,
            &mut part_file,
            &mut hasher,
            &mut journal,
            &apdl,
            Cursor {
                start,
                total,
                high: &mut high,
            },
            &progress,
            &cancel,
            shared,
        )
        .await?
        {
            Outcome::Complete(written) => break written,
            Outcome::Interrupted { written, source } => {
                attempts += 1;
                if !shared.retry.may_retry(attempts) {
                    return Err(source);
                }
                let delay = shared.retry.delay(attempts, None, &shared.jitter);
                if !sleep_or_cancel(delay, &cancel).await {
                    return Err(FetchError::Cancelled);
                }
                // Everything received is durable and hashed, so the next attempt asks only for the
                // rest. This is the resume path the journal already supported, run in-process.
                start = written;
            }
        }
    };

    if let Some(exp) = spec.expected_len()
        && written != exp
    {
        return Err(FetchError::LengthMismatch {
            expected: exp,
            got: written,
        });
    }

    if let (Some(h), Some(exp)) = (hasher.take(), verify.sha) {
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

    // Make the data durable through the handle we wrote before hashing it back or handing it off.
    part_file
        .sync_all()
        .await
        .map_err(|e| FetchError::io(&part, e))?;
    drop(part_file);

    // Block mode over a range-ignoring host: the whole file streamed on one connection, so verify each
    // block from disk now. Without ranges a bad block cannot be re-fetched in isolation, so a mismatch
    // fails the file and drops the journal (a retry restarts clean).
    if let Some(plan) = &verify.blocks {
        emit(
            &progress,
            Progress {
                bytes_done: written,
                total,
                phase: Phase::Verifying,
            },
        );
        if let Some(block) = verify_blocks_seq(&part, plan).await? {
            let _ = tokio::fs::remove_file(&apdl).await;
            return Err(FetchError::BlockVerifyFailed {
                block,
                offset: plan.block_range(block).start,
                attempts: 1,
            });
        }
    }

    publish(dest, &part, &apdl, written, total, &progress).await
}

/// Where one body attempt starts and what the transfer has already reported.
struct Cursor<'a> {
    /// The offset this response's body lands at.
    start: u64,
    /// The transfer's total length, once the server or the caller has named one.
    total: Option<u64>,
    /// The high-water mark progress events are clamped to, shared across attempts.
    high: &'a mut u64,
}

/// How one body attempt ended.
enum Outcome {
    /// The body ran to its end; `written` bytes are durable.
    Complete(u64),
    /// The connection was cut off or went silent mid-body. Everything received is durable and hashed,
    /// so the next attempt resumes from `written`; `source` is the failure to report if the attempt
    /// budget runs out first.
    Interrupted { written: u64, source: FetchError },
}

/// Stream one response body into the `.part`, hashing as it goes.
///
/// The body lands in a batch buffer: one write and one `fsync` + journal-commit per batch, so a
/// multi-GB transfer issues thousands of writes, not millions. Hashing reads the arriving chunk, so
/// it is unaffected by the buffering. A mid-body error or an inactivity timeout commits the batch
/// first, so the [`Outcome::Interrupted`] watermark it reports is durable rather than merely received.
///
/// # Errors
/// [`FetchError::Cancelled`] if `cancel` fires, or [`FetchError::Io`] if the `.part` or its journal
/// cannot be written. A transport failure is not an error here: it is an outcome the caller retries.
#[allow(clippy::too_many_arguments)]
async fn stream_body(
    resp: reqwest::Response,
    spec: &DownloadSpec,
    part: &Path,
    part_file: &mut tokio::fs::File,
    hasher: &mut Option<Sha256>,
    journal: &mut Option<Journal>,
    apdl: &Path,
    cursor: Cursor<'_>,
    progress: &Option<mpsc::UnboundedSender<Progress>>,
    cancel: &CancellationToken,
    shared: &Shared,
) -> Result<Outcome, FetchError> {
    let Cursor { start, total, high } = cursor;
    let mut stream = Box::pin(resp.bytes_stream());
    let mut written = start;
    let mut batch: Vec<u8> = Vec::with_capacity(BATCH as usize);
    let tick = |written: u64, high: &mut u64, phase: Phase| {
        *high = (*high).max(written);
        emit(
            progress,
            Progress {
                bytes_done: *high,
                total,
                phase,
            },
        );
    };
    tick(written, high, Phase::Downloading);
    loop {
        // Each arm that leaves the loop early names the failure it would report; the batch is
        // committed once, below, so no return path can leave received bytes unflushed.
        let cut_off = tokio::select! {
            biased;
            () = cancel.cancelled() => Some(FetchError::Cancelled),
            () = tokio::time::sleep(shared.stall_timeout) => Some(FetchError::Stalled {
                url: spec.url().clone(),
                at_bytes: written,
            }),
            item = stream.next() => match item {
                None => break,
                Some(Ok(chunk)) => {
                    let bytes: &[u8] = chunk.as_ref();
                    // Throttle on the bytes just read off the socket, before consuming more.
                    shared.limiter.acquire(bytes.len() as u64).await;
                    if let Some(h) = hasher.as_mut() {
                        h.update(bytes);
                    }
                    batch.extend_from_slice(bytes);
                    written += bytes.len() as u64;
                    if batch.len() as u64 >= BATCH {
                        write_batch(part_file, part, &mut batch).await?;
                        flush_and_commit(part_file, part, journal, apdl, written).await?;
                        tick(written, high, Phase::Downloading);
                    }
                    None
                }
                Some(Err(e)) => Some(transport_error(spec.url(), e)),
            },
        };
        if let Some(source) = cut_off {
            write_batch(part_file, part, &mut batch).await?;
            flush_and_commit(part_file, part, journal, apdl, written).await?;
            if matches!(source, FetchError::Cancelled) {
                return Err(FetchError::Cancelled);
            }
            // A server that resets after its last byte (a real RST rather than a clean close) has
            // still delivered everything asked for; retrying would ask for an empty range.
            if total.is_some_and(|total| written >= total) {
                return Ok(Outcome::Complete(written));
            }
            return Ok(Outcome::Interrupted { written, source });
        }
    }
    write_batch(part_file, part, &mut batch).await?;
    flush_and_commit(part_file, part, journal, apdl, written).await?;
    Ok(Outcome::Complete(written))
}

/// Send the request and settle the resume disposition, retrying what is worth retrying.
///
/// A valid `206` continues from `start`; a `200` (source changed, or the server ignored the range)
/// restarts cleanly from zero; a `416` or an unusable `206` re-requests once from zero. A connect
/// failure or a throttling status spends an attempt from `attempts` and backs off under the fetcher's
/// policy; every other status is fatal and is not retried.
///
/// # Errors
/// [`FetchError::Http`] for a fatal status or once the attempt budget is spent,
/// [`FetchError::Connect`] if the last attempt could not reach the host, [`FetchError::Cancelled`] if
/// `cancel` fired, or [`FetchError::Io`] if truncating the `.part` for a restart failed.
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
    shared: &Shared,
    cancel: &CancellationToken,
    attempts: &mut u32,
) -> Result<reqwest::Response, FetchError> {
    // The resume disposition gets exactly one restart from zero, and it is not charged to the retry
    // budget: it corrects *this* request rather than re-attempting a failed one.
    let mut restarted = false;
    loop {
        let mut req = apply_headers(client.get(spec.url().clone()), spec.header_policy());
        if *start > 0 {
            req = req.header(RANGE, format!("bytes={}-", *start));
            if let Some(value) = if_range.as_deref()
                && let Ok(header) = reqwest::header::HeaderValue::from_bytes(value)
            {
                req = req.header(IF_RANGE, header);
            }
        }
        let sent = tokio::select! {
            biased;
            () = cancel.cancelled() => return Err(FetchError::Cancelled),
            sent = req.send() => sent,
        };
        // Each arm yields the failure to report if this is the last attempt, plus the pause the
        // server asked for; a usable response returns straight out.
        let (failure, asked) = match sent {
            Ok(resp) => {
                let status = resp.status().as_u16();
                if status == 200 {
                    if *start > 0 {
                        reset_to_zero(part_file, part, hasher, journal, start, if_range).await?;
                    }
                    return Ok(resp);
                }
                if status == 206
                    && *start > 0
                    && content_range_ok(&resp, *start, spec.expected_len())
                {
                    return Ok(resp);
                }
                if (status == 206 || status == 416) && *start > 0 && !restarted {
                    restarted = true;
                    reset_to_zero(part_file, part, hasher, journal, start, if_range).await?;
                    continue;
                }
                let failure = FetchError::Http {
                    status,
                    url: spec.url().clone(),
                };
                if classify_status(status) == Class::Fatal {
                    return Err(failure);
                }
                (failure, retry_after(resp.headers()))
            }
            Err(e) => (connect_error(spec.url(), e), None),
        };
        *attempts += 1;
        if !shared.retry.may_retry(*attempts) {
            return Err(failure);
        }
        let delay = shared.retry.delay(*attempts, asked, &shared.jitter);
        if !sleep_or_cancel(delay, cancel).await {
            return Err(FetchError::Cancelled);
        }
    }
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

/// The request fingerprint shared by both engines: source, declared length, and validator digest.
/// `etag`/`last_modified` start empty; the segmented engine fills them from its probe. Keeping this in
/// one place means a new fingerprint field cannot be set in one engine and forgotten in the other.
pub(crate) fn base_identity(spec: &DownloadSpec, expected_len: Option<u64>) -> Identity {
    Identity {
        url: spec.url().as_str().to_owned(),
        expected_len,
        validator_digest: spec.validator().config_digest(),
        etag: None,
        last_modified: None,
    }
}

/// The shared publish tail: atomically rename the verified `.part` onto `dest`, `fsync` the parent for
/// rename durability, drop the journal, and emit `Complete`. The data itself must already be durable
/// (each engine `fsync`s the part its own way before calling this).
pub(crate) async fn publish(
    dest: &Path,
    part: &Path,
    apdl: &Path,
    bytes: u64,
    total: Option<u64>,
    progress: &Option<mpsc::UnboundedSender<Progress>>,
) -> Result<VerifiedFile, FetchError> {
    tokio::fs::rename(part, dest)
        .await
        .map_err(|e| FetchError::io(dest, e))?;
    sync_parent_dir(dest).await;
    let _ = tokio::fs::remove_file(apdl).await;
    emit(
        progress,
        Progress {
            bytes_done: bytes,
            total,
            phase: Phase::Complete,
        },
    );
    Ok(VerifiedFile::mint(dest))
}

/// Derive what a download must prove from its validator: a whole-file SHA256, a per-block SHA1 map, or
/// nothing. The spec builder has already checked a block validator's layout, so the length is present
/// and consistent here.
pub(crate) fn plan(validator: &Validator, expected_len: Option<u64>) -> Result<Verify, FetchError> {
    match validator {
        Validator::Sha256(digest) => Ok(Verify {
            sha: Some(*digest),
            blocks: None,
        }),
        // No fetch-side hash: length is checked during the transfer, and a downstream gate
        // authenticates the bytes. Reached only via `download_external`, which returns a plain path
        // rather than a `VerifiedFile`.
        Validator::None | Validator::External => Ok(Verify {
            sha: None,
            blocks: None,
        }),
        Validator::BlockSha1 { block_size, hashes } => {
            let len = expected_len.ok_or(FetchError::Unsupported {
                what: "block-hash validation requires a declared length",
            })?;
            Ok(Verify {
                sha: None,
                blocks: Some(Arc::new(BlockPlan::new(*block_size, hashes.clone(), len))),
            })
        }
    }
}

/// Hash each block of `path` from disk in order, returning the index of the first block whose SHA1 does
/// not match its plan, or `None` when every block verifies. Each block is hashed on a blocking worker.
pub(crate) async fn verify_blocks_seq(
    path: &Path,
    plan: &BlockPlan,
) -> Result<Option<u32>, FetchError> {
    for i in 0..plan.count() {
        let range = plan.block_range(i);
        let want = plan.expected(i);
        let owned = path.to_path_buf();
        let got = tokio::task::spawn_blocking(move || crate::block::hash_block(&owned, range))
            .await
            .map_err(|e| FetchError::io(path, std::io::Error::other(e)))?
            .map_err(|e| FetchError::io(path, e))?;
        if got != want {
            return Ok(Some(i));
        }
    }
    Ok(None)
}

/// Idempotent skip: return an existing destination only if it still satisfies the validator, so a
/// `VerifiedFile` is never minted over unverified or stale bytes. The re-hash reads local disk only,
/// never the network, so an unchanged file is not re-downloaded. `Ok(None)` means "not satisfied,
/// proceed with the download".
pub(crate) async fn check_existing_dest(
    dest: &Path,
    verify: &Verify,
    expected_len: Option<u64>,
    progress: &Option<mpsc::UnboundedSender<Progress>>,
) -> Result<Option<VerifiedFile>, FetchError> {
    if let Ok(meta) = tokio::fs::metadata(dest).await
        && meta.is_file()
        && dest_satisfies(dest, meta.len(), verify, expected_len).await?
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

/// Whether an existing destination already satisfies the request: the declared length (if any) and the
/// validator's proof (a whole-file digest, or every block's SHA1), recomputed from disk so the skip
/// never trusts a file's path as proof. A block download is skipped only when *every* block verifies.
async fn dest_satisfies(
    dest: &Path,
    len: u64,
    verify: &Verify,
    expected_len: Option<u64>,
) -> Result<bool, FetchError> {
    if expected_len.is_some_and(|n| n != len) {
        return Ok(false);
    }
    if let Some(plan) = &verify.blocks {
        return Ok(verify_blocks_seq(dest, plan).await?.is_none());
    }
    match verify.sha {
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
/// expected total. Parses through the one shared [`parse_content_range`](crate::multipart::parse_content_range).
fn content_range_ok(resp: &reqwest::Response, start: u64, expected_len: Option<u64>) -> bool {
    let Some(value) = resp
        .headers()
        .get(CONTENT_RANGE)
        .and_then(|v| v.to_str().ok())
    else {
        return false;
    };
    crate::multipart::parse_content_range(value).is_some_and(|(first, _last, total)| {
        first == start
            && match (expected_len, total) {
                (Some(exp), Some(t)) => t == exp,
                _ => true,
            }
    })
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

/// A failure establishing the connection, or the client's redirect policy declining to follow one.
/// Both arrive from the same `send`, and only the cause chain tells them apart.
pub(crate) fn connect_error(url: &Url, source: reqwest::Error) -> FetchError {
    if let Some(detail) = crate::redirect::refusal(&source) {
        return FetchError::RedirectRefused {
            url: url.clone(),
            detail,
        };
    }
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

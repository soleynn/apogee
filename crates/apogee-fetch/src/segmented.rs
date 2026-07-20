//! The segmented multi-connection transfer engine and the single/segmented dispatch.
//!
//! A file of known length whose host serves ranges is divided into segments and pulled by a pool of
//! connection workers writing at their own offsets into one preallocated `.part`. A work queue plus
//! that pool is the whole mechanism: a stalled or dropped connection re-queues the *remaining* bytes
//! of its segment (nothing already durable is lost), and the completed-interval journal lets the
//! whole transfer resume across a restart. When the length is unknown, the file is small, or the host
//! ignores ranges, the transfer falls back to the single-connection engine in [`crate::download`].

use std::collections::{HashMap, VecDeque};
use std::io::SeekFrom;
use std::ops::Range;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use futures_util::StreamExt;
use reqwest::header::{CONTENT_RANGE, RANGE};
use tokio::io::{AsyncSeekExt, AsyncWriteExt};
use tokio::sync::{Notify, mpsc};
use tokio_util::sync::CancellationToken;
use url::Url;

use crate::download;
use crate::error::FetchError;
use crate::fetcher::Shared;
use crate::intervals::IntervalSet;
use crate::journal::{self, Identity, Journal};
use crate::prealloc::preallocate;
use crate::probe::{Capability, classify};
use crate::progress::{Phase, Progress};
use crate::spec::DownloadSpec;
use crate::validator::VerifiedFile;

/// Bytes streamed between `fsync` + journal-commit points within a segment (the resume granularity).
const BATCH: u64 = 1024 * 1024;
/// The floor on segment size; a file no larger than this is not worth splitting.
const MIN_SEGMENT: u64 = 8 * 1024 * 1024;
/// How many times one stuck offset may be re-queued before the job fails as stalled.
const RETRY_BUDGET: u32 = 5;

/// Decide single vs segmented and run the transfer. The single-connection engine owns the
/// unknown-length, small-file, and range-ignored (demoted) cases; the segmented engine owns the rest.
pub(crate) async fn dispatch(
    client: &reqwest::Client,
    spec: &DownloadSpec,
    progress: Option<mpsc::UnboundedSender<Progress>>,
    cancel: CancellationToken,
    shared: &Shared,
) -> Result<VerifiedFile, FetchError> {
    let expected_sha = download::expected_sha(spec.validator())?;
    let single = |progress| {
        download::run(
            client,
            spec,
            progress,
            cancel.clone(),
            &shared.limiter,
            &shared.scheduler,
        )
    };

    let Some(len) = spec.expected_len() else {
        return single(progress).await;
    };
    let per_file = shared.max_connections_per_file;
    let seg_size = (len / per_file as u64).max(MIN_SEGMENT);
    if per_file <= 1 || len.div_ceil(seg_size) <= 1 {
        return single(progress).await;
    }

    // Skip a satisfied destination before spending a probe request.
    if let Some(verified) =
        download::check_existing_dest(spec.dest(), expected_sha, Some(len), &progress).await?
    {
        return Ok(verified);
    }

    let capability = match shared.capabilities.get(spec.url()) {
        Some(cap) => cap,
        None => {
            let cap = probe(client, spec, &cancel).await?;
            shared.capabilities.set(spec.url(), cap);
            cap
        }
    };
    match capability {
        Capability::SingleConnection => single(progress).await,
        Capability::Segmentable => {
            transfer(
                client,
                spec,
                len,
                seg_size,
                expected_sha,
                progress,
                cancel,
                shared,
            )
            .await
        }
    }
}

/// Probe range support with a one-byte ranged request, classifying the response and dropping its body
/// (so a range-ignoring `200` wastes only a socket buffer, never the whole file).
async fn probe(
    client: &reqwest::Client,
    spec: &DownloadSpec,
    cancel: &CancellationToken,
) -> Result<Capability, FetchError> {
    let request = client.get(spec.url().clone()).header(RANGE, "bytes=0-0");
    let resp = tokio::select! {
        biased;
        () = cancel.cancelled() => return Err(FetchError::Cancelled),
        sent = request.send() => sent.map_err(|e| download::connect_error(spec.url(), e))?,
    };
    match resp.status().as_u16() {
        200 | 206 => Ok(classify(&resp)),
        status => Err(FetchError::Http {
            status,
            url: spec.url().clone(),
        }),
    }
}

/// Shared state for one segmented transfer: the work queue, the durable-byte counter, the journal, and
/// the terminal outcome. One `Arc` is held by every worker plus the aggregator and cancel watcher.
struct TransferState {
    client: reqwest::Client,
    url: Url,
    part: PathBuf,
    apdl: PathBuf,
    len: u64,
    stall_timeout: Duration,
    limiter: crate::limiter::LimitHandle,
    scheduler: Arc<crate::scheduler::Scheduler>,
    queue: Mutex<VecDeque<Range<u64>>>,
    notify: Notify,
    progress_notify: Notify,
    durable: AtomicU64,
    attempts: Mutex<HashMap<u64, u32>>,
    journal: tokio::sync::Mutex<Option<Journal>>,
    done: CancellationToken,
    end: Mutex<Option<Result<(), FetchError>>>,
}

impl TransferState {
    /// Record the terminal outcome (first writer wins) and wake every task by firing `done`.
    fn finish(&self, result: Result<(), FetchError>) {
        let mut end = self.end.lock().unwrap_or_else(PoisonError::into_inner);
        if end.is_none() {
            *end = Some(result);
            self.done.cancel();
        }
    }

    /// Push a pending range and wake one waiting worker.
    fn push_range(&self, range: Range<u64>) {
        if range.start >= range.end {
            return;
        }
        self.queue
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push_back(range);
        self.notify.notify_one();
    }

    /// Take the next pending range, waiting for one to appear. `None` when the transfer is finished or
    /// cancelled (never inferred from an empty queue, so a mid-re-queue gap cannot end the job early).
    async fn pop_or_wait(&self, cancel: &CancellationToken) -> Option<Range<u64>> {
        loop {
            if let Some(range) = self
                .queue
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .pop_front()
            {
                return Some(range);
            }
            // Register interest before the final re-check so a push between the two cannot be lost.
            let notified = self.notify.notified();
            if let Some(range) = self
                .queue
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .pop_front()
            {
                return Some(range);
            }
            tokio::select! {
                biased;
                () = self.done.cancelled() => return None,
                () = cancel.cancelled() => return None,
                () = notified => {}
            }
        }
    }

    /// Increment and return the attempt count for a stuck offset.
    fn bump_attempt(&self, start: u64) -> u32 {
        let mut attempts = self.attempts.lock().unwrap_or_else(PoisonError::into_inner);
        let counter = attempts.entry(start).or_insert(0);
        *counter += 1;
        *counter
    }

    /// Append a completed interval to the journal, if one is being kept.
    async fn journal_commit(&self, start: u64, end: u64) -> Result<(), FetchError> {
        let mut journal = self.journal.lock().await;
        if let Some(journal) = journal.as_mut() {
            journal
                .commit_interval(start, end)
                .await
                .map_err(|e| FetchError::io(&self.apdl, e))?;
        }
        Ok(())
    }
}

/// Set up and run a segmented transfer, then verify and publish.
#[allow(clippy::too_many_arguments)]
async fn transfer(
    client: &reqwest::Client,
    spec: &DownloadSpec,
    len: u64,
    seg_size: u64,
    expected_sha: Option<[u8; 32]>,
    progress: Option<mpsc::UnboundedSender<Progress>>,
    cancel: CancellationToken,
    shared: &Shared,
) -> Result<VerifiedFile, FetchError> {
    let dest = spec.dest();
    let part = download::sidecar(dest, ".part");
    let apdl = download::sidecar(dest, ".apdl");

    let identity = Identity {
        url: spec.url().as_str().to_owned(),
        expected_len: Some(len),
        validator_digest: spec.validator().config_digest(),
        etag: None,
        last_modified: None,
    };

    // Resume: trust the journaled intervals only when the identity matches and the `.part` is fully
    // preallocated (so every covered byte is within the file).
    let mut covered = IntervalSet::new();
    if spec.resume()
        && let Some(loaded) = journal::load(&apdl)
            .await
            .map_err(|e| FetchError::io(&apdl, e))?
        && loaded.identity.matches(&identity)
        && let Ok(meta) = tokio::fs::metadata(&part).await
        && meta.is_file()
        && meta.len() >= len
    {
        covered = loaded.intervals;
    }

    preallocate(&part, len).await?;

    let gaps = covered.complement(len);
    let already = covered.covered_len();
    download::emit(
        &progress,
        Progress {
            bytes_done: already,
            total: Some(len),
            phase: Phase::Connecting,
        },
    );

    if !gaps.is_empty() {
        let journal = if already > 0 {
            Some(
                Journal::open_append(&apdl)
                    .await
                    .map_err(|e| FetchError::io(&apdl, e))?,
            )
        } else {
            Journal::create(&apdl, &identity)
                .await
                .map_err(|e| FetchError::io(&apdl, e))?
        };

        let mut queue = VecDeque::new();
        for gap in &gaps {
            let mut start = gap.start;
            while start < gap.end {
                let end = (start + seg_size).min(gap.end);
                queue.push_back(start..end);
                start = end;
            }
        }
        let worker_count = shared.max_connections_per_file.min(queue.len());

        let state = Arc::new(TransferState {
            client: client.clone(),
            url: spec.url().clone(),
            part: part.clone(),
            apdl: apdl.clone(),
            len,
            stall_timeout: shared.stall_timeout,
            limiter: shared.limiter.clone(),
            scheduler: shared.scheduler.clone(),
            queue: Mutex::new(queue),
            notify: Notify::new(),
            progress_notify: Notify::new(),
            durable: AtomicU64::new(already),
            attempts: Mutex::new(HashMap::new()),
            journal: tokio::sync::Mutex::new(journal),
            done: CancellationToken::new(),
            end: Mutex::new(None),
        });

        let aggregate = tokio::spawn(aggregator(state.clone(), progress.clone(), len));
        let watch = tokio::spawn({
            let (state, cancel) = (state.clone(), cancel.clone());
            async move {
                tokio::select! {
                    () = cancel.cancelled() => state.finish(Err(FetchError::Cancelled)),
                    () = state.done.cancelled() => {}
                }
            }
        });
        let workers: Vec<_> = (0..worker_count)
            .map(|_| tokio::spawn(worker(state.clone(), cancel.clone())))
            .collect();
        for handle in workers {
            let _ = handle.await;
        }
        // All workers have exited; make sure the aggregator and watcher wind down too.
        state.done.cancel();
        let _ = aggregate.await;
        let _ = watch.await;

        if let Some(Err(err)) = state
            .end
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take()
        {
            return Err(err);
        }
    }

    verify_and_publish(dest, &part, &apdl, len, expected_sha, &progress).await
}

/// Emit a monotonic download snapshot on every progress tick, so concurrent workers cannot interleave
/// a smaller `bytes_done` after a larger one.
async fn aggregator(
    state: Arc<TransferState>,
    progress: Option<mpsc::UnboundedSender<Progress>>,
    len: u64,
) {
    loop {
        tokio::select! {
            biased;
            () = state.done.cancelled() => return,
            () = state.progress_notify.notified() => {
                download::emit(
                    &progress,
                    Progress {
                        bytes_done: state.durable.load(Ordering::SeqCst),
                        total: Some(len),
                        phase: Phase::Downloading,
                    },
                );
            }
        }
    }
}

/// The outcome of one segment attempt.
enum SegmentResult {
    /// The segment's range is fully durable.
    Done,
    /// The connection dropped or stalled; the remaining bytes must be re-fetched.
    Requeue(Range<u64>),
    /// The server returned a `200` where a `206` was expected (the source changed under us).
    SourceChanged,
    /// The transfer is ending (finished or cancelled); stop working.
    Stop,
    /// An unrecoverable failure for the whole job.
    Fatal(FetchError),
}

/// A worker: pull ranges and stream them until the transfer finishes.
async fn worker(state: Arc<TransferState>, cancel: CancellationToken) {
    while let Some(range) = state.pop_or_wait(&cancel).await {
        match stream_segment(&state, range.clone(), &cancel).await {
            SegmentResult::Done => {
                if state.durable.load(Ordering::SeqCst) >= state.len {
                    state.finish(Ok(()));
                }
            }
            SegmentResult::Requeue(remaining) => {
                if state.bump_attempt(remaining.start) > RETRY_BUDGET {
                    state.finish(Err(FetchError::Stalled {
                        url: state.url.clone(),
                        at_bytes: state.durable.load(Ordering::SeqCst),
                    }));
                } else {
                    state.push_range(remaining);
                }
            }
            SegmentResult::SourceChanged => {
                // A changed source restarts clean: drop the stale journal and surface a transient
                // error so a retry re-downloads from scratch.
                let _ = tokio::fs::remove_file(&state.apdl).await;
                state.finish(Err(FetchError::Transport {
                    url: state.url.clone(),
                    source: std::io::Error::other("range ignored mid-transfer; source changed"),
                }));
            }
            SegmentResult::Stop => return,
            SegmentResult::Fatal(err) => state.finish(Err(err)),
        }
        if state.done.is_cancelled() {
            return;
        }
    }
}

/// Stream one segment's range into the preallocated `.part` at its offset, journaling each durable
/// batch. Holds one global connection slot for the segment's lifetime.
async fn stream_segment(
    state: &TransferState,
    range: Range<u64>,
    cancel: &CancellationToken,
) -> SegmentResult {
    let _conn = state.scheduler.acquire_connection().await;
    let mut file = match open_segment_file(&state.part, range.start).await {
        Ok(file) => file,
        Err(err) => return SegmentResult::Fatal(err),
    };

    let request = state
        .client
        .get(state.url.clone())
        .header(RANGE, format!("bytes={}-{}", range.start, range.end - 1));
    let resp = tokio::select! {
        biased;
        () = cancel.cancelled() => return SegmentResult::Stop,
        () = state.done.cancelled() => return SegmentResult::Stop,
        sent = request.send() => match sent {
            Ok(resp) => resp,
            // A connect error is transient: re-queue the whole range.
            Err(_) => return SegmentResult::Requeue(range),
        },
    };
    match resp.status().as_u16() {
        200 => return SegmentResult::SourceChanged,
        206 => {}
        status => {
            return SegmentResult::Fatal(FetchError::Http {
                status,
                url: state.url.clone(),
            });
        }
    }
    if content_range_start(&resp) != Some(range.start) {
        return SegmentResult::Fatal(FetchError::Http {
            status: 206,
            url: state.url.clone(),
        });
    }

    let mut stream = Box::pin(resp.bytes_stream());
    let mut batch: Vec<u8> = Vec::with_capacity(BATCH as usize);
    let mut committed = range.start;
    loop {
        let item = tokio::select! {
            biased;
            () = cancel.cancelled() => {
                let _ = commit_batch(&mut file, &mut batch, &mut committed, state).await;
                return SegmentResult::Stop;
            }
            () = state.done.cancelled() => {
                let _ = commit_batch(&mut file, &mut batch, &mut committed, state).await;
                return SegmentResult::Stop;
            }
            () = tokio::time::sleep(state.stall_timeout) => {
                // Inactivity past the stall timeout: flush what is durable and re-queue the rest.
                if let Err(err) = commit_batch(&mut file, &mut batch, &mut committed, state).await {
                    return SegmentResult::Fatal(err);
                }
                return SegmentResult::Requeue(committed..range.end);
            }
            item = stream.next() => item,
        };
        let Some(chunk) = item else { break };
        let chunk = match chunk {
            Ok(chunk) => chunk,
            Err(_) => {
                let _ = commit_batch(&mut file, &mut batch, &mut committed, state).await;
                return SegmentResult::Requeue(committed..range.end);
            }
        };
        let bytes: &[u8] = chunk.as_ref();
        state.limiter.acquire(bytes.len() as u64).await;
        batch.extend_from_slice(bytes);
        if batch.len() as u64 >= BATCH
            && let Err(err) = commit_batch(&mut file, &mut batch, &mut committed, state).await
        {
            return SegmentResult::Fatal(err);
        }
    }
    if let Err(err) = commit_batch(&mut file, &mut batch, &mut committed, state).await {
        return SegmentResult::Fatal(err);
    }
    // A short 206 (fewer bytes than the range) leaves a gap; re-queue the remainder.
    if committed < range.end {
        return SegmentResult::Requeue(committed..range.end);
    }
    SegmentResult::Done
}

/// Flush the buffered batch: write it, `fsync` the data, journal the now-durable interval, advance the
/// durable counter, and tick progress. A no-op on an empty batch.
async fn commit_batch(
    file: &mut tokio::fs::File,
    batch: &mut Vec<u8>,
    committed: &mut u64,
    state: &TransferState,
) -> Result<(), FetchError> {
    if batch.is_empty() {
        return Ok(());
    }
    file.write_all(batch)
        .await
        .map_err(|e| FetchError::io(&state.part, e))?;
    file.sync_data()
        .await
        .map_err(|e| FetchError::io(&state.part, e))?;
    let bytes = batch.len() as u64;
    let end = *committed + bytes;
    state.journal_commit(*committed, end).await?;
    state.durable.fetch_add(bytes, Ordering::SeqCst);
    state.progress_notify.notify_one();
    *committed = end;
    batch.clear();
    Ok(())
}

/// Open the preallocated `.part` for writing and position at `at` (segments write sequentially from
/// their start, so no further seeks are needed).
async fn open_segment_file(part: &Path, at: u64) -> Result<tokio::fs::File, FetchError> {
    let mut file = tokio::fs::OpenOptions::new()
        .write(true)
        .open(part)
        .await
        .map_err(|e| FetchError::io(part, e))?;
    file.seek(SeekFrom::Start(at))
        .await
        .map_err(|e| FetchError::io(part, e))?;
    Ok(file)
}

/// The first byte of a `Content-Range: bytes first-last/total` header.
fn content_range_start(resp: &reqwest::Response) -> Option<u64> {
    let value = resp.headers().get(CONTENT_RANGE)?.to_str().ok()?;
    let (range, _total) = value.strip_prefix("bytes ")?.split_once('/')?;
    let (first, _last) = range.split_once('-')?;
    first.parse::<u64>().ok()
}

/// Re-hash the completed `.part` (for a whole-file validator), then publish it: durable, atomic
/// rename, parent-dir `fsync`, journal removed.
async fn verify_and_publish(
    dest: &Path,
    part: &Path,
    apdl: &Path,
    len: u64,
    expected_sha: Option<[u8; 32]>,
    progress: &Option<mpsc::UnboundedSender<Progress>>,
) -> Result<VerifiedFile, FetchError> {
    if let Some(expected) = expected_sha {
        download::emit(
            progress,
            Progress {
                bytes_done: len,
                total: Some(len),
                phase: Phase::Verifying,
            },
        );
        let got = download::hash_file(part).await?;
        if got != expected {
            // Drop the journal so a retry restarts clean rather than re-assembling the same bad bytes.
            let _ = tokio::fs::remove_file(apdl).await;
            return Err(FetchError::FileVerifyFailed {
                expected: download::hex(&expected),
                got: download::hex(&got),
            });
        }
    }
    if let Ok(file) = tokio::fs::File::open(part).await {
        let _ = file.sync_all().await;
    }
    tokio::fs::rename(part, dest)
        .await
        .map_err(|e| FetchError::io(dest, e))?;
    download::sync_parent_dir(dest).await;
    let _ = tokio::fs::remove_file(apdl).await;
    download::emit(
        progress,
        Progress {
            bytes_done: len,
            total: Some(len),
            phase: Phase::Complete,
        },
    );
    Ok(VerifiedFile::mint(dest))
}

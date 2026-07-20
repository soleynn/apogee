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
use std::sync::{Arc, Mutex};
use std::time::Duration;

use futures_util::StreamExt;
use reqwest::header::{CONTENT_RANGE, ETAG, IF_RANGE, LAST_MODIFIED, RANGE};
use tokio::io::{AsyncSeekExt, AsyncWriteExt};
use tokio::sync::{Notify, mpsc};
use tokio_util::sync::CancellationToken;
use url::Url;

use crate::block::{self, BlockVerify};
use crate::download::{self, Verify};
use crate::error::FetchError;
use crate::fetcher::Shared;
use crate::headers::{HeaderPolicy, apply_headers};
use crate::intervals::IntervalSet;
use crate::journal::{self, Identity, Journal};
use crate::prealloc::preallocate;
use crate::probe::{Capability, classify};
use crate::progress::{Phase, Progress};
use crate::spec::DownloadSpec;
use crate::util::lock;
use crate::validator::VerifiedFile;

/// Bytes streamed between `fsync` + journal-commit points within a segment (the resume granularity).
const BATCH: u64 = 1024 * 1024;
/// The floor on segment size; a file no larger than this is not worth splitting.
const MIN_SEGMENT: u64 = 8 * 1024 * 1024;
/// How many times one stuck offset may be re-queued before the job fails as stalled.
const RETRY_BUDGET: u32 = 5;
/// How many times one block may be re-fetched after a failed hash before the file fails. A separate
/// budget from [`RETRY_BUDGET`]: a corrupt block and a stalled connection are different failure modes.
const BLOCK_RETRY_BUDGET: u32 = 5;

/// One unit of transfer work: a byte range and which source to fetch it from (`0` is the primary,
/// higher indices are mirrors). Re-queues carry their source; a dirty block's re-fetch may rotate it.
struct Task {
    range: Range<u64>,
    source: usize,
}

/// Decide single vs segmented and run the transfer. The single-connection engine owns the
/// unknown-length, small-file, and range-ignored (demoted) cases; the segmented engine owns the rest.
pub(crate) async fn dispatch(
    client: &reqwest::Client,
    spec: &DownloadSpec,
    progress: Option<mpsc::UnboundedSender<Progress>>,
    cancel: CancellationToken,
    shared: &Shared,
) -> Result<VerifiedFile, FetchError> {
    let verify = download::plan(spec.validator(), spec.expected_len())?;

    let Some(len) = spec.expected_len() else {
        return download::run(
            client,
            spec,
            verify,
            progress,
            cancel,
            &shared.limiter,
            &shared.scheduler,
        )
        .await;
    };
    let per_file = shared.max_connections_per_file;
    let seg_size = (len / per_file as u64).max(MIN_SEGMENT);
    let block_mode = verify.blocks.is_some();
    // A small whole-file transfer stays single-connection. Block mode keeps the ranged engine even for
    // one segment: its dirty-block re-fetch rides that engine's work queue, so it demotes only when the
    // host ignores ranges (handled below).
    if (per_file <= 1 || len.div_ceil(seg_size) <= 1) && !block_mode {
        return download::run(
            client,
            spec,
            verify,
            progress,
            cancel,
            &shared.limiter,
            &shared.scheduler,
        )
        .await;
    }

    // Skip a satisfied destination before spending a probe request.
    if let Some(verified) =
        download::check_existing_dest(spec.dest(), &verify, Some(len), &progress).await?
    {
        return Ok(verified);
    }

    // A cache hit knows only the capability, not the URL's validators (which are per-URL, not per-host),
    // so a fresh cache-hit download records no validators; a resume then relies on the whole-file hash
    // to catch a changed source.
    let (capability, etag, last_modified) = match shared.capabilities.get(spec.url()) {
        Some(cap) => (cap, None, None),
        None => {
            let probe = probe(client, spec, &cancel).await?;
            shared.capabilities.set(spec.url(), probe.capability);
            (probe.capability, probe.etag, probe.last_modified)
        }
    };
    match capability {
        // A range-ignoring host cannot serve a block re-fetch; the single-connection engine verifies
        // block mode from disk after streaming the whole file (no targeted repair).
        Capability::SingleConnection => {
            download::run(
                client,
                spec,
                verify,
                progress,
                cancel,
                &shared.limiter,
                &shared.scheduler,
            )
            .await
        }
        Capability::Segmentable => {
            transfer(
                client,
                spec,
                len,
                seg_size,
                verify,
                etag,
                last_modified,
                progress,
                cancel,
                shared,
            )
            .await
        }
    }
}

/// A probe's verdict plus the server validators to record for a later resume's `If-Range`.
struct Probe {
    capability: Capability,
    etag: Option<Vec<u8>>,
    last_modified: Option<Vec<u8>>,
}

/// Probe range support with a one-byte ranged request, classifying the response and capturing its
/// validators, then dropping its body (so a range-ignoring `200` wastes only a socket buffer, never
/// the whole file).
async fn probe(
    client: &reqwest::Client,
    spec: &DownloadSpec,
    cancel: &CancellationToken,
) -> Result<Probe, FetchError> {
    let request = apply_headers(client.get(spec.url().clone()), spec.header_policy())
        .header(RANGE, "bytes=0-0");
    let resp = tokio::select! {
        biased;
        () = cancel.cancelled() => return Err(FetchError::Cancelled),
        sent = request.send() => sent.map_err(|e| download::connect_error(spec.url(), e))?,
    };
    let capability = match resp.status().as_u16() {
        200 | 206 => classify(&resp),
        status => {
            return Err(FetchError::Http {
                status,
                url: spec.url().clone(),
            });
        }
    };
    Ok(Probe {
        capability,
        etag: download::header_bytes(&resp, &ETAG),
        last_modified: download::header_bytes(&resp, &LAST_MODIFIED),
    })
}

/// Shared state for one segmented transfer: the work queue, the durable-byte counter, the journal, and
/// the terminal outcome. One `Arc` is held by every worker plus the progress aggregator.
struct TransferState {
    client: reqwest::Client,
    /// The primary URL, followed by any mirrors: a [`Task`]'s `source` indexes this list. Index `0` is
    /// the primary and the resume identity key, so rotating to a mirror never invalidates the journal.
    sources: Vec<Url>,
    part: PathBuf,
    apdl: PathBuf,
    len: u64,
    stall_timeout: Duration,
    header_policy: Option<HeaderPolicy>,
    /// The `If-Range` value (ETag or Last-Modified) sent on resume, or `None` on a fresh transfer.
    if_range: Option<Vec<u8>>,
    limiter: crate::limiter::LimitHandle,
    scheduler: Arc<crate::scheduler::Scheduler>,
    queue: Mutex<VecDeque<Task>>,
    notify: Notify,
    progress_notify: Notify,
    durable: AtomicU64,
    /// The live durable byte set (not just its length), so the block verifier can tell which whole
    /// blocks are on disk. Seeded from the resume set; grown in `commit_batch`, shrunk when a dirty
    /// block is cleared. Its length always equals `durable`.
    covered: Mutex<IntervalSet>,
    attempts: Mutex<HashMap<u64, u32>>,
    journal: tokio::sync::Mutex<Option<Journal>>,
    /// Present only in block mode: the per-block verification state and its wake channel.
    verify: Option<Arc<BlockVerify>>,
    done: CancellationToken,
    end: Mutex<Option<Result<(), FetchError>>>,
}

impl TransferState {
    /// Record the terminal outcome (first writer wins) and wake every task by firing `done`.
    fn finish(&self, result: Result<(), FetchError>) {
        let mut end = lock(&self.end);
        if end.is_none() {
            *end = Some(result);
            self.done.cancel();
        }
    }

    /// The primary source (index `0`): the resume identity key and the target for top-level errors.
    fn primary(&self) -> &Url {
        &self.sources[0]
    }

    /// Push a pending task and wake one waiting worker. An empty range is dropped.
    fn push_task(&self, task: Task) {
        if task.range.start >= task.range.end {
            return;
        }
        lock(&self.queue).push_back(task);
        self.notify.notify_one();
    }

    /// Take the next pending task, waiting for one to appear. `None` when the transfer is finished or
    /// cancelled (never inferred from an empty queue, so a mid-re-queue gap cannot end the job early).
    async fn pop_or_wait(&self, cancel: &CancellationToken) -> Option<Task> {
        loop {
            if let Some(task) = lock(&self.queue).pop_front() {
                return Some(task);
            }
            // Register interest before the final re-check so a push between the two cannot be lost.
            let notified = self.notify.notified();
            if let Some(task) = lock(&self.queue).pop_front() {
                return Some(task);
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
        let mut attempts = lock(&self.attempts);
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
    verify: Verify,
    etag: Option<Vec<u8>>,
    last_modified: Option<Vec<u8>>,
    progress: Option<mpsc::UnboundedSender<Progress>>,
    cancel: CancellationToken,
    shared: &Shared,
) -> Result<VerifiedFile, FetchError> {
    let dest = spec.dest();
    let part = download::sidecar(dest, ".part");
    let apdl = download::sidecar(dest, ".apdl");
    let block_verify = verify.blocks.clone().map(|plan| Arc::new(BlockVerify::new(plan)));

    // A fresh transfer records the probe's validators so a later resume can revalidate with `If-Range`.
    let identity = Identity {
        etag,
        last_modified,
        ..download::base_identity(spec, Some(len))
    };

    // Resume: trust the journaled intervals only when the identity matches and the `.part` is fully
    // preallocated (so every covered byte is within the file). The recorded validator becomes this
    // run's `If-Range` so a source that changed since is caught.
    let mut covered = IntervalSet::new();
    let mut if_range = None;
    if spec.resume()
        && let Some(loaded) = journal::load(&apdl)
            .await
            .map_err(|e| FetchError::io(&apdl, e))?
        && loaded.identity.matches(&identity)
        && let Ok(meta) = tokio::fs::metadata(&part).await
        && meta.is_file()
        && meta.len() >= len
    {
        if_range = loaded
            .identity
            .etag
            .clone()
            .or_else(|| loaded.identity.last_modified.clone());
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

    // Block mode always runs the engine, even with no gaps: a resume-complete file still has to have
    // every durable block re-hashed from disk before it can be trusted (the block analogue of the
    // single-connection path re-seeding its whole-file hash on resume).
    if !gaps.is_empty() || block_verify.is_some() {
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
                queue.push_back(Task {
                    range: start..end,
                    source: 0,
                });
                start = end;
            }
        }
        // Block mode needs at least one worker parked and ready even with an empty queue, so a
        // dirty-block re-fetch has somewhere to run.
        let worker_count = if block_verify.is_some() {
            shared.max_connections_per_file.min(queue.len().max(1))
        } else {
            shared.max_connections_per_file.min(queue.len())
        };

        let state = Arc::new(TransferState {
            client: client.clone(),
            sources: spec.sources(),
            part: part.clone(),
            apdl: apdl.clone(),
            len,
            stall_timeout: shared.stall_timeout,
            header_policy: spec.header_policy().cloned(),
            if_range,
            limiter: shared.limiter.clone(),
            scheduler: shared.scheduler.clone(),
            queue: Mutex::new(queue),
            notify: Notify::new(),
            progress_notify: Notify::new(),
            durable: AtomicU64::new(already),
            covered: Mutex::new(covered),
            attempts: Mutex::new(HashMap::new()),
            journal: tokio::sync::Mutex::new(journal),
            verify: block_verify,
            done: CancellationToken::new(),
            end: Mutex::new(None),
        });

        let aggregate = tokio::spawn(aggregator(state.clone(), progress.clone(), len));
        let verifier = state
            .verify
            .is_some()
            .then(|| tokio::spawn(block_verifier(state.clone(), cancel.clone())));
        let workers: Vec<_> = (0..worker_count)
            .map(|_| tokio::spawn(worker(state.clone(), cancel.clone())))
            .collect();
        for handle in workers {
            let _ = handle.await;
        }
        // All workers have exited; wind the aggregator and verifier down. Workers record the outcome in
        // `end`: `Some(Ok)` on completion, `Some(Err)` on failure. A pure external cancel exits every
        // worker without a finish, so `end` stays `None` - read authoritatively here rather than racing
        // a watcher task against the `done` token.
        state.done.cancel();
        let _ = aggregate.await;
        if let Some(verifier) = verifier {
            let _ = verifier.await;
        }

        match lock(&state.end).take() {
            Some(Ok(())) => {} // completed: fall through to verify + publish
            Some(Err(err)) => return Err(err),
            None => return Err(FetchError::Cancelled), // cancelled before completion; part + journal kept
        }
    }

    verify_and_publish(dest, &part, &apdl, len, verify.sha, &progress).await
}

/// Emit a monotonic download snapshot on every progress tick, so concurrent workers cannot interleave
/// a smaller `bytes_done` after a larger one. A dirty block clears its bytes and drops `durable`, so
/// the snapshot is clamped to a high-water mark: progress never regresses across a block repair.
async fn aggregator(
    state: Arc<TransferState>,
    progress: Option<mpsc::UnboundedSender<Progress>>,
    len: u64,
) {
    let mut high = state.durable.load(Ordering::SeqCst);
    loop {
        tokio::select! {
            biased;
            () = state.done.cancelled() => return,
            () = state.progress_notify.notified() => {
                high = high.max(state.durable.load(Ordering::SeqCst));
                download::emit(
                    &progress,
                    Progress {
                        bytes_done: high,
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

/// A worker: pull tasks and stream them until the transfer finishes.
async fn worker(state: Arc<TransferState>, cancel: CancellationToken) {
    while let Some(task) = state.pop_or_wait(&cancel).await {
        let source = task.source;
        match stream_segment(&state, task, &cancel).await {
            SegmentResult::Done => {}
            SegmentResult::Requeue(remaining) => {
                if state.bump_attempt(remaining.start) > RETRY_BUDGET {
                    state.finish(Err(FetchError::Stalled {
                        url: state.primary().clone(),
                        at_bytes: state.durable.load(Ordering::SeqCst),
                    }));
                } else {
                    // A transport stall keeps the same source; block-level mirror rotation is driven by
                    // the verifier, not by a dropped connection.
                    state.push_task(Task {
                        range: remaining,
                        source,
                    });
                }
            }
            SegmentResult::SourceChanged => {
                // A changed source restarts clean: drop the stale journal and surface the typed
                // changed-source error so a retry re-downloads from scratch.
                let _ = tokio::fs::remove_file(&state.apdl).await;
                state.finish(Err(FetchError::ServerFileChanged {
                    validator: "range ignored mid-transfer".to_owned(),
                }));
            }
            SegmentResult::Stop => return,
            SegmentResult::Fatal(err) => state.finish(Err(err)),
        }
        // Whole-file mode finishes when every byte is durable. Block mode finishes only when the
        // verifier confirms every block, so a file whose bytes are all on disk but not yet verified must
        // not end here. Completion is checked on every path, not just `Done`: a stall or drop can flush
        // the file's final bytes and return an empty `Requeue`, which `push_task` drops, so the `Done`
        // arm would never see it. `finish` is first-writer-wins, so a redundant call is harmless.
        if state.verify.is_none() && state.durable.load(Ordering::SeqCst) >= state.len {
            state.finish(Ok(()));
        }
        if state.done.is_cancelled() {
            return;
        }
    }
}

/// The block verifier: as bytes become durable, hash each newly-complete block off the transfer path
/// and either confirm it or re-queue it for a repair. Finishes the transfer once every block verifies.
async fn block_verifier(state: Arc<TransferState>, cancel: CancellationToken) {
    let Some(verify) = state.verify.clone() else {
        return;
    };
    loop {
        // Snapshot coverage once, then dispatch every block it newly completes. Process-first, so a
        // resume with everything already durable still hashes every loaded block on the first pass.
        let covered = lock(&state.covered).clone();
        for i in verify.take_ready(&covered) {
            spawn_hash(state.clone(), verify.clone(), i, cancel.clone());
        }
        tokio::select! {
            biased;
            () = state.done.cancelled() => return,
            () = cancel.cancelled() => return,
            () = verify.notify.notified() => {}
        }
    }
}

/// Hash one claimed block on a blocking worker, then report the verdict. Kept off the transfer path:
/// the block is fully durable and out of the work queue, so this read never races a worker's write.
fn spawn_hash(state: Arc<TransferState>, verify: Arc<BlockVerify>, i: u32, cancel: CancellationToken) {
    let part = state.part.clone();
    let range = verify.block_range(i);
    let want = verify.expected(i);
    tokio::spawn(async move {
        let hashed = tokio::task::spawn_blocking(move || block::hash_block(&part, range)).await;
        match hashed {
            Ok(Ok(got)) if got == want => on_verified(&state, &verify, i, &cancel),
            Ok(Ok(_)) => on_dirty(&state, &verify, i, &cancel).await,
            Ok(Err(e)) => state.finish(Err(FetchError::io(&state.part, e))),
            Err(_) => state.finish(Err(FetchError::io(
                &state.part,
                std::io::Error::other("block hash worker panicked"),
            ))),
        }
    });
}

/// A block passed: mark it verified and, if it was the last, finish the transfer. A late result landing
/// after an external cancel must not publish a cancelled job, so the completion is gated on `!cancel`.
fn on_verified(state: &TransferState, verify: &BlockVerify, i: u32, cancel: &CancellationToken) {
    if state.done.is_cancelled() {
        return;
    }
    let verified = verify.mark_verified(i);
    if verified == verify.count() && !cancel.is_cancelled() {
        state.finish(Ok(()));
    }
}

/// A block failed its hash: spend one retry and either re-fetch just that block (clearing its bytes so
/// `durable` and `covered` stay consistent) or, once the budget is gone, fail the whole file.
async fn on_dirty(state: &TransferState, verify: &BlockVerify, i: u32, cancel: &CancellationToken) {
    if state.done.is_cancelled() || cancel.is_cancelled() {
        return;
    }
    let range = verify.block_range(i);
    let attempts = verify.bump_attempt(i);
    if attempts > BLOCK_RETRY_BUDGET {
        // Drop the journal so a retry restarts clean rather than trusting the bad interval.
        let _ = tokio::fs::remove_file(&state.apdl).await;
        state.finish(Err(FetchError::BlockVerifyFailed {
            block: i,
            offset: range.start,
            attempts,
        }));
        return;
    }
    // Clear the block before resetting it, so a verifier wake cannot re-dispatch it on stale coverage.
    lock(&state.covered).remove(range.start, range.end);
    state.durable.fetch_sub(range.end - range.start, Ordering::SeqCst);
    verify.reset_pending(i);
    let source = mirror_source(state, attempts);
    state.push_task(Task { range, source });
}

/// Which source to re-fetch a dirty block from, given how many times it has failed: the primary first,
/// then each mirror in turn. With no mirrors this is always the primary.
fn mirror_source(state: &TransferState, attempts: u32) -> usize {
    (attempts as usize).saturating_sub(1) % state.sources.len()
}

/// Stream one segment's range into the preallocated `.part` at its offset, journaling each durable
/// batch. Holds one global connection slot for the segment's lifetime.
async fn stream_segment(
    state: &TransferState,
    task: Task,
    cancel: &CancellationToken,
) -> SegmentResult {
    let range = task.range;
    let url = &state.sources[task.source];
    let _conn = state.scheduler.acquire_connection().await;
    let mut file = match open_segment_file(&state.part, range.start).await {
        Ok(file) => file,
        Err(err) => return SegmentResult::Fatal(err),
    };

    let mut request = apply_headers(state.client.get(url.clone()), state.header_policy.as_ref())
        .header(RANGE, format!("bytes={}-{}", range.start, range.end - 1));
    // On resume, revalidate the source against the recorded validator: a changed source answers a
    // conditional range with a full `200`, which we treat as a changed source. Only the primary carries
    // `If-Range`; a mirror's validators may differ, and the block hash is the real check anyway.
    if task.source == 0
        && let Some(value) = &state.if_range
        && let Ok(header) = reqwest::header::HeaderValue::from_bytes(value)
    {
        request = request.header(IF_RANGE, header);
    }
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
                url: url.clone(),
            });
        }
    }
    match content_range(&resp) {
        // The range must start where we asked, and the server's total (when concrete) must match the
        // caller's declared length - the §3.7 cross-check the single-connection path also enforces.
        Some((first, total)) => {
            if first != range.start {
                return SegmentResult::Fatal(FetchError::Http {
                    status: 206,
                    url: url.clone(),
                });
            }
            if let Some(total) = total
                && total != state.len
            {
                return SegmentResult::Fatal(FetchError::LengthMismatch {
                    expected: state.len,
                    got: total,
                });
            }
        }
        None => {
            return SegmentResult::Fatal(FetchError::Http {
                status: 206,
                url: url.clone(),
            });
        }
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
    lock(&state.covered).insert(*committed, end);
    state.progress_notify.notify_one();
    // Nudge the block verifier: this batch may have completed a whole block.
    if let Some(verify) = &state.verify {
        verify.notify.notify_one();
    }
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
fn content_range(resp: &reqwest::Response) -> Option<(u64, Option<u64>)> {
    let value = resp.headers().get(CONTENT_RANGE)?.to_str().ok()?;
    let (range, total) = value.strip_prefix("bytes ")?.split_once('/')?;
    let (first, _last) = range.split_once('-')?;
    let first = first.parse::<u64>().ok()?;
    let total = if total == "*" {
        None
    } else {
        Some(total.parse::<u64>().ok()?)
    };
    Some((first, total))
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
    // No single write handle survived the workers, so re-open to make the assembled data durable,
    // then hand off to the shared publish tail.
    if let Ok(file) = tokio::fs::File::open(part).await {
        let _ = file.sync_all().await;
    }
    download::publish(dest, part, apdl, len, Some(len), progress).await
}

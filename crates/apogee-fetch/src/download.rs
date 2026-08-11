//! The single-connection streaming download state machine.
//!
//! A download reserves its `.part` to the full length as soon as one is known (the caller's, or the
//! first response's `Content-Length`), so a transfer with nowhere to land fails up front rather than
//! partway through; a body whose length nobody states reserves nothing. The body streams to the
//! `.part`, hashing as it writes, and the journal watermark advances only after the bytes it names are
//! `fsync`ed, so a crash never leaves the journal ahead of the disk. On success the file is verified,
//! renamed onto its destination, and the journal removed. An interrupted transfer resumes from the
//! journal watermark with `Range` + `If-Range`; a source that answers a ranged request with a `200`
//! restarts cleanly from zero instead of stitching bodies together. An existing destination is
//! re-hashed against the validator rather than trusted on its path.
//!
//! A retry does not have to return to the source that failed: each try picks its source by the same
//! rule the segmented engine's re-queue uses ([`rotate`](crate::retry::rotate)), so a transfer of
//! unknown length, a file too small to segment, or a job demoted after the primary answered a ranged
//! probe with a whole body all fail over to a mirror. The journal's identity and a conditional range's
//! validator stay the primary's alone (see [`Conditional`]).

use std::ffi::OsString;
use std::fmt::Write as _;
use std::io::SeekFrom;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use futures_util::StreamExt;
use reqwest::header::{CONTENT_RANGE, ETAG, IF_RANGE, LAST_MODIFIED, RANGE};
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};
use tokio_util::sync::CancellationToken;
use url::Url;

use crate::block::BlockPlan;
use crate::error::FetchError;
use crate::fetcher::Shared;
use crate::hash::{DigestPin, FileHasher};
use crate::headers::apply_headers;
use crate::journal::{self, Identity, Journal};
use crate::prealloc::preallocate;
use crate::progress::{Phase, Reporter};
use crate::retry::{
    Class, classify_send_error, classify_status, retry_after, rotate, sleep_or_cancel,
};
use crate::spec::DownloadSpec;
use crate::validator::{Validator, VerifiedFile};

/// What a download must prove before it publishes: a whole-file digest, a per-block SHA1 map, or
/// nothing. Built by [`plan`] from the spec's [`Validator`].
pub(crate) struct Verify {
    // Both `Sha256` and `Blake3` digests are 32 bytes wide, so the expected bytes alone can't say
    // which function produced them; the tag has to travel with the digest.
    pub(crate) digest: Option<DigestPin>,
    pub(crate) blocks: Option<Arc<BlockPlan>>,
}

/// Bytes streamed between `fsync` + journal-commit points, and the write-buffer size: bounds how much
/// a kill can cost (a resume re-fetches at most this much) against per-batch write/fsync overhead.
const BATCH: u64 = 1024 * 1024;
/// The buffer size for reading a file back to hash it (resume re-seed, existing-dest verification).
const READ_CHUNK: usize = 64 * 1024;

/// Run one single-connection download to completion: request, stream, verify, and publish.
///
/// One attempt is one request plus the body it delivers; a connection cut off mid-body, or one that
/// goes silent past the inactivity timeout, commits what it received and retries the rest after a
/// backoff rather than losing the whole transfer.
pub(crate) async fn run(
    client: &reqwest::Client,
    spec: &DownloadSpec,
    verify: Verify,
    progress: Reporter,
    cancel: CancellationToken,
    shared: &Shared,
) -> Result<VerifiedFile, FetchError> {
    let dest = spec.dest();
    let part = sidecar(dest, ".part");
    let apdl = sidecar(dest, ".apdl");

    if !spec.overwrite()
        && let Some(verified) =
            check_existing_dest(dest, &verify, spec.expected_len(), &progress, &cancel).await?
    {
        return Ok(verified);
    }

    // Hold one global connection slot for the transfer, so a single-connection download counts against
    // the same cap as a segment. Released when this scope ends.
    let _conn = shared.scheduler.acquire_connection().await;

    let core_identity = base_identity(spec, spec.expected_len());
    // The primary, then each mirror: the list every try rotates through. The primary stays index 0, so
    // it alone carries the journal's identity and a conditional range's validator.
    let sources = spec.sources();

    // Reconcile a prior attempt: resume only when the journal matches this request, records real
    // progress, and the `.part` is at least that long.
    //
    // The length test is kept rather than replaced now that the `.part` is preallocated. What it used
    // to do, separate an interrupted transfer from a journal claiming more than the file holds, the
    // reservation makes moot: a `.part` this engine left behind is always the full reserved length.
    // What it still does is the case it was written for, a `.part` shortened or replaced by something
    // outside this engine, where resuming at the watermark would stitch a tail onto bytes that are not
    // there. The watermark's own trustworthiness never came from the file size anyway: it comes from
    // the commit order (bytes are `fsync`ed before the interval naming them is written) and the
    // identity match, which is exactly what the segmented engine leans on beside its own preallocated
    // `.part`.
    let mut start = 0u64;
    let mut if_range: Option<Conditional> = None;
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
        // A journaled validator is always the primary's: the identity it was recorded under is the
        // primary's URL, and only the primary's own answer is ever written there.
        if_range = loaded
            .identity
            .etag
            .clone()
            .or_else(|| loaded.identity.last_modified.clone())
            .map(|value| Conditional { source: 0, value });
        journal_identity = loaded.identity;
    }

    // Block mode leaves the running hasher off (there is no whole-file digest on that path); its
    // per-block SHA1s are checked from disk after the stream completes.
    let mut hasher: Option<FileHasher> = verify.digest.map(|pin| pin.hasher());
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
        let Attempt { resp, source } = obtain_response(
            client,
            spec,
            &sources,
            Partial {
                path: &part,
                file: &mut part_file,
                hasher: &mut hasher,
                journal: &mut journal,
                start: &mut start,
                if_range: &mut if_range,
            },
            shared,
            &progress,
            &cancel,
            &mut attempts,
        )
        .await?;
        let url = &sources[source];

        // The first progress event of an attempt is emitted only after the resume disposition is
        // settled, so it never names bytes a `200` has just discarded.
        high = high.max(start);
        progress.emit(high, spec.expected_len(), Phase::Connecting);

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

        // Reserve the whole file before a byte of the body lands, so a transfer that cannot fit fails
        // here instead of after writing however much did fit. The length is the caller's when it
        // declared one and the response's own `Content-Length` otherwise, which is the case that
        // matters: everything whose length the caller did not declare runs on this engine, and those
        // are the largest transfers there are. A body of genuinely unknown length (a chunked response
        // with no `Content-Length`) reserves nothing rather than guessing at a size.
        //
        // Inside the attempt loop, after `obtain_response` has settled the resume disposition, because
        // that is what decides where the body lands: a `200` answering a ranged request truncates the
        // `.part` back to zero on its way through, and reserving here takes back what the truncation
        // gave up. `open_part` has the same relationship and runs before the first request for the same
        // reason. `preallocate` never shrinks a file, so an attempt that did not restart pays one
        // syscall over an already-full-length file.
        if let Some(len) = total {
            preallocate(&part, len).await?;
        }

        // A fresh start records the server's validators so a later resume can revalidate with
        // `If-Range`. Only the primary's own answer may be recorded: the identity these are written
        // under is the primary's URL, so a mirror's would be offered back to the primary on the next
        // run and invite a changed-source verdict on a source that never changed. The segmented
        // engine drops a mirror-answered probe's validators for the same reason.
        //
        // A mirror-served prefix therefore journals nothing to revalidate against, so the next run's
        // resume continues it unconditionally and the file's own validator is what catches a prefix
        // and a tail that came from copies which had diverged. That is the trade the segmented engine
        // already makes for a mirror-answered probe, and the reason `External` names a downstream gate.
        if spec.resume() && journal.is_none() {
            let (etag, last_modified) = match source {
                0 => (
                    header_bytes(&resp, &ETAG),
                    header_bytes(&resp, &LAST_MODIFIED),
                ),
                _ => (None, None),
            };
            journal_identity.etag = etag;
            journal_identity.last_modified = last_modified;
            journal = Journal::create(&apdl, &journal_identity)
                .await
                .map_err(|e| FetchError::io(&apdl, e))?;
        }
        // Pin this response's validator for the in-process retries too, even when no journal is being
        // kept: a source that changes between a dropped body and its retry then answers the
        // conditional range with a `200` and restarts cleanly, instead of stitching two files
        // together. Held per source, so the pin is re-taken whenever the rotation lands somewhere the
        // current one does not describe.
        if if_range.as_ref().is_none_or(|held| held.source != source) {
            if_range = conditional(&resp, source);
        }

        match stream_body(
            resp,
            url,
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
            Outcome::Interrupted {
                written,
                source: cause,
            } => {
                let from = source;
                attempts += 1;
                if !shared.retry.may_retry(attempts) {
                    tracing::warn!(
                        url = %url,
                        attempts,
                        at_bytes = written,
                        reason = %cause,
                        "the body kept failing and the attempt budget is spent",
                    );
                    return Err(exhausted(&sources, attempts, written, cause));
                }
                let to = rotate(attempts, sources.len());
                progress.counters().retry(from, to);
                let delay = shared.retry.delay(attempts, None, &shared.jitter);
                tracing::debug!(
                    url = %url,
                    attempts,
                    at_bytes = written,
                    from,
                    to,
                    delay_ms = delay.as_millis(),
                    reason = %cause,
                    "the body was cut off; resuming after a backoff",
                );
                if !sleep_or_cancel(delay, &cancel).await {
                    return Err(FetchError::Cancelled);
                }
                // Everything received is durable and hashed, so the next attempt asks only for the
                // rest. This is the resume path the journal already supported, run in-process, and the
                // spent attempt is also what steps the rotation, so the rest may come off a mirror.
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

    if let (Some(h), Some(pin)) = (hasher.take(), verify.digest) {
        progress.emit(written, total, Phase::Verifying);
        let exp = pin.bytes();
        let got = h.finalize();
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
        progress.emit(written, total, Phase::Verifying);
        if let Some(block) = verify_blocks_seq(&part, plan, &cancel).await? {
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

/// A usable response and which source answered it: `0` for the primary, higher for a mirror.
struct Attempt {
    resp: reqwest::Response,
    source: usize,
}

/// The `.part` being written and everything that must move with it on a resume: its handle, running
/// hash, journal, resume offset, and validator. Grouped because [`reset_to_zero`] moves all of it
/// together, never one piece without the rest.
struct Partial<'a> {
    path: &'a Path,
    file: &'a mut tokio::fs::File,
    hasher: &'a mut Option<FileHasher>,
    journal: &'a mut Option<Journal>,
    start: &'a mut u64,
    if_range: &'a mut Option<Conditional>,
}

/// A server validator (`ETag` or `Last-Modified`) and the source that issued it. Tagged because a
/// validator is only valid against the source that issued it: offering the primary's to a mirror, or
/// the reverse, reads as a change that never happened.
struct Conditional {
    source: usize,
    value: Vec<u8>,
}

/// The strongest validator `resp` offers (`ETag`, else `Last-Modified`), tagged with `source`.
fn conditional(resp: &reqwest::Response, source: usize) -> Option<Conditional> {
    header_bytes(resp, &ETAG)
        .or_else(|| header_bytes(resp, &LAST_MODIFIED))
        .map(|value| Conditional { source, value })
}

/// The failure to report once the attempt budget is spent: [`FetchError::AllSourcesFailed`] when
/// `sources` holds mirrors (failover itself was exhausted), else `last` verbatim.
fn exhausted(sources: &[Url], attempts: u32, at_bytes: u64, last: FetchError) -> FetchError {
    match sources {
        [primary, _, ..] => FetchError::AllSourcesFailed {
            url: primary.clone(),
            sources: sources.len(),
            attempts,
            at_bytes,
        },
        _ => last,
    }
}

/// Where one body attempt starts, the transfer's total length once known, and the shared progress
/// high-water mark.
struct Cursor<'a> {
    start: u64,
    total: Option<u64>,
    high: &'a mut u64,
}

/// How one body attempt ended.
enum Outcome {
    /// The body ran to its end; `written` bytes are durable.
    Complete(u64),
    /// The connection was cut off or went quiet; `written` bytes are durable and hashed, so the next
    /// attempt resumes from there. `source` is the failure to report if the attempt budget runs out.
    Interrupted { written: u64, source: FetchError },
}

/// Stream one response body into the `.part`, hashing as it goes, in `BATCH`-sized batches: one write
/// and one `fsync` + journal-commit per batch rather than per chunk. A mid-body error or inactivity
/// timeout commits the current batch first, so an [`Outcome::Interrupted`] watermark is always durable.
///
/// # Errors
/// [`FetchError::Cancelled`] if `cancel` fires, or [`FetchError::Io`] if the `.part` or its journal
/// cannot be written. A transport failure is not an error here: [`Outcome::Interrupted`] reports it to
/// the caller as an outcome to retry instead.
#[allow(clippy::too_many_arguments)]
async fn stream_body(
    resp: reqwest::Response,
    url: &Url,
    part: &Path,
    part_file: &mut tokio::fs::File,
    hasher: &mut Option<FileHasher>,
    journal: &mut Option<Journal>,
    apdl: &Path,
    cursor: Cursor<'_>,
    progress: &Reporter,
    cancel: &CancellationToken,
    shared: &Shared,
) -> Result<Outcome, FetchError> {
    let Cursor { start, total, high } = cursor;
    let mut stream = Box::pin(resp.bytes_stream());
    let mut written = start;
    let mut batch: Vec<u8> = Vec::with_capacity(BATCH as usize);
    let tick = |written: u64, high: &mut u64, phase: Phase| {
        *high = (*high).max(written);
        progress.emit(*high, total, phase);
    };
    tick(written, high, Phase::Downloading);
    loop {
        // Each arm that leaves the loop early names the failure it would report; the batch is
        // committed once, below, so no return path can leave received bytes unflushed.
        let cut_off = tokio::select! {
            biased;
            () = cancel.cancelled() => Some(FetchError::Cancelled),
            () = tokio::time::sleep(shared.stall_timeout) => {
                progress.counters().stall();
                tracing::warn!(
                    url = %url,
                    at_bytes = written,
                    timeout_ms = shared.stall_timeout.as_millis(),
                    "the body went quiet past the inactivity timeout",
                );
                Some(FetchError::Stalled { url: url.clone(), at_bytes: written })
            }
            item = stream.next() => match item {
                None => break,
                Some(Ok(chunk)) => {
                    let bytes: &[u8] = chunk.as_ref();
                    // Throttle on the bytes just read off the socket, before consuming more. Raced
                    // against the cancel token: at a low rate this wait is chunk-size over rate long,
                    // and inside this handler the select's own cancel arm is not being polled, so an
                    // unraced wait would hold a cancel off by that long. The tokens are only debited
                    // when the wait completes, so abandoning it mid-wait leaks none.
                    let cancelled = tokio::select! {
                        biased;
                        () = cancel.cancelled() => true,
                        () = shared.limiter.acquire(bytes.len() as u64) => false,
                    };
                    if cancelled {
                        Some(FetchError::Cancelled)
                    } else {
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
                }
                Some(Err(e)) => Some(transport_error(url, e)),
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

/// Send the request and settle the resume disposition, retrying what is worth retrying and rotating
/// off a source that will not answer.
///
/// A valid `206` continues from `start`; a `200` (source changed, or the range was ignored) restarts
/// cleanly from zero; a `416` or an unusable `206` retries once more from zero. A connect failure, a
/// throttling status, and a stalled response (see [`send_bounded`]) each spend an attempt and back off
/// under the fetcher's retry policy; every other status is fatal.
///
/// Which source each try goes to is [`rotate`]'s decision, the same rule the segmented engine's
/// re-queue follows. The choice is a pure function of `attempts`, which only the failure paths
/// advance, so rotating never adds a try the attempt budget has not already paid for.
///
/// # Errors
/// [`FetchError::Http`] for a fatal status, [`FetchError::AllSourcesFailed`] once a transfer with
/// mirrors exhausts its budget across them (the last source's own failure when there are none),
/// [`FetchError::Connect`] if the last attempt could not reach the host, [`FetchError::Stalled`] if it
/// answered with no headers at all, [`FetchError::Cancelled`] if `cancel` fires, or [`FetchError::Io`]
/// if truncating the `.part` for a restart failed.
#[allow(clippy::too_many_arguments)]
async fn obtain_response(
    client: &reqwest::Client,
    spec: &DownloadSpec,
    sources: &[Url],
    mut partial: Partial<'_>,
    shared: &Shared,
    progress: &Reporter,
    cancel: &CancellationToken,
    attempts: &mut u32,
) -> Result<Attempt, FetchError> {
    // The resume disposition gets exactly one restart from zero, and it is not charged to the retry
    // budget: it corrects *this* request rather than re-attempting a failed one. It therefore does not
    // step the rotation either, so the correction is asked of the source that needs correcting.
    let mut restarted = false;
    loop {
        let source = rotate(*attempts, sources.len());
        let url = &sources[source];
        let mut req = apply_headers(client.get(url.clone()), spec.header_policy());
        if *partial.start > 0 {
            req = req.header(RANGE, format!("bytes={}-", *partial.start));
            // The validator goes back only to the source that issued it. Offered to any other, it is a
            // mismatch by construction, and this engine answers a mismatch by throwing the durable
            // prefix away and streaming from zero.
            if let Some(held) = partial.if_range.as_ref()
                && held.source == source
                && let Ok(header) = reqwest::header::HeaderValue::from_bytes(&held.value)
            {
                req = req.header(IF_RANGE, header);
            }
        }
        let sent = tokio::select! {
            biased;
            () = cancel.cancelled() => return Err(FetchError::Cancelled),
            sent = send_bounded(req, shared.stall_timeout) => sent,
        };
        // Each arm yields the failure to report if this is the last attempt, plus the pause the
        // server asked for; a usable response returns straight out.
        let (failure, asked) = match sent {
            // The source took the request and sent no headers within the deadline: no progress, with
            // nothing delivered to resume from, which is the same verdict a body going quiet earns.
            Err(_elapsed) => {
                progress.counters().stall();
                tracing::warn!(
                    url = %url,
                    at_bytes = *partial.start,
                    timeout_ms = shared.stall_timeout.as_millis(),
                    "the source sent no response headers within the deadline",
                );
                (
                    FetchError::Stalled {
                        url: url.clone(),
                        at_bytes: *partial.start,
                    },
                    None,
                )
            }
            Ok(Ok(resp)) => {
                let status = resp.status().as_u16();
                if status == 200 {
                    if *partial.start > 0 {
                        reset_to_zero(&mut partial).await?;
                    }
                    return Ok(Attempt { resp, source });
                }
                if status == 206
                    && *partial.start > 0
                    && content_range_ok(&resp, *partial.start, spec.expected_len())
                {
                    return Ok(Attempt { resp, source });
                }
                if (status == 206 || status == 416) && *partial.start > 0 && !restarted {
                    restarted = true;
                    reset_to_zero(&mut partial).await?;
                    continue;
                }
                let failure = FetchError::Http {
                    status,
                    url: url.clone(),
                };
                if classify_status(status) == Class::Fatal {
                    return Err(failure);
                }
                (failure, retry_after(resp.headers()))
            }
            Ok(Err(e)) if classify_send_error(&e) == Class::Fatal => {
                return Err(connect_error(url, e));
            }
            Ok(Err(e)) => (connect_error(url, e), None),
        };
        *attempts += 1;
        if !shared.retry.may_retry(*attempts) {
            tracing::warn!(
                url = %url,
                attempts = *attempts,
                at_bytes = *partial.start,
                reason = %failure,
                "no source answered and the attempt budget is spent",
            );
            return Err(exhausted(sources, *attempts, *partial.start, failure));
        }
        let to = rotate(*attempts, sources.len());
        progress.counters().retry(source, to);
        let delay = shared.retry.delay(*attempts, asked, &shared.jitter);
        tracing::debug!(
            url = %url,
            attempts = *attempts,
            at_bytes = *partial.start,
            from = source,
            to,
            delay_ms = delay.as_millis(),
            reason = %failure,
            "retrying the request after a backoff",
        );
        if !sleep_or_cancel(delay, cancel).await {
            return Err(FetchError::Cancelled);
        }
    }
}

/// Open the `.part` for writing at `start`: create fresh at zero, or truncate an existing file to
/// `start`, re-seed the running hash from its prefix, and seek to the end for appending.
async fn open_part(
    part: &Path,
    start: u64,
    hasher: Option<&mut FileHasher>,
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

/// Truncate the `.part`, reset the running hash, and drop the journal, resume offset, and validator,
/// so the next body streams from zero.
async fn reset_to_zero(partial: &mut Partial<'_>) -> Result<(), FetchError> {
    partial
        .file
        .set_len(0)
        .await
        .map_err(|e| FetchError::io(partial.path, e))?;
    partial
        .file
        .seek(SeekFrom::Start(0))
        .await
        .map_err(|e| FetchError::io(partial.path, e))?;
    if let Some(h) = partial.hasher.as_mut() {
        h.reset();
    }
    *partial.journal = None;
    *partial.start = 0;
    // The held validator described a prefix that no longer exists. The response that triggered this
    // reset carries the current one, and the caller re-pins from it.
    *partial.if_range = None;
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

/// Make the batch durable, then advance the journal watermark: the record never names bytes the disk
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
/// `etag`/`last_modified` start empty; the segmented engine fills them in from its own probe.
pub(crate) fn base_identity(spec: &DownloadSpec, expected_len: Option<u64>) -> Identity {
    Identity {
        url: spec.url().as_str().to_owned(),
        expected_len,
        validator_digest: spec.validator().config_digest(),
        etag: None,
        last_modified: None,
    }
}

/// The publish tail shared by both engines: rename the verified `.part` onto `dest`, `fsync` the
/// parent for rename durability, drop the journal, and emit `Complete`. The part's data must already
/// be durable; each engine `fsync`s it its own way before calling this.
pub(crate) async fn publish(
    dest: &Path,
    part: &Path,
    apdl: &Path,
    bytes: u64,
    total: Option<u64>,
    progress: &Reporter,
) -> Result<VerifiedFile, FetchError> {
    tokio::fs::rename(part, dest)
        .await
        .map_err(|e| FetchError::io(dest, e))?;
    sync_parent_dir(dest).await;
    let _ = tokio::fs::remove_file(apdl).await;
    progress.emit(bytes, total, Phase::Complete);
    Ok(VerifiedFile::mint(dest))
}

/// Derive what a download must prove from its validator: a whole-file digest, a per-block SHA1 map, or
/// nothing. The spec builder has already checked a block validator's layout, so the length is present
/// and consistent here.
pub(crate) fn plan(validator: &Validator, expected_len: Option<u64>) -> Result<Verify, FetchError> {
    match validator {
        Validator::Sha256(digest) => Ok(Verify {
            digest: Some(DigestPin::Sha256(*digest)),
            blocks: None,
        }),
        Validator::Blake3(digest) => Ok(Verify {
            digest: Some(DigestPin::Blake3(*digest)),
            blocks: None,
        }),
        // No fetch-side hash: length is checked during the transfer, and a downstream gate
        // authenticates the bytes. Reached only via `download_external`, which returns a plain path
        // rather than a `VerifiedFile`.
        Validator::None | Validator::External => Ok(Verify {
            digest: None,
            blocks: None,
        }),
        Validator::BlockSha1 { block_size, hashes } => {
            let len = expected_len.ok_or(FetchError::Unsupported {
                what: "block-hash validation requires a declared length",
            })?;
            Ok(Verify {
                digest: None,
                blocks: Some(Arc::new(BlockPlan::new(*block_size, hashes.clone(), len))),
            })
        }
    }
}

/// Hash each block of `path` from disk in order, returning the index of the first block whose SHA1
/// does not match its plan, or `None` when every block verifies. Hashed on a blocking worker per
/// block, with the cancel token checked between blocks so a multi-gigabyte re-hash stays cancellable.
pub(crate) async fn verify_blocks_seq(
    path: &Path,
    plan: &BlockPlan,
    cancel: &CancellationToken,
) -> Result<Option<u32>, FetchError> {
    for i in 0..plan.count() {
        if cancel.is_cancelled() {
            return Err(FetchError::Cancelled);
        }
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

/// Idempotent skip: return an existing destination only if it still satisfies the validator (checked
/// against local disk only, never the network), so a `VerifiedFile` is never minted over stale bytes.
/// `Ok(None)` means the download should proceed.
pub(crate) async fn check_existing_dest(
    dest: &Path,
    verify: &Verify,
    expected_len: Option<u64>,
    progress: &Reporter,
    cancel: &CancellationToken,
) -> Result<Option<VerifiedFile>, FetchError> {
    if let Ok(meta) = tokio::fs::metadata(dest).await
        && meta.is_file()
        && dest_satisfies(dest, meta.len(), verify, expected_len, cancel).await?
    {
        progress.emit(meta.len(), expected_len, Phase::Complete);
        return Ok(Some(VerifiedFile::mint(dest)));
    }
    Ok(None)
}

/// Whether `dest` already satisfies the request: the declared length, if any, and the validator's
/// proof recomputed from disk. A block download is skipped only when every block verifies.
async fn dest_satisfies(
    dest: &Path,
    len: u64,
    verify: &Verify,
    expected_len: Option<u64>,
    cancel: &CancellationToken,
) -> Result<bool, FetchError> {
    if expected_len.is_some_and(|n| n != len) {
        return Ok(false);
    }
    if let Some(plan) = &verify.blocks {
        return Ok(verify_blocks_seq(dest, plan, cancel).await?.is_none());
    }
    match verify.digest {
        None => Ok(true),
        Some(pin) => Ok(hash_file(dest, pin, cancel).await? == pin.bytes()),
    }
}

/// Hash a file on disk in bounded memory, under the function `pin` names. The cancel token is checked
/// once per chunk, so a cancel lands within one read rather than after the whole file.
pub(crate) async fn hash_file(
    path: &Path,
    pin: DigestPin,
    cancel: &CancellationToken,
) -> Result<[u8; 32], FetchError> {
    let mut file = tokio::fs::File::open(path)
        .await
        .map_err(|e| FetchError::io(path, e))?;
    let mut hasher = pin.hasher();
    let mut buf = vec![0u8; READ_CHUNK];
    loop {
        if cancel.is_cancelled() {
            return Err(FetchError::Cancelled);
        }
        let read = file
            .read(&mut buf)
            .await
            .map_err(|e| FetchError::io(path, e))?;
        if read == 0 {
            break;
        }
        hasher.update(&buf[..read]);
    }
    Ok(hasher.finalize())
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

/// Send `req` and wait for the response headers, giving up after `within`. Reaching the host is
/// inside that: DNS, connect, TLS handshake, any redirect hops, and the wait for a status line.
/// `Err(Elapsed)` reads as the source going quiet: it costs an attempt and rotates like any other
/// delivery failure, while a host that refuses the connection errors immediately as
/// [`FetchError::Connect`] instead of reaching here.
pub(crate) async fn send_bounded(
    req: reqwest::RequestBuilder,
    within: Duration,
) -> Result<Result<reqwest::Response, reqwest::Error>, tokio::time::error::Elapsed> {
    // Bounds only the wait for headers, not the body: the crate's other deadline is an inactivity
    // timeout that arms once the body is already streaming, and reqwest's own whole-request `timeout`
    // would cover both and cut a multi-gigabyte transfer off at a fixed duration rather than at a fixed
    // silence. A host that completes the connection and then never sends a status line would otherwise
    // hang every engine inside one `send` with no error to retry on and no attempt budget to bound it.
    tokio::time::timeout(within, req.send()).await
}

/// A failure establishing the connection, or the client's redirect policy declining to follow one.
/// Both arrive from the same `send`; only the cause chain tells them apart.
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

pub(crate) fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(out, "{b:02x}");
    }
    out
}

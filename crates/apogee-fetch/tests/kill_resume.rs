//! Property test: repeated interruptions converge to a byte-identical file, and every resume picks up
//! where the last one left off instead of re-fetching what it had already banked.
//!
//! Each case interrupts a download at a random set of progress points, resumes from the journal after
//! every interruption, and finally lets it complete. Two things must hold: the final file hashes to
//! the source, and no request ever asks for a byte the client had already committed.
//!
//! That second claim is measured on the client, not on the server's byte tally. A cancelled download
//! abandons its response, and the bytes already in the frame channel and the socket buffers are
//! counted as served while never reaching the client at all; on loopback that overshoot runs to
//! megabytes (`tcp_wmem` auto-tunes there), which swamps any budget worth asserting. The offset each
//! request asks to start at has no such problem: the client picks it from its own journal before a
//! byte moves, so it says exactly what the resume decided to re-fetch.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use apogee_fetch::{DownloadSpec, Fetcher, Progress, Validator};
use apogee_test_support::chaos::{ChaosServer, body_sha256, sha256_of};
use proptest::prelude::*;
use tokio_util::sync::CancellationToken;

/// The whole-file size each case downloads (a few fsync batches' worth).
const FILE_LEN: u64 = 3 * 1024 * 1024;

/// One download attempt: what the client had banked before it started, and the offsets its requests
/// asked to begin at.
#[derive(Debug)]
struct Attempt {
    /// The highest progress the client had reported before this attempt began, so the lowest offset
    /// it may ask for without re-fetching. A lower bound rather than the exact watermark: cancelling
    /// also commits the batch in flight, which is more than the last progress event announced.
    banked: u64,
    /// The offset every request this attempt made asked to start at, in arrival order.
    resumed_from: Vec<u64>,
}

/// Download `FILE_LEN` bytes from `seed`, cancelling once each time progress crosses a point in
/// `interrupt_at`, then completing. Returns the final file's hash and one [`Attempt`] per download.
async fn download_with_interruptions(
    seed: u64,
    interrupt_at: &[u64],
) -> Result<([u8; 32], Vec<Attempt>), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let dest = dir.path().join("out.bin");
    let server = ChaosServer::builder(seed, FILE_LEN)
        .etag("\"v1\"")
        .chunk(64 * 1024)
        .start()
        .await?;
    let spec = DownloadSpec::builder(
        server.url("file.bin"),
        &dest,
        Validator::Sha256(body_sha256(seed, FILE_LEN)),
    )
    .expected_len(FILE_LEN)
    .build()?;
    let downloader = Fetcher::builder().build()?;

    let mut attempts: Vec<Attempt> = Vec::new();
    let mut banked = 0u64;
    let mut counted = 0usize;
    // The requests that arrived since the last split, which are exactly the ones the attempt just
    // awaited made: downloads run one after another here, so no two overlap. This reads the offsets
    // recorded on the request path rather than the ranges recorded when a body ends, because an
    // abandoned body can be recorded after the next request has already arrived and would then be
    // counted against the wrong attempt.
    let split = |server: &ChaosServer, counted: &mut usize| {
        let starts = server.stats().requested_starts();
        let fresh = starts[*counted..].to_vec();
        *counted = starts.len();
        fresh
    };

    for &point in interrupt_at {
        let seen = Arc::new(AtomicU64::new(0));
        let reported = Arc::clone(&seen);
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<Progress>();
        let cancel = CancellationToken::new();
        let trigger = cancel.clone();
        let watcher = tokio::spawn(async move {
            while let Some(progress) = rx.recv().await {
                // Progress is emitted only after the batch behind it is fsynced and journaled, so the
                // last value seen here is a watermark the client can genuinely resume from.
                reported.fetch_max(progress.bytes_done, Ordering::SeqCst);
                if progress.bytes_done >= point {
                    trigger.cancel();
                    break;
                }
            }
        });
        // Ignore the outcome: a cancel is an error, and a race that completes first is fine.
        let _ = downloader.download(&spec, Some(tx), cancel).await;
        watcher.abort();
        let _ = watcher.await;
        attempts.push(Attempt {
            banked,
            resumed_from: split(&server, &mut counted),
        });
        banked = banked.max(seen.load(Ordering::SeqCst));
    }

    let verified = downloader
        .download(&spec, None, CancellationToken::new())
        .await?;
    attempts.push(Attempt {
        banked,
        resumed_from: split(&server, &mut counted),
    });
    let bytes = tokio::fs::read(verified.path()).await?;
    Ok((sha256_of(&bytes), attempts))
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(24))]

    #[test]
    fn resumes_byte_identically_without_re_fetching_what_it_banked(
        seed in any::<u64>(),
        interrupt_at in prop::collection::vec(1u64..FILE_LEN, 0..5),
    ) {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        let (hash, attempts) = runtime
            .block_on(download_with_interruptions(seed, &interrupt_at))
            .unwrap();

        prop_assert_eq!(hash, body_sha256(seed, FILE_LEN));
        prop_assert_eq!(attempts.len(), interrupt_at.len() + 1);
        // The first attempt has nothing banked, so it must start from the beginning.
        prop_assert_eq!(attempts[0].resumed_from.first(), Some(&0));
        for (i, attempt) in attempts.iter().enumerate() {
            // How many requests an attempt makes is deliberately not asserted. An attempt whose
            // request fails before delivering anything retries at the same offset, which is the retry
            // policy working rather than waste, and an interrupt point at or below what was already
            // banked cancels on the first progress event without the response carrying anything at
            // all. The offset is the invariant; the count is a scheduling detail.
            for start in &attempt.resumed_from {
                // A download that restarted from zero, or from anywhere below the watermark, would
                // re-fetch bytes it already had. This is the claim the whole journal exists to make.
                prop_assert!(
                    *start >= attempt.banked,
                    "attempt {} asked to resume at {} having already banked {} (starts {:?})",
                    i,
                    start,
                    attempt.banked,
                    attempt.resumed_from,
                );
            }
        }
    }
}

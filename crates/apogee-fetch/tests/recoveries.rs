//! What the progress stream says about a transfer that had to fight for its bytes.
//!
//! Every recovery here ends in `Ok`, which is the reason the counters exist: the returned value is
//! identical whether the transfer retried forty times or none, so these pin the one surface that can
//! still tell the two apart. Each test drives exactly one recovery and asserts both that its own
//! counter moved and that the others did not, because a counter that is really "something happened"
//! wearing five names would pass a test that only checked the one.

use std::time::Duration;

use apogee_fetch::{
    DownloadSpec, FetchError, Fetcher, Progress, Recoveries, RetryPolicy, Validator, VerifiedFile,
};
use apogee_test_support::chaos::{
    ChaosServer, block_hashes, body_sha256, generated_vec, sha256_of,
};
use tokio_util::sync::CancellationToken;

const MIB: u64 = 1024 * 1024;

/// The default policy with its waits compressed. These tests measure what was counted, never how
/// long the transfer was polite for.
fn brisk() -> RetryPolicy {
    RetryPolicy::default()
        .base_delay(Duration::from_millis(1))
        .max_delay(Duration::from_millis(5))
}

/// Run `spec` on `fetcher` and hand back the outcome with the tally the last progress event carried.
///
/// The last event is the `Complete` one: both engines emit it from `publish`, after every worker and
/// the progress aggregator have been joined, so nothing can still be counting when it is sent. The
/// drained events are returned too, so a test can check the tally never went backwards.
async fn run(
    fetcher: &Fetcher,
    spec: &DownloadSpec,
) -> Result<(Result<VerifiedFile, FetchError>, Vec<Progress>), tokio::task::JoinError> {
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<Progress>();
    let drain = tokio::spawn(async move {
        let mut seen = Vec::new();
        while let Some(event) = rx.recv().await {
            seen.push(event);
        }
        seen
    });
    // `download` owns the sender, so returning drops it and the drain ends on its own.
    let outcome = fetcher
        .download(spec, Some(tx), CancellationToken::new())
        .await;
    Ok((outcome, drain.await?))
}

/// The tally the transfer finished on, and the assertion that it only ever grew.
fn final_tally(events: &[Progress]) -> Recoveries {
    for pair in events.windows(2) {
        let (before, after) = (pair[0].recoveries, pair[1].recoveries);
        assert!(
            after.retries >= before.retries
                && after.rotations >= before.rotations
                && after.stalls >= before.stalls
                && after.blocks_refetched >= before.blocks_refetched
                && after.sources_dropped >= before.sources_dropped
                && after.demoted >= before.demoted,
            "the tally went backwards: {before:?} then {after:?}",
        );
    }
    events
        .last()
        .map(|event| event.recoveries)
        .unwrap_or_default()
}

/// A fetcher with compressed waits and room to segment.
fn fetcher(connections: usize) -> Result<Fetcher, FetchError> {
    Fetcher::builder()
        .max_connections_per_file(connections)
        .retry_policy(brisk())
        .build()
}

/// The control arm. Without it every assertion below is satisfied by a counter that is simply always
/// set, and "this transfer had trouble" would be indistinguishable from "this crate says so".
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_transfer_that_went_fine_reports_nothing_to_recover_from() {
    let dir = tempfile::tempdir().unwrap();
    let dest = dir.path().join("out.bin");
    let len = 16 * MIB;
    let server = ChaosServer::builder(70, len).start().await.unwrap();
    let spec = DownloadSpec::builder(
        server.url("f.bin"),
        &dest,
        Validator::Sha256(body_sha256(70, len)),
    )
    .expected_len(len)
    .build()
    .unwrap();

    let (outcome, events) = run(&fetcher(2).unwrap(), &spec).await.unwrap();
    outcome.unwrap();
    let tally = final_tally(&events);
    assert!(
        tally.is_clean(),
        "a healthy transfer reported {tally:?} to recover from",
    );
    assert!(
        events.iter().all(|event| event.recoveries.is_clean()),
        "a healthy transfer counted something mid-flight",
    );
}

/// A body cut off mid-stream is re-requested, and the retry that did it is on the stream. This is the
/// case the soak run had to count TCP connections to answer.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_body_cut_off_mid_stream_counts_a_retry() {
    let dir = tempfile::tempdir().unwrap();
    let dest = dir.path().join("out.bin");
    let len = 8 * MIB;
    let server = ChaosServer::builder(71, len)
        .drop_after(2 * MIB)
        .chunk(64 * 1024)
        .start()
        .await
        .unwrap();
    // No declared length, so this runs on the single-connection engine and the drop is a body retry
    // rather than a segment re-queue.
    let spec = DownloadSpec::builder(
        server.url("f.bin"),
        &dest,
        Validator::Sha256(body_sha256(71, len)),
    )
    .build()
    .unwrap();

    let (outcome, events) = run(&fetcher(1).unwrap(), &spec).await.unwrap();
    let verified = outcome.unwrap();
    assert_eq!(
        sha256_of(&tokio::fs::read(verified.path()).await.unwrap()),
        body_sha256(71, len),
    );
    let tally = final_tally(&events);
    assert_eq!(tally.retries, 1, "{tally:?}");
    // One source, so nowhere to rotate to, and a reset is not a silence.
    assert_eq!(tally.rotations, 0, "{tally:?}");
    assert_eq!(tally.stalls, 0, "{tally:?}");
    assert_eq!(tally.blocks_refetched, 0, "{tally:?}");
}

/// A source that goes silent mid-body is counted as a stall, and separately as the retry that stall
/// cost. The two are distinct: a reset counts one and not the other (above).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_source_going_silent_counts_a_stall_and_the_retry_it_cost() {
    let dir = tempfile::tempdir().unwrap();
    let dest = dir.path().join("out.bin");
    let len = 8 * MIB;
    let server = ChaosServer::builder(72, len)
        .stall_after(2 * MIB)
        .chunk(64 * 1024)
        .start()
        .await
        .unwrap();
    let spec = DownloadSpec::builder(
        server.url("f.bin"),
        &dest,
        Validator::Sha256(body_sha256(72, len)),
    )
    .build()
    .unwrap();

    let fetcher = Fetcher::builder()
        .max_connections_per_file(1)
        .retry_policy(brisk())
        .stall_timeout(Duration::from_millis(250))
        .build()
        .unwrap();
    let (outcome, events) = tokio::time::timeout(Duration::from_secs(60), run(&fetcher, &spec))
        .await
        .expect("a stalled body must time out, not hang")
        .unwrap();
    outcome.unwrap();
    let tally = final_tally(&events);
    assert_eq!(tally.stalls, 1, "{tally:?}");
    assert_eq!(tally.retries, 1, "{tally:?}");
    assert_eq!(tally.blocks_refetched, 0, "{tally:?}");
    assert!(!tally.demoted, "{tally:?}");
}

/// A primary that ignores the capability probe's range demotes the whole transfer to one connection.
/// It costs throughput and nothing else, so nothing else on the stream would ever say it happened.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_range_deaf_primary_counts_a_demotion() {
    let dir = tempfile::tempdir().unwrap();
    let dest = dir.path().join("out.bin");
    let len = 16 * MIB; // two segments, so segmentation is what is being given up
    let server = ChaosServer::builder(73, len)
        .accept_ranges(false)
        .start()
        .await
        .unwrap();
    let spec = DownloadSpec::builder(
        server.url("f.bin"),
        &dest,
        Validator::Sha256(body_sha256(73, len)),
    )
    .expected_len(len)
    .build()
    .unwrap();

    let (outcome, events) = run(&fetcher(4).unwrap(), &spec).await.unwrap();
    outcome.unwrap();
    let tally = final_tally(&events);
    assert!(tally.demoted, "{tally:?}");
    // Demotion is a recovery on its own: it spends no attempt and drops no source.
    assert_eq!(tally.retries, 0, "{tally:?}");
    assert_eq!(tally.sources_dropped, 0, "{tally:?}");
}

/// A mirror that answers a ranged request with a whole body leaves the rotation for the rest of the
/// transfer. The primary keeps serving, so the transfer succeeds and the loss is invisible without
/// the counter.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_range_deaf_mirror_counts_a_dropped_source() {
    let dir = tempfile::tempdir().unwrap();
    let dest = dir.path().join("out.bin");
    let (len, block_size) = (48 * MIB, 4 * MIB as u32); // block 5 spans [20 MiB, 24 MiB)
    let primary = ChaosServer::builder(74, len)
        .corrupt_range(20 * MIB..24 * MIB) // always corrupt, so the repair has to leave the primary
        .start()
        .await
        .unwrap();
    let deaf = ChaosServer::builder(74, len)
        .accept_ranges(false)
        .start()
        .await
        .unwrap();
    let good = ChaosServer::builder(74, len).start().await.unwrap();
    let spec = DownloadSpec::builder(
        primary.url("f.bin"),
        &dest,
        Validator::BlockSha1 {
            block_size,
            hashes: block_hashes(74, len, block_size),
        },
    )
    .expected_len(len)
    .mirror(deaf.url("f.bin"))
    .mirror(good.url("f.bin"))
    .build()
    .unwrap();

    let (outcome, events) =
        tokio::time::timeout(Duration::from_secs(60), run(&fetcher(4).unwrap(), &spec))
            .await
            .expect("a range-ignoring mirror must be passed over, not hang")
            .unwrap();
    let verified = outcome.unwrap();
    assert_eq!(
        tokio::fs::read(verified.path()).await.unwrap(),
        generated_vec(74, 0, len as usize),
    );
    let tally = final_tally(&events);
    assert_eq!(tally.sources_dropped, 1, "{tally:?}");
    // The permanently corrupt block is what sent work to a mirror in the first place.
    assert!(tally.blocks_refetched >= 1, "{tally:?}");
    assert!(tally.rotations >= 1, "{tally:?}");
    assert!(!tally.demoted, "{tally:?}");
}

/// A block that arrives corrupt is cleared and asked for again. The bytes are right by the end, so
/// the counter is the only record that the wire was wrong.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_block_that_failed_its_hash_counts_a_refetch() {
    let dir = tempfile::tempdir().unwrap();
    let dest = dir.path().join("out.bin");
    let (len, block_size) = (32 * MIB, 4 * MIB as u32);
    let server = ChaosServer::builder(75, len)
        .corrupt_range_once(8 * MIB..12 * MIB) // one block, clean on its re-fetch
        .start()
        .await
        .unwrap();
    let spec = DownloadSpec::builder(
        server.url("f.bin"),
        &dest,
        Validator::BlockSha1 {
            block_size,
            hashes: block_hashes(75, len, block_size),
        },
    )
    .expected_len(len)
    .build()
    .unwrap();

    let (outcome, events) =
        tokio::time::timeout(Duration::from_secs(60), run(&fetcher(4).unwrap(), &spec))
            .await
            .expect("a re-fetched block must complete, not hang")
            .unwrap();
    let verified = outcome.unwrap();
    assert_eq!(
        tokio::fs::read(verified.path()).await.unwrap(),
        generated_vec(75, 0, len as usize),
    );
    let tally = final_tally(&events);
    assert_eq!(tally.blocks_refetched, 1, "{tally:?}");
    // A re-fetch spends an attempt like any other failure to deliver.
    assert_eq!(tally.retries, 1, "{tally:?}");
    // One source, so the re-fetch went back to the primary.
    assert_eq!(tally.rotations, 0, "{tally:?}");
    assert_eq!(tally.stalls, 0, "{tally:?}");
    assert_eq!(tally.sources_dropped, 0, "{tally:?}");
}

//! A source that takes the request and never answers it.
//!
//! Every other silence these tests' fixtures can produce starts a body first, so the transfer already
//! holds a status, a length and a stream to poll, and the no-progress timeout runs on that stream.
//! Withholding the response leaves nothing to poll: the connection is up, the request is delivered,
//! and the engine sits inside one `send`. Each path below used to park there for as long as the
//! kernel kept the socket, spending no attempt and raising no error, so the outer `timeout` on each
//! test is the assertion that matters most - a regression here is a hang, not a wrong answer.

use std::error::Error;
use std::time::Duration;

use apogee_fetch::{
    DownloadSpec, FetchError, Fetcher, HttpSource, RangePacking, RetryPolicy, Validator,
};
use apogee_test_support::chaos::{ChaosServer, body_sha256, sha256_of};
use tokio_util::sync::CancellationToken;

const MIB: u64 = 1024 * 1024;

/// Long enough that a loopback response beats it every time, short enough that a test spending its
/// whole attempt budget on it still finishes in well under a second.
const DEADLINE: Duration = Duration::from_millis(150);

/// The default policy with its waits compressed: what these tests measure is that the deadline fires
/// and what it costs, never how long the transfer was polite for.
fn brisk() -> RetryPolicy {
    RetryPolicy::default()
        .base_delay(Duration::from_millis(1))
        .max_delay(Duration::from_millis(5))
}

fn fetcher(attempts: u32) -> Result<Fetcher, FetchError> {
    Fetcher::builder()
        .max_connections_per_file(2)
        .stall_timeout(DEADLINE)
        .retry_policy(brisk().max_attempts(attempts))
        .build()
}

/// What a hang fails with, so a regression here reads as the hang it is rather than as whichever
/// assertion the test never reached.
const NOT_WAITED_OUT: &str = "a silent source must be given up on, not waited out";

/// Run `fut` under a wall-clock ceiling far above what the compressed policy needs, so a transfer
/// that goes back to hanging fails the test instead of stalling the suite.
async fn bounded<T>(fut: impl Future<Output = T>) -> Result<T, tokio::time::error::Elapsed> {
    tokio::time::timeout(Duration::from_secs(30), fut).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_source_that_never_answers_ends_the_transfer_instead_of_hanging() {
    // No declared length, so this is the single-connection engine with no probe in front of it: the
    // very first request of the transfer is the one that goes unanswered. One source, so the failure
    // is reported verbatim rather than as an exhausted failover.
    let dir = tempfile::tempdir().unwrap();
    let dest = dir.path().join("out.bin");
    let len = 3 * MIB;
    let server = ChaosServer::builder(90, len)
        .withhold_response(u64::MAX)
        .start()
        .await
        .unwrap();
    let spec = DownloadSpec::builder(
        server.url("f.bin"),
        &dest,
        Validator::Sha256(body_sha256(90, len)),
    )
    .build()
    .unwrap();

    let err = bounded(
        fetcher(3)
            .unwrap()
            .download(&spec, None, CancellationToken::new()),
    )
    .await
    .expect(NOT_WAITED_OUT)
    .unwrap_err();

    match err {
        FetchError::Stalled {
            ref url, at_bytes, ..
        } => {
            assert_eq!(url, &server.url("f.bin"));
            assert_eq!(at_bytes, 0, "nothing was ever delivered to stall past");
        }
        other => panic!("got {other:?}"),
    }
    // The budget was spent rather than skipped: silence costs an attempt like any other failure to
    // deliver, which is what makes a mirror reachable from here at all.
    assert_eq!(server.stats().requests(), 3);
    assert!(!dest.exists(), "a failed download never publishes");
    assert!(err.is_transient(), "asking a quiet host again may work");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn one_withheld_response_costs_an_attempt_and_the_retry_lands() {
    // The other half of the rule: the deadline must not be fatal. One request is swallowed, the next
    // is served, and the file lands verified having paid exactly one attempt for the silence.
    let dir = tempfile::tempdir().unwrap();
    let dest = dir.path().join("out.bin");
    let len = 3 * MIB;
    let server = ChaosServer::builder(91, len)
        .withhold_response(1)
        .start()
        .await
        .unwrap();
    let spec = DownloadSpec::builder(
        server.url("f.bin"),
        &dest,
        Validator::Sha256(body_sha256(91, len)),
    )
    .build()
    .unwrap();

    let verified = bounded(
        fetcher(3)
            .unwrap()
            .download(&spec, None, CancellationToken::new()),
    )
    .await
    .expect(NOT_WAITED_OUT)
    .unwrap();

    assert_eq!(
        sha256_of(&tokio::fs::read(verified.path()).await.unwrap()),
        body_sha256(91, len),
    );
    assert_eq!(
        server.stats().requests(),
        2,
        "the silence, then the transfer"
    );
    assert_eq!(
        server.stats().served_ranges(),
        vec![0..len],
        "the retry streamed the whole file, not a resume of bytes that never arrived",
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_silent_primary_still_reaches_a_mirror() {
    // Rotation is driven by the attempt counter, so a failure that spends no attempt can never fail
    // over. A primary that answers nothing at all is the sharpest case of that: it is up, it accepts,
    // and it holds. The mirror has to get the transfer anyway.
    let dir = tempfile::tempdir().unwrap();
    let dest = dir.path().join("out.bin");
    let len = 3 * MIB;
    let primary = ChaosServer::builder(92, len)
        .withhold_response(u64::MAX)
        .start()
        .await
        .unwrap();
    let mirror = ChaosServer::builder(92, len).start().await.unwrap();
    let spec = DownloadSpec::builder(
        primary.url("f.bin"),
        &dest,
        Validator::Sha256(body_sha256(92, len)),
    )
    .mirror(mirror.url("f.bin"))
    .build()
    .unwrap();

    let verified = bounded(
        fetcher(4)
            .unwrap()
            .download(&spec, None, CancellationToken::new()),
    )
    .await
    .expect(NOT_WAITED_OUT)
    .unwrap();

    assert_eq!(
        sha256_of(&tokio::fs::read(verified.path()).await.unwrap()),
        body_sha256(92, len),
    );
    assert_eq!(
        primary.stats().requests(),
        2,
        "one try and the free same-source retry, then the rotation steps off it",
    );
    assert_eq!(mirror.stats().requests(), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_silent_probe_does_not_hang_a_segmented_transfer() {
    // The probe is the transfer's first request, and it runs before any segment worker exists, so
    // nothing else was ever going to notice it hanging. It retries under the same policy and the
    // transfer proceeds to segment normally.
    let dir = tempfile::tempdir().unwrap();
    let dest = dir.path().join("out.bin");
    let len = 16 * MIB; // two 8 MiB segments, so the probe is a real decision
    let server = ChaosServer::builder(93, len)
        .withhold_response(1)
        .start()
        .await
        .unwrap();
    let spec = DownloadSpec::builder(
        server.url("f.bin"),
        &dest,
        Validator::Sha256(body_sha256(93, len)),
    )
    .expected_len(len)
    .build()
    .unwrap();

    let verified = bounded(
        fetcher(3)
            .unwrap()
            .download(&spec, None, CancellationToken::new()),
    )
    .await
    .expect(NOT_WAITED_OUT)
    .unwrap();

    assert_eq!(
        sha256_of(&tokio::fs::read(verified.path()).await.unwrap()),
        body_sha256(93, len),
    );
    let mut served = server.stats().served_ranges();
    served.sort_by_key(|r| r.start);
    assert_eq!(
        served,
        vec![0..1, 0..8 * MIB, 8 * MIB..len],
        "the re-probe's one byte, then both segments",
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_silent_segment_is_requeued_rather_than_holding_its_connection_slot() {
    // A segment worker holds a global connection slot for as long as its request is in flight. Parked
    // in `send` it holds one forever, so with the slots gone the whole transfer stops - not just the
    // segment. The withheld range is keyed on its own start so the probe is not what absorbs it.
    let dir = tempfile::tempdir().unwrap();
    let dest = dir.path().join("out.bin");
    let len = 16 * MIB;
    let server = ChaosServer::builder(94, len)
        .withhold_range_at(8 * MIB, 1)
        .start()
        .await
        .unwrap();
    let spec = DownloadSpec::builder(
        server.url("f.bin"),
        &dest,
        Validator::Sha256(body_sha256(94, len)),
    )
    .expected_len(len)
    .build()
    .unwrap();

    let verified = bounded(
        fetcher(3)
            .unwrap()
            .download(&spec, None, CancellationToken::new()),
    )
    .await
    .expect(NOT_WAITED_OUT)
    .unwrap();

    assert_eq!(
        sha256_of(&tokio::fs::read(verified.path()).await.unwrap()),
        body_sha256(94, len),
    );
    assert_eq!(
        server
            .stats()
            .requested_starts()
            .iter()
            .filter(|start| **start == 8 * MIB)
            .count(),
        2,
        "the silent segment was asked for again, whole",
    );
    let mut served = server.stats().served_ranges();
    served.sort_by_key(|r| r.start);
    assert_eq!(
        served,
        vec![0..1, 0..8 * MIB, 8 * MIB..len],
        "the requeue re-fetched the segment rather than leaving a hole",
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_silent_host_hands_a_range_fetch_back_instead_of_parking_it() {
    // `fetch_ranges` is deliberately one attempt against one URL, because repair's planner owns the
    // recovery. That only holds if the planner is handed something to recover from: this is the one
    // path with no retry loop of its own to notice a source that answers nothing.
    let server = ChaosServer::builder(95, 64 * 1024)
        .withhold_response(u64::MAX)
        .start()
        .await
        .unwrap();
    let url = server.url("f.bin");
    // Two ranges, so the request is a real packed multi-range ask rather than a lone `206`.
    let ranges = [4096u64..8192, 16384..20480];

    let err = bounded(async {
        fetcher(3)?
            .fetch_ranges(
                &HttpSource::new(url.clone(), 64 * 1024),
                &ranges,
                RangePacking::default(),
                CancellationToken::new(),
                |_, _| Ok(()),
            )
            .await
            .err()
            .ok_or_else(|| Box::<dyn Error>::from("a silent source must not deliver ranges"))
    })
    .await
    .expect(NOT_WAITED_OUT)
    .unwrap();

    match err {
        FetchError::Stalled {
            ref url, at_bytes, ..
        } => {
            assert_eq!(url, &server.url("f.bin"));
            assert_eq!(
                at_bytes, 4096,
                "the request's own first range names the stall"
            );
        }
        other => panic!("got {other:?}"),
    }
    assert_eq!(server.stats().requests(), 1, "one attempt, as documented");
}

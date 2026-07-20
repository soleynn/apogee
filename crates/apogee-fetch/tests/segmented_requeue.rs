//! Lossless segment re-queue and stall detection under concurrency.

use std::time::Duration;

use apogee_fetch::{DownloadSpec, FetchError, Fetcher, Validator};
use apogee_test_support::chaos::{ChaosServer, body_sha256, sha256_of};
use tokio_util::sync::CancellationToken;

const MIB: u64 = 1024 * 1024;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_dropped_segment_re_fetches_only_its_remainder() {
    let dir = tempfile::tempdir().unwrap();
    let dest = dir.path().join("out.bin");
    let len = 24 * MIB;
    // Drop the segment that starts at 8 MiB after it has sent 512 KiB; its remainder re-queues.
    let server = ChaosServer::builder(5, len)
        .drop_range_at(8 * MIB, 512 * 1024)
        .chunk(256 * 1024)
        .start()
        .await
        .unwrap();
    let fetcher = Fetcher::builder()
        .max_connections_per_file(4)
        .build()
        .unwrap();
    let spec = DownloadSpec::builder(
        server.url("f.bin"),
        &dest,
        Validator::Sha256(body_sha256(5, len)),
    )
    .expected_len(len)
    .build()
    .unwrap();

    let verified = fetcher
        .download(&spec, None, CancellationToken::new())
        .await
        .unwrap();
    let bytes = tokio::fs::read(verified.path()).await.unwrap();
    assert_eq!(sha256_of(&bytes), body_sha256(5, len));
    assert!(
        server.stats().bytes_served() < len + 2 * MIB,
        "a re-queue re-fetches only the dropped tail, not the whole file; served {}",
        server.stats().bytes_served(),
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_stalled_segment_recovers_after_re_queue() {
    let dir = tempfile::tempdir().unwrap();
    let dest = dir.path().join("out.bin");
    let len = 24 * MIB;
    // The segment at 8 MiB hangs after 512 KiB (one-shot); the inactivity timeout re-queues it and the
    // retry completes.
    let server = ChaosServer::builder(6, len)
        .stall_range_at(8 * MIB, 512 * 1024)
        .chunk(256 * 1024)
        .start()
        .await
        .unwrap();
    let fetcher = Fetcher::builder()
        .max_connections_per_file(4)
        .stall_timeout(Duration::from_millis(150))
        .build()
        .unwrap();
    let spec = DownloadSpec::builder(
        server.url("f.bin"),
        &dest,
        Validator::Sha256(body_sha256(6, len)),
    )
    .expected_len(len)
    .build()
    .unwrap();

    let verified = fetcher
        .download(&spec, None, CancellationToken::new())
        .await
        .unwrap();
    assert_eq!(
        sha256_of(&tokio::fs::read(verified.path()).await.unwrap()),
        body_sha256(6, len),
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_permanently_slow_segment_fails_as_stalled() {
    let dir = tempfile::tempdir().unwrap();
    let dest = dir.path().join("out.bin");
    let len = 24 * MIB;
    // The segment at 8 MiB never delivers a chunk within the stall window on any attempt, so its retry
    // budget is exhausted and the job fails as stalled.
    let server = ChaosServer::builder(7, len)
        .slow_range(8 * MIB, Duration::from_secs(30))
        .chunk(256 * 1024)
        .start()
        .await
        .unwrap();
    let fetcher = Fetcher::builder()
        .max_connections_per_file(4)
        .stall_timeout(Duration::from_millis(100))
        .build()
        .unwrap();
    let spec = DownloadSpec::builder(
        server.url("f.bin"),
        &dest,
        Validator::Sha256(body_sha256(7, len)),
    )
    .expected_len(len)
    .build()
    .unwrap();

    let err = fetcher
        .download(&spec, None, CancellationToken::new())
        .await
        .unwrap_err();
    assert!(
        matches!(err, FetchError::Stalled { .. }),
        "a segment that never progresses must fail as stalled, got {err:?}",
    );
    assert!(!dest.exists(), "a failed download never publishes");
}

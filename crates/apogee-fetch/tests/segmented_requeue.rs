//! Lossless segment re-queue and stall detection under concurrency.

use std::path::PathBuf;
use std::time::Duration;

use apogee_fetch::{DownloadSpec, FetchError, Fetcher, Progress, Validator};
use apogee_test_support::chaos::{ChaosServer, body_sha256, sha256_of};
use tokio_util::sync::CancellationToken;

const MIB: u64 = 1024 * 1024;

fn apdl_of(dest: &std::path::Path) -> PathBuf {
    let mut name = dest.as_os_str().to_owned();
    name.push(".apdl");
    PathBuf::from(name)
}

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
async fn a_reset_after_the_final_byte_still_completes() {
    // Every segment is served in full and then reset (no clean EOF), so each worker commits all its
    // bytes and then gets an error, returning an EMPTY remainder. Completion must be detected on that
    // path, not only the clean-EOF `Done` path, or the download hangs forever with no worker finishing.
    let dir = tempfile::tempdir().unwrap();
    let dest = dir.path().join("out.bin");
    let len = 24 * MIB;
    let server = ChaosServer::builder(12, len)
        .reset_after_range()
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
        Validator::Sha256(body_sha256(12, len)),
    )
    .expected_len(len)
    .build()
    .unwrap();

    // The timeout turns a regression (a permanent hang) into a failing test rather than a stuck job.
    let verified = tokio::time::timeout(
        Duration::from_secs(20),
        fetcher.download(&spec, None, CancellationToken::new()),
    )
    .await
    .expect("download must complete, not hang on the empty-remainder path")
    .unwrap();
    assert_eq!(
        sha256_of(&tokio::fs::read(verified.path()).await.unwrap()),
        body_sha256(12, len),
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_cancelled_segmented_download_returns_cancelled_and_keeps_the_journal() {
    // A cancel mid-transfer must surface as FetchError::Cancelled and leave the part + journal for a
    // resume, never fall through to publish or delete the journal.
    let dir = tempfile::tempdir().unwrap();
    let dest = dir.path().join("out.bin");
    let len = 24 * MIB;
    let server = ChaosServer::builder(13, len)
        .throttle(Duration::from_millis(1))
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
        Validator::Sha256(body_sha256(13, len)),
    )
    .expected_len(len)
    .build()
    .unwrap();

    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<Progress>();
    let cancel = CancellationToken::new();
    let trigger = cancel.clone();
    let watcher = tokio::spawn(async move {
        while let Some(p) = rx.recv().await {
            if p.bytes_done >= 4 * MIB {
                trigger.cancel();
                break;
            }
        }
    });
    let err = fetcher.download(&spec, Some(tx), cancel).await.unwrap_err();
    watcher.abort();
    let _ = watcher.await;

    assert!(
        matches!(err, FetchError::Cancelled),
        "a cancel must surface as Cancelled, got {err:?}",
    );
    assert!(!dest.exists(), "a cancelled download never publishes");
    assert!(
        apdl_of(&dest).exists(),
        "the journal survives a cancel for resume",
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

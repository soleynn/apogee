//! Cross-process resume of a segmented download: a new fetcher fetches only the gaps.

use std::path::{Path, PathBuf};
use std::time::Duration;

use apogee_fetch::{DownloadSpec, FetchError, Fetcher, Progress, Validator};
use apogee_test_support::chaos::{ChaosServer, body_sha256, sha256_of};
use tokio_util::sync::CancellationToken;

const MIB: u64 = 1024 * 1024;

fn sidecar(dest: &Path, suffix: &str) -> PathBuf {
    let mut name = dest.as_os_str().to_owned();
    name.push(suffix);
    PathBuf::from(name)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn resumes_a_segmented_download_across_a_new_fetcher() {
    let dir = tempfile::tempdir().unwrap();
    let dest = dir.path().join("out.bin");
    let len = 24 * MIB;
    // A small per-chunk delay keeps the transfer in flight long enough to cancel it mid-way.
    let server = ChaosServer::builder(8, len)
        .throttle(Duration::from_millis(1))
        .chunk(256 * 1024)
        .start()
        .await
        .unwrap();
    let spec = DownloadSpec::builder(
        server.url("f.bin"),
        &dest,
        Validator::Sha256(body_sha256(8, len)),
    )
    .expected_len(len)
    .build()
    .unwrap();

    // First fetcher: cancel once a few segments' worth of progress is durable.
    {
        let fetcher = Fetcher::builder()
            .max_connections_per_file(4)
            .build()
            .unwrap();
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<Progress>();
        let cancel = CancellationToken::new();
        let trigger = cancel.clone();
        let watcher = tokio::spawn(async move {
            while let Some(p) = rx.recv().await {
                if p.bytes_done >= 6 * MIB {
                    trigger.cancel();
                    break;
                }
            }
        });
        let _ = fetcher.download(&spec, Some(tx), cancel).await;
        watcher.abort();
        let _ = watcher.await;
    }
    let after_first = server.stats().bytes_served();
    assert!(
        after_first < len,
        "the first attempt was cancelled before completion, served {after_first}",
    );
    assert!(
        sidecar(&dest, ".apdl").exists(),
        "the journal survives a cancel for resume",
    );
    assert!(!dest.exists(), "the cancelled download never published");

    // Second fetcher (fresh caches): resumes and fetches only the missing gaps.
    let fetcher2 = Fetcher::builder()
        .max_connections_per_file(4)
        .build()
        .unwrap();
    let verified = fetcher2
        .download(&spec, None, CancellationToken::new())
        .await
        .unwrap();
    let bytes = tokio::fs::read(verified.path()).await.unwrap();
    assert_eq!(sha256_of(&bytes), body_sha256(8, len));

    let resumed = server.stats().bytes_served() - after_first;
    assert!(
        resumed < len,
        "the resume fetched only the gaps, not the whole file ({resumed} of {len})",
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_source_that_changed_since_the_journal_is_caught_on_resume() {
    let dir = tempfile::tempdir().unwrap();
    let dest = dir.path().join("out.bin");
    let len = 24 * MIB;
    // ETag is "v1" for the first request (the fresh run's probe), then "v2" for everything after, so
    // the resume's If-Range: "v1" no longer matches and the server answers a full 200.
    let server = ChaosServer::builder(10, len)
        .etag("\"v1\"")
        .change_etag_after(1, "\"v2\"")
        .throttle(Duration::from_millis(1))
        .chunk(256 * 1024)
        .start()
        .await
        .unwrap();
    let spec = DownloadSpec::builder(
        server.url("f.bin"),
        &dest,
        Validator::Sha256(body_sha256(10, len)),
    )
    .expected_len(len)
    .build()
    .unwrap();

    // Fresh run: cancel after some progress, leaving a journal that recorded ETag "v1".
    {
        let fetcher = Fetcher::builder()
            .max_connections_per_file(4)
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
        let _ = fetcher.download(&spec, Some(tx), cancel).await;
        watcher.abort();
        let _ = watcher.await;
    }
    assert!(
        sidecar(&dest, ".apdl").exists(),
        "the journal survives the cancel"
    );

    // Resume against the now-changed source: If-Range invalidation surfaces as a changed source, and
    // the stale journal is dropped so a retry restarts clean.
    let fetcher2 = Fetcher::builder()
        .max_connections_per_file(4)
        .build()
        .unwrap();
    let err = fetcher2
        .download(&spec, None, CancellationToken::new())
        .await
        .unwrap_err();
    assert!(
        matches!(err, FetchError::ServerFileChanged { .. }),
        "a changed source on resume must be caught, got {err:?}",
    );
    assert!(
        !sidecar(&dest, ".apdl").exists(),
        "the stale journal is dropped so a retry restarts clean",
    );
}

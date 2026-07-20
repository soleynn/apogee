//! Segmented multi-connection download behavior against the chaos server.

use std::path::{Path, PathBuf};

use apogee_fetch::{DownloadSpec, Fetcher, Validator};
use apogee_test_support::chaos::{ChaosServer, body_sha256, sha256_of};
use tokio_util::sync::CancellationToken;

const MIB: u64 = 1024 * 1024;

fn sidecar(dest: &Path, suffix: &str) -> PathBuf {
    let mut name = dest.as_os_str().to_owned();
    name.push(suffix);
    PathBuf::from(name)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn segmented_download_reassembles_correctly() {
    let dir = tempfile::tempdir().unwrap();
    let dest = dir.path().join("out.bin");
    let len = 24 * MIB;
    let server = ChaosServer::builder(11, len)
        .chunk(256 * 1024)
        .start()
        .await
        .unwrap();
    let spec = DownloadSpec::builder(
        server.url("f.bin"),
        &dest,
        Validator::Sha256(body_sha256(11, len)),
    )
    .expected_len(len)
    .build()
    .unwrap();
    let fetcher = Fetcher::builder()
        .max_connections_per_file(4)
        .build()
        .unwrap();

    // Submit as a job and drain its progress stream, exercising the Job handle.
    let mut job = fetcher.submit(spec);
    let mut progress = job.progress().into_inner();
    let watcher = tokio::spawn(async move {
        let mut last = 0;
        while let Some(p) = progress.recv().await {
            assert!(p.bytes_done >= last, "progress must be monotonic");
            last = p.bytes_done;
        }
        last
    });
    let verified = job.await.unwrap();
    let last = watcher.await.unwrap();

    assert_eq!(verified.path(), dest);
    let bytes = tokio::fs::read(&dest).await.unwrap();
    assert_eq!(bytes.len() as u64, len);
    assert_eq!(sha256_of(&bytes), body_sha256(11, len));
    assert_eq!(last, len, "the final progress reaches the full length");
    assert!(
        server.stats().peak_concurrency() >= 2,
        "segmentation must open concurrent connections, saw {}",
        server.stats().peak_concurrency(),
    );
    assert!(!sidecar(&dest, ".part").exists(), "the part file is gone");
    assert!(!sidecar(&dest, ".apdl").exists(), "the journal is gone");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn demotes_to_single_connection_and_caches_the_verdict() {
    let dir = tempfile::tempdir().unwrap();
    let dest = dir.path().join("out.bin");
    let dest2 = dir.path().join("out2.bin");
    let len = 24 * MIB;
    // A server that ignores Range: the probe sees a 200 and the job demotes to one connection.
    let server = ChaosServer::builder(4, len)
        .accept_ranges(false)
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
        Validator::Sha256(body_sha256(4, len)),
    )
    .expected_len(len)
    .build()
    .unwrap();
    fetcher
        .download(&spec, None, CancellationToken::new())
        .await
        .unwrap();
    assert_eq!(
        server.stats().requests(),
        2,
        "the first job probes once, then streams on a single connection",
    );

    // A second job to the same host reuses the cached demotion: no second probe.
    let spec2 = DownloadSpec::builder(
        server.url("f.bin"),
        &dest2,
        Validator::Sha256(body_sha256(4, len)),
    )
    .expected_len(len)
    .build()
    .unwrap();
    fetcher
        .download(&spec2, None, CancellationToken::new())
        .await
        .unwrap();
    assert_eq!(
        server.stats().requests(),
        3,
        "the cached verdict skips the probe on the second job",
    );

    assert_eq!(
        sha256_of(&tokio::fs::read(&dest).await.unwrap()),
        body_sha256(4, len),
    );
}

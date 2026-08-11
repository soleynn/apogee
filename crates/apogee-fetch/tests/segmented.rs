//! Segmented multi-connection download behavior against the chaos server.

use std::path::{Path, PathBuf};

use apogee_fetch::{DownloadSpec, FetchError, Fetcher, Validator};
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
    let mut progress = job.progress();
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

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_transfer_of_unknown_length_stays_on_one_connection() {
    // Dispatch takes the single-connection path on an undeclared length before it probes anything, so
    // a source that would happily serve ranges is never asked to. That ordering is a decision, not an
    // oversight: splitting a transfer is worth several times the throughput only over HTTP/1.1 with a
    // socket per segment, and every source whose length the caller cannot declare negotiates h2, where
    // the segments would be streams on one connection sharing one congestion window. Probing first
    // would buy that nothing and would cost a round trip on every small download that makes exactly
    // one request today.
    //
    // The fixture speaks HTTP/1.1, which is what makes it a fair test of the *ordering* rather than of
    // the protocol: it is the case where segmenting would pay, and the transfer still must not. A
    // future source that both ignores h2 and hides its length is the thing that should reopen this,
    // and it now has to do so by editing this test.
    //
    // Both halves are the same server, the same fetcher settings and the same bytes. Only the declared
    // length differs, because "one request" proves nothing on its own: the second half is what shows
    // this setup segments at all.
    let dir = tempfile::tempdir().unwrap();
    let len = 32 * MIB; // four segments at the cap below, well clear of the 8 MiB floor
    let settings = || Fetcher::builder().max_connections_per_file(4).build();

    let undeclared = ChaosServer::builder(12, len)
        .chunk(256 * 1024)
        .start()
        .await
        .unwrap();
    let dest = dir.path().join("undeclared.bin");
    let spec = DownloadSpec::builder(
        undeclared.url("f.bin"),
        &dest,
        Validator::Sha256(body_sha256(12, len)),
    )
    .build()
    .unwrap();
    settings()
        .unwrap()
        .download(&spec, None, CancellationToken::new())
        .await
        .unwrap();

    assert_eq!(
        sha256_of(&tokio::fs::read(&dest).await.unwrap()),
        body_sha256(12, len),
    );
    assert_eq!(
        undeclared.stats().requests(),
        1,
        "one whole-body request: no capability probe, and no segment asked for",
    );
    assert_eq!(
        undeclared.stats().peak_concurrency(),
        1,
        "the transfer never opened a second connection",
    );
    assert_eq!(
        undeclared.stats().served_ranges(),
        vec![0..len],
        "the body arrived in one piece rather than in segments",
    );

    // The contrast: declare the length and the identical setup fans out.
    let declared = ChaosServer::builder(12, len)
        .chunk(256 * 1024)
        .start()
        .await
        .unwrap();
    let dest = dir.path().join("declared.bin");
    let spec = DownloadSpec::builder(
        declared.url("f.bin"),
        &dest,
        Validator::Sha256(body_sha256(12, len)),
    )
    .expected_len(len)
    .build()
    .unwrap();
    settings()
        .unwrap()
        .download(&spec, None, CancellationToken::new())
        .await
        .unwrap();

    assert_eq!(
        sha256_of(&tokio::fs::read(&dest).await.unwrap()),
        body_sha256(12, len),
    );
    assert_eq!(
        declared.stats().requests(),
        5,
        "the probe plus one request per segment",
    );
    assert!(
        declared.stats().peak_concurrency() >= 2,
        "the declared-length transfer segmented, saw {}",
        declared.stats().peak_concurrency(),
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_server_length_that_disagrees_fails_before_publishing() {
    // The origin serves 24 MiB but the spec expects 20 MiB. The segment's Content-Range total exposes
    // the disagreement, so the transfer fails with LengthMismatch instead of minting a truncated file.
    let dir = tempfile::tempdir().unwrap();
    let dest = dir.path().join("out.bin");
    let server_len = 24 * MIB;
    let expected = 20 * MIB;
    let server = ChaosServer::builder(9, server_len)
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
        Validator::Sha256(body_sha256(9, expected)),
    )
    .expected_len(expected)
    .build()
    .unwrap();

    let err = fetcher
        .download(&spec, None, CancellationToken::new())
        .await
        .unwrap_err();
    assert!(
        matches!(err, FetchError::LengthMismatch { expected: e, got: g } if e == expected && g == server_len),
        "expected LengthMismatch, got {err:?}",
    );
    assert!(
        !dest.exists(),
        "a length-mismatched download never publishes"
    );
}

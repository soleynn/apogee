//! End-to-end download behavior against the streaming chaos server.
//!
//! Integration tests live outside the crate so they exercise the same public surface a real consumer
//! sees. Each drives the [`Fetcher`] against a scripted [`ChaosServer`] and asserts the file lands
//! byte-identical, an interruption resumes, a changed source restarts cleanly, and the refusals fire
//! before any bytes move.

use std::path::{Path, PathBuf};
use std::time::Duration;

use apogee_fetch::{DownloadSpec, DownloadSpecBuilder, FetchError, Fetcher, Validator};
use apogee_test_support::chaos::{ChaosServer, block_hashes, body_sha256, generated_vec, sha256_of};
use tokio_util::sync::CancellationToken;

const MIB: u64 = 1024 * 1024;

fn sidecar(dest: &Path, suffix: &str) -> PathBuf {
    let mut name = dest.as_os_str().to_owned();
    name.push(suffix);
    PathBuf::from(name)
}

/// A verified-Sha256 spec builder for `len` bytes from `seed`, served by `server`.
fn spec_builder(server: &ChaosServer, dest: &Path, seed: u64, len: u64) -> DownloadSpecBuilder {
    DownloadSpec::builder(
        server.url("file.bin"),
        dest,
        Validator::Sha256(body_sha256(seed, len)),
    )
    .expected_len(len)
}

#[tokio::test]
async fn downloads_verifies_and_publishes() {
    let dir = tempfile::tempdir().unwrap();
    let dest = dir.path().join("out.bin");
    let len = 300_000;
    let server = ChaosServer::builder(11, len).start().await.unwrap();
    let spec = spec_builder(&server, &dest, 11, len).build().unwrap();

    let verified = Fetcher::builder()
        .build()
        .unwrap()
        .download(&spec, None, CancellationToken::new())
        .await
        .unwrap();

    assert_eq!(verified.path(), dest);
    assert_eq!(
        tokio::fs::read(&dest).await.unwrap(),
        generated_vec(11, 0, len as usize)
    );
    assert!(!sidecar(&dest, ".part").exists(), "the part file is gone");
    assert!(!sidecar(&dest, ".apdl").exists(), "the journal is gone");
}

#[tokio::test]
async fn a_content_length_that_disagrees_fails_before_writing() {
    let dir = tempfile::tempdir().unwrap();
    let dest = dir.path().join("out.bin");
    let server = ChaosServer::builder(1, 1000).start().await.unwrap();
    let spec = DownloadSpec::builder(
        server.url("file.bin"),
        &dest,
        Validator::Sha256(body_sha256(1, 2000)),
    )
    .expected_len(2000)
    .build()
    .unwrap();

    let err = Fetcher::builder()
        .build()
        .unwrap()
        .download(&spec, None, CancellationToken::new())
        .await
        .unwrap_err();

    assert!(matches!(
        err,
        FetchError::LengthMismatch {
            expected: 2000,
            got: 1000
        }
    ));
    assert!(!dest.exists());
}

#[tokio::test]
async fn a_wrong_hash_is_a_verify_failure_that_keeps_the_part() {
    let dir = tempfile::tempdir().unwrap();
    let dest = dir.path().join("out.bin");
    let len = 4096;
    let server = ChaosServer::builder(3, len).start().await.unwrap();
    // Claim the hash of a different body; the bytes arrive fine but fail verification.
    let spec = DownloadSpec::builder(
        server.url("file.bin"),
        &dest,
        Validator::Sha256(body_sha256(999, len)),
    )
    .expected_len(len)
    .build()
    .unwrap();

    let err = Fetcher::builder()
        .build()
        .unwrap()
        .download(&spec, None, CancellationToken::new())
        .await
        .unwrap_err();

    assert!(matches!(err, FetchError::FileVerifyFailed { .. }));
    assert!(
        !dest.exists(),
        "an unverified file never reaches the destination"
    );
    assert!(
        sidecar(&dest, ".part").exists(),
        "the part file is kept for triage"
    );
}

#[tokio::test]
async fn a_dropped_connection_resumes_from_the_journal() {
    let dir = tempfile::tempdir().unwrap();
    let dest = dir.path().join("out.bin");
    let len = 4 * MIB;
    let server = ChaosServer::builder(5, len)
        .etag("\"v1\"")
        .drop_after(2_500_000)
        .chunk(64 * 1024)
        .start()
        .await
        .unwrap();
    let spec = spec_builder(&server, &dest, 5, len).build().unwrap();
    let downloader = Fetcher::builder().build().unwrap();

    let err = downloader
        .download(&spec, None, CancellationToken::new())
        .await
        .unwrap_err();
    assert!(matches!(err, FetchError::Transport { .. }));
    assert!(!dest.exists());

    let verified = downloader
        .download(&spec, None, CancellationToken::new())
        .await
        .unwrap();
    let bytes = tokio::fs::read(verified.path()).await.unwrap();
    assert_eq!(bytes.len() as u64, len);
    assert_eq!(sha256_of(&bytes), body_sha256(5, len));
    assert!(
        server.stats().bytes_served() < 2 * len,
        "a resume must not re-download the whole file"
    );
}

#[tokio::test]
async fn a_changed_etag_restarts_cleanly_and_still_verifies() {
    let dir = tempfile::tempdir().unwrap();
    let dest = dir.path().join("out.bin");
    let len = 4 * MIB;
    // First request drops after a committed batch; the resume's If-Range no longer matches, so the
    // server answers 200 and the download must restart from zero rather than append at the watermark.
    let server = ChaosServer::builder(9, len)
        .etag("\"v1\"")
        .change_etag_after(1, "\"v2\"")
        .drop_after(2 * MIB)
        .chunk(64 * 1024)
        .start()
        .await
        .unwrap();
    let spec = spec_builder(&server, &dest, 9, len).build().unwrap();
    let downloader = Fetcher::builder().build().unwrap();

    downloader
        .download(&spec, None, CancellationToken::new())
        .await
        .unwrap_err();
    let verified = downloader
        .download(&spec, None, CancellationToken::new())
        .await
        .unwrap();

    let bytes = tokio::fs::read(verified.path()).await.unwrap();
    assert_eq!(sha256_of(&bytes), body_sha256(9, len));
}

#[tokio::test]
async fn a_server_that_ignores_range_on_resume_restarts_cleanly() {
    let dir = tempfile::tempdir().unwrap();
    let dest = dir.path().join("out.bin");
    let len = 4 * MIB;
    // Ranges are refused entirely: the first response is a 200 that drops, and the resume's Range is
    // ignored (another 200), so the engine must fall back to a clean restart without corrupting offsets.
    let server = ChaosServer::builder(4, len)
        .accept_ranges(false)
        .drop_after(2 * MIB)
        .chunk(64 * 1024)
        .start()
        .await
        .unwrap();
    let spec = spec_builder(&server, &dest, 4, len).build().unwrap();
    let downloader = Fetcher::builder().build().unwrap();

    downloader
        .download(&spec, None, CancellationToken::new())
        .await
        .unwrap_err();
    let verified = downloader
        .download(&spec, None, CancellationToken::new())
        .await
        .unwrap();

    let bytes = tokio::fs::read(verified.path()).await.unwrap();
    assert_eq!(sha256_of(&bytes), body_sha256(4, len));
}

#[tokio::test]
async fn a_cancelled_download_resumes_to_completion() {
    let dir = tempfile::tempdir().unwrap();
    let dest = dir.path().join("out.bin");
    let len = 4 * MIB;
    let server = ChaosServer::builder(6, len)
        .etag("\"v1\"")
        .throttle(Duration::from_millis(2))
        .chunk(64 * 1024)
        .start()
        .await
        .unwrap();
    let spec = spec_builder(&server, &dest, 6, len).build().unwrap();
    let downloader = Fetcher::builder().build().unwrap();

    let cancel = CancellationToken::new();
    let trigger = cancel.clone();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(25)).await;
        trigger.cancel();
    });
    let err = downloader.download(&spec, None, cancel).await.unwrap_err();
    assert!(matches!(err, FetchError::Cancelled));
    assert!(!dest.exists());

    let verified = downloader
        .download(&spec, None, CancellationToken::new())
        .await
        .unwrap();
    let bytes = tokio::fs::read(verified.path()).await.unwrap();
    assert_eq!(sha256_of(&bytes), body_sha256(6, len));
}

#[tokio::test]
async fn an_existing_destination_is_returned_without_a_request() {
    let dir = tempfile::tempdir().unwrap();
    let dest = dir.path().join("out.bin");
    let len = 1000;
    tokio::fs::write(&dest, generated_vec(2, 0, len as usize))
        .await
        .unwrap();
    let server = ChaosServer::builder(2, len).start().await.unwrap();
    let spec = spec_builder(&server, &dest, 2, len).build().unwrap();

    let verified = Fetcher::builder()
        .build()
        .unwrap()
        .download(&spec, None, CancellationToken::new())
        .await
        .unwrap();

    assert_eq!(verified.path(), dest);
    assert_eq!(
        server.stats().requests(),
        0,
        "an existing file skips the network"
    );
}

#[tokio::test]
async fn a_block_hashed_download_verifies_and_publishes() {
    let dir = tempfile::tempdir().unwrap();
    let dest = dir.path().join("out.bin");
    let len = 300_000u64;
    let block_size = 100_000u32; // three blocks
    let server = ChaosServer::builder(3, len).start().await.unwrap();
    let spec = DownloadSpec::builder(
        server.url("file.bin"),
        &dest,
        Validator::BlockSha1 {
            block_size,
            hashes: block_hashes(3, len, block_size),
        },
    )
    .expected_len(len)
    .build()
    .unwrap();

    let verified = Fetcher::builder()
        .build()
        .unwrap()
        .download(&spec, None, CancellationToken::new())
        .await
        .unwrap();

    assert_eq!(verified.path(), dest);
    assert_eq!(
        tokio::fs::read(&dest).await.unwrap(),
        generated_vec(3, 0, len as usize)
    );
    assert!(!sidecar(&dest, ".part").exists(), "the part file is gone");
    assert!(!sidecar(&dest, ".apdl").exists(), "the journal is gone");
}

#[tokio::test]
async fn a_persistently_corrupt_block_fails_after_exhausting_its_retries() {
    let dir = tempfile::tempdir().unwrap();
    let dest = dir.path().join("out.bin");
    let len = 300_000u64;
    let block_size = 100_000u32; // three blocks; the middle one is always corrupt
    let server = ChaosServer::builder(5, len)
        .corrupt_range(100_000..200_000)
        .start()
        .await
        .unwrap();
    let spec = DownloadSpec::builder(
        server.url("file.bin"),
        &dest,
        Validator::BlockSha1 {
            block_size,
            hashes: block_hashes(5, len, block_size),
        },
    )
    .expected_len(len)
    .build()
    .unwrap();

    let err = Fetcher::builder()
        .build()
        .unwrap()
        .download(&spec, None, CancellationToken::new())
        .await
        .unwrap_err();

    assert!(
        matches!(
            err,
            FetchError::BlockVerifyFailed {
                block: 1,
                offset: 100_000,
                ..
            }
        ),
        "got {err:?}"
    );
    assert!(!dest.exists(), "no verified file is published");
    assert!(
        !sidecar(&dest, ".apdl").exists(),
        "the journal is dropped on failure"
    );
}

#[tokio::test]
async fn resume_disabled_writes_no_journal_and_restarts_from_zero() {
    let dir = tempfile::tempdir().unwrap();
    let dest = dir.path().join("out.bin");
    let len = 4 * MIB;
    let server = ChaosServer::builder(7, len)
        .etag("\"v1\"")
        .drop_after(2 * MIB)
        .chunk(64 * 1024)
        .start()
        .await
        .unwrap();
    let spec = spec_builder(&server, &dest, 7, len)
        .resume(false)
        .build()
        .unwrap();
    let downloader = Fetcher::builder().build().unwrap();

    downloader
        .download(&spec, None, CancellationToken::new())
        .await
        .unwrap_err();
    assert!(
        !sidecar(&dest, ".apdl").exists(),
        "a disabled resume never writes a journal"
    );

    let verified = downloader
        .download(&spec, None, CancellationToken::new())
        .await
        .unwrap();
    let bytes = tokio::fs::read(verified.path()).await.unwrap();
    assert_eq!(sha256_of(&bytes), body_sha256(7, len));
    assert!(!sidecar(&dest, ".apdl").exists());
    assert!(
        server.stats().bytes_served() > len,
        "a disabled resume re-fetches the dropped prefix from zero"
    );
}

#[tokio::test]
async fn a_part_shorter_than_the_watermark_restarts_from_zero() {
    let dir = tempfile::tempdir().unwrap();
    let dest = dir.path().join("out.bin");
    let len = 4 * MIB;
    let server = ChaosServer::builder(8, len)
        .etag("\"v1\"")
        .drop_after(2 * MIB)
        .chunk(64 * 1024)
        .start()
        .await
        .unwrap();
    let spec = spec_builder(&server, &dest, 8, len).build().unwrap();
    let downloader = Fetcher::builder().build().unwrap();

    downloader
        .download(&spec, None, CancellationToken::new())
        .await
        .unwrap_err();
    let part = sidecar(&dest, ".part");
    assert!(part.exists() && sidecar(&dest, ".apdl").exists());
    // Truncate the part below the journaled watermark: the resume must distrust it and restart.
    let handle = std::fs::OpenOptions::new().write(true).open(&part).unwrap();
    handle.set_len(1024).unwrap();
    drop(handle);

    let verified = downloader
        .download(&spec, None, CancellationToken::new())
        .await
        .unwrap();
    let bytes = tokio::fs::read(verified.path()).await.unwrap();
    assert_eq!(sha256_of(&bytes), body_sha256(8, len));
}

#[tokio::test]
async fn a_range_not_satisfiable_response_restarts_and_completes() {
    let dir = tempfile::tempdir().unwrap();
    let dest = dir.path().join("out.bin");
    let len = 4 * MIB;
    // The first (rangeless) request drops; the resume's ranged request gets 416, so the engine must
    // reset and re-request from zero within the same download call.
    let server = ChaosServer::builder(3, len)
        .etag("\"v1\"")
        .drop_after(2 * MIB)
        .range_not_satisfiable(true)
        .chunk(64 * 1024)
        .start()
        .await
        .unwrap();
    let spec = spec_builder(&server, &dest, 3, len).build().unwrap();
    let downloader = Fetcher::builder().build().unwrap();

    downloader
        .download(&spec, None, CancellationToken::new())
        .await
        .unwrap_err();
    let verified = downloader
        .download(&spec, None, CancellationToken::new())
        .await
        .unwrap();
    let bytes = tokio::fs::read(verified.path()).await.unwrap();
    assert_eq!(sha256_of(&bytes), body_sha256(3, len));
}

#[tokio::test]
async fn resume_uses_last_modified_when_no_etag_is_offered() {
    let dir = tempfile::tempdir().unwrap();
    let dest = dir.path().join("out.bin");
    let len = 4 * MIB;
    let server = ChaosServer::builder(5, len)
        .last_modified("Wed, 21 Oct 2025 07:28:00 GMT")
        .drop_after(2 * MIB)
        .chunk(64 * 1024)
        .start()
        .await
        .unwrap();
    let spec = spec_builder(&server, &dest, 5, len).build().unwrap();
    let downloader = Fetcher::builder().build().unwrap();

    downloader
        .download(&spec, None, CancellationToken::new())
        .await
        .unwrap_err();
    let verified = downloader
        .download(&spec, None, CancellationToken::new())
        .await
        .unwrap();
    let bytes = tokio::fs::read(verified.path()).await.unwrap();
    assert_eq!(sha256_of(&bytes), body_sha256(5, len));
    assert!(
        server.stats().bytes_served() < 2 * len,
        "a Last-Modified If-Range should resume, not restart"
    );
}

#[tokio::test]
async fn a_changed_last_modified_restarts_cleanly() {
    let dir = tempfile::tempdir().unwrap();
    let dest = dir.path().join("out.bin");
    let len = 4 * MIB;
    let server = ChaosServer::builder(6, len)
        .last_modified("Wed, 21 Oct 2025 07:28:00 GMT")
        .change_last_modified_after(1, "Thu, 22 Oct 2025 07:28:00 GMT")
        .drop_after(2 * MIB)
        .chunk(64 * 1024)
        .start()
        .await
        .unwrap();
    let spec = spec_builder(&server, &dest, 6, len).build().unwrap();
    let downloader = Fetcher::builder().build().unwrap();

    downloader
        .download(&spec, None, CancellationToken::new())
        .await
        .unwrap_err();
    let verified = downloader
        .download(&spec, None, CancellationToken::new())
        .await
        .unwrap();
    let bytes = tokio::fs::read(verified.path()).await.unwrap();
    assert_eq!(sha256_of(&bytes), body_sha256(6, len));
}

#[tokio::test]
async fn a_wrong_size_destination_is_re_downloaded() {
    let dir = tempfile::tempdir().unwrap();
    let dest = dir.path().join("out.bin");
    let len = 1000;
    tokio::fs::write(&dest, vec![0u8; 500]).await.unwrap();
    let server = ChaosServer::builder(2, len).start().await.unwrap();
    let spec = spec_builder(&server, &dest, 2, len).build().unwrap();

    let verified = Fetcher::builder()
        .build()
        .unwrap()
        .download(&spec, None, CancellationToken::new())
        .await
        .unwrap();

    assert!(
        server.stats().requests() > 0,
        "a wrong-size destination is not trusted"
    );
    assert_eq!(
        sha256_of(&tokio::fs::read(verified.path()).await.unwrap()),
        body_sha256(2, len)
    );
}

#[tokio::test]
async fn a_same_size_wrong_content_destination_is_re_downloaded() {
    let dir = tempfile::tempdir().unwrap();
    let dest = dir.path().join("out.bin");
    let len = 1000;
    // Right size, wrong bytes: the skip must re-hash and reject it, never mint a proof on length alone.
    tokio::fs::write(&dest, generated_vec(999, 0, len as usize))
        .await
        .unwrap();
    let server = ChaosServer::builder(2, len).start().await.unwrap();
    let spec = spec_builder(&server, &dest, 2, len).build().unwrap();

    let verified = Fetcher::builder()
        .build()
        .unwrap()
        .download(&spec, None, CancellationToken::new())
        .await
        .unwrap();

    assert!(
        server.stats().requests() > 0,
        "a same-size wrong-content destination is re-hashed and re-downloaded, not trusted"
    );
    assert_eq!(
        sha256_of(&tokio::fs::read(verified.path()).await.unwrap()),
        body_sha256(2, len)
    );
}

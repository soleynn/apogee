//! End-to-end download behavior against the streaming chaos server.
//!
//! Integration tests live outside the crate so they exercise the same public surface a real consumer
//! sees. Each drives the [`Fetcher`] against a scripted [`ChaosServer`] and asserts the file lands
//! byte-identical, an interruption resumes, a changed source restarts cleanly, and the refusals fire
//! before any bytes move.

use std::path::{Path, PathBuf};
use std::time::Duration;

use apogee_fetch::{DownloadSpec, DownloadSpecBuilder, FetchError, Fetcher, Validator};
use apogee_test_support::chaos::{ChaosServer, generate_into, generated_vec};
use sha2::{Digest, Sha256};
use tokio_util::sync::CancellationToken;

const MIB: u64 = 1024 * 1024;

/// The SHA256 of the deterministic body, streamed so a large expectation is never materialized.
fn body_sha256(seed: u64, len: u64) -> [u8; 32] {
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 64 * 1024];
    let mut off = 0u64;
    while off < len {
        let want = (len - off).min(buf.len() as u64) as usize;
        generate_into(seed, off, &mut buf[..want]);
        hasher.update(&buf[..want]);
        off += want as u64;
    }
    finalize(hasher)
}

fn finalize(hasher: Sha256) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(&hasher.finalize());
    out
}

/// The SHA256 of a byte slice.
fn sha256_of(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    finalize(hasher)
}

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
    assert!(matches!(err, FetchError::Connect { .. }));
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
async fn block_hash_validation_is_rejected_before_any_request() {
    let dir = tempfile::tempdir().unwrap();
    let dest = dir.path().join("out.bin");
    let server = ChaosServer::builder(1, 1000).start().await.unwrap();
    let spec = DownloadSpec::builder(
        server.url("file.bin"),
        &dest,
        Validator::BlockSha1 {
            block_size: 256,
            hashes: vec![[0; 20]],
        },
    )
    .build()
    .unwrap();

    let err = Fetcher::builder()
        .build()
        .unwrap()
        .download(&spec, None, CancellationToken::new())
        .await
        .unwrap_err();

    assert!(matches!(err, FetchError::Unsupported { .. }));
    assert_eq!(server.stats().requests(), 0);
}

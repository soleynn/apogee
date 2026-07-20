//! Per-block SHA1 verification end to end: a block-hashed download verifies while it streams,
//! re-fetches only a dirty block, rotates to a mirror on repeated failure, honors the patch header
//! policy, and falls back to a whole-file block check when the host ignores ranges.

use std::time::Duration;

use apogee_fetch::{DownloadSpec, FetchError, Fetcher, HeaderPolicy, Validator};
use apogee_test_support::chaos::{ChaosServer, generated_vec};
use sha1::{Digest, Sha1};
use tokio_util::sync::CancellationToken;

const MIB: u64 = 1024 * 1024;
/// The one byte a `bytes=0-0` range-capability probe serves before the transfer starts.
const PROBE: u64 = 1;

/// The per-block SHA1s of the generated body: one hash per `block_size` bytes, the last block short.
fn block_hashes(seed: u64, len: u64, block_size: u32) -> Vec<[u8; 20]> {
    generated_vec(seed, 0, len as usize)
        .chunks(block_size as usize)
        .map(|chunk| {
            let mut hasher = Sha1::new();
            hasher.update(chunk);
            hasher.finalize().into()
        })
        .collect()
}

/// A `BlockSha1` spec for `len` bytes from `seed`, verified at `block_size`, served by `server`.
fn block_spec(
    server: &ChaosServer,
    dest: &std::path::Path,
    seed: u64,
    len: u64,
    block_size: u32,
) -> DownloadSpec {
    DownloadSpec::builder(
        server.url("f.bin"),
        dest,
        Validator::BlockSha1 {
            block_size,
            hashes: block_hashes(seed, len, block_size),
        },
    )
    .expected_len(len)
    .build()
    .unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_multi_block_multi_segment_download_verifies_and_publishes() {
    let dir = tempfile::tempdir().unwrap();
    let dest = dir.path().join("out.bin");
    let (len, block_size) = (48 * MIB, 4 * MIB as u32); // twelve blocks across four segments
    let server = ChaosServer::builder(21, len).start().await.unwrap();
    let spec = block_spec(&server, &dest, 21, len, block_size);
    let fetcher = Fetcher::builder().max_connections_per_file(4).build().unwrap();

    let verified = fetcher
        .download(&spec, None, CancellationToken::new())
        .await
        .unwrap();

    assert_eq!(verified.path(), dest);
    assert_eq!(
        tokio::fs::read(&dest).await.unwrap(),
        generated_vec(21, 0, len as usize)
    );
    // Nothing was corrupt, so the file is served exactly once (plus the capability probe byte).
    assert_eq!(server.stats().bytes_served(), len + PROBE);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn only_the_dirty_block_is_re_fetched_then_verifies() {
    let dir = tempfile::tempdir().unwrap();
    let dest = dir.path().join("out.bin");
    let (len, block_size) = (48 * MIB, 4 * MIB as u32);
    // Block 5 spans [20 MiB, 24 MiB); corrupt it on the first serve only, so its re-fetch is clean.
    let server = ChaosServer::builder(22, len)
        .corrupt_range_once(20 * MIB..24 * MIB)
        .start()
        .await
        .unwrap();
    let spec = block_spec(&server, &dest, 22, len, block_size);
    let fetcher = Fetcher::builder().max_connections_per_file(4).build().unwrap();

    let verified = fetcher
        .download(&spec, None, CancellationToken::new())
        .await
        .unwrap();

    assert_eq!(
        tokio::fs::read(verified.path()).await.unwrap(),
        generated_vec(22, 0, len as usize)
    );
    // Byte-accounted repair: the whole file once, plus exactly the one dirty block re-served (and the
    // capability probe byte). No other range is re-fetched.
    assert_eq!(
        server.stats().bytes_served(),
        len + u64::from(block_size) + PROBE,
        "only the dirty block is re-fetched"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_block_that_spans_two_segments_verifies() {
    let dir = tempfile::tempdir().unwrap();
    let dest = dir.path().join("out.bin");
    // block_size (24 MiB) larger than seg_size (48/4 = 12 MiB): each block spans two segments.
    let (len, block_size) = (48 * MIB, 24 * MIB as u32);
    let server = ChaosServer::builder(23, len).start().await.unwrap();
    let spec = block_spec(&server, &dest, 23, len, block_size);
    let fetcher = Fetcher::builder().max_connections_per_file(4).build().unwrap();

    let verified = fetcher
        .download(&spec, None, CancellationToken::new())
        .await
        .unwrap();
    assert_eq!(
        tokio::fs::read(verified.path()).await.unwrap(),
        generated_vec(23, 0, len as usize)
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_short_final_block_verifies() {
    let dir = tempfile::tempdir().unwrap();
    let dest = dir.path().join("out.bin");
    // 50 MiB at a 16 MiB block: three full blocks and a 2 MiB tail.
    let (len, block_size) = (50 * MIB, 16 * MIB as u32);
    let server = ChaosServer::builder(24, len).start().await.unwrap();
    let spec = block_spec(&server, &dest, 24, len, block_size);
    let fetcher = Fetcher::builder().max_connections_per_file(4).build().unwrap();

    let verified = fetcher
        .download(&spec, None, CancellationToken::new())
        .await
        .unwrap();
    assert_eq!(
        tokio::fs::read(verified.path()).await.unwrap(),
        generated_vec(24, 0, len as usize)
    );
}

#[tokio::test]
async fn a_single_block_file_verifies() {
    let dir = tempfile::tempdir().unwrap();
    let dest = dir.path().join("out.bin");
    let len = 40_000u64; // smaller than one block
    let block_size = 64 * 1024u32;
    let server = ChaosServer::builder(25, len).start().await.unwrap();
    let spec = block_spec(&server, &dest, 25, len, block_size);

    let verified = Fetcher::builder()
        .build()
        .unwrap()
        .download(&spec, None, CancellationToken::new())
        .await
        .unwrap();
    assert_eq!(
        tokio::fs::read(verified.path()).await.unwrap(),
        generated_vec(25, 0, len as usize)
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_killed_block_download_resumes_and_verifies() {
    let dir = tempfile::tempdir().unwrap();
    let dest = dir.path().join("out.bin");
    let (len, block_size) = (16 * MIB, 4 * MIB as u32);
    let server = ChaosServer::builder(26, len)
        .etag("\"v1\"")
        .throttle(Duration::from_millis(2))
        .chunk(64 * 1024)
        .start()
        .await
        .unwrap();
    let spec = block_spec(&server, &dest, 26, len, block_size);
    let fetcher = Fetcher::builder().max_connections_per_file(4).build().unwrap();

    // Cancel mid-download, so some blocks are durable but the file is not yet complete.
    let cancel = CancellationToken::new();
    let trigger = cancel.clone();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(25)).await;
        trigger.cancel();
    });
    let err = fetcher.download(&spec, None, cancel).await.unwrap_err();
    assert!(matches!(err, FetchError::Cancelled));
    assert!(!dest.exists());

    // Resuming re-hashes the durable blocks from disk and fetches only the rest.
    let verified = fetcher
        .download(&spec, None, CancellationToken::new())
        .await
        .unwrap();
    assert_eq!(
        tokio::fs::read(verified.path()).await.unwrap(),
        generated_vec(26, 0, len as usize)
    );
}

#[tokio::test]
async fn a_range_ignoring_host_verifies_blocks_from_disk() {
    let dir = tempfile::tempdir().unwrap();
    let dest = dir.path().join("out.bin");
    let (len, block_size) = (2 * MIB, 512 * 1024u32);
    let server = ChaosServer::builder(27, len)
        .accept_ranges(false)
        .start()
        .await
        .unwrap();
    let spec = block_spec(&server, &dest, 27, len, block_size);

    let verified = Fetcher::builder()
        .build()
        .unwrap()
        .download(&spec, None, CancellationToken::new())
        .await
        .unwrap();
    assert_eq!(
        tokio::fs::read(verified.path()).await.unwrap(),
        generated_vec(27, 0, len as usize)
    );
}

#[tokio::test]
async fn a_range_ignoring_host_rejects_a_corrupt_block() {
    let dir = tempfile::tempdir().unwrap();
    let dest = dir.path().join("out.bin");
    let (len, block_size) = (2 * MIB, 512 * 1024u32);
    // Second block [512 KiB, 1 MiB) is corrupt; without ranges it cannot be repaired.
    let server = ChaosServer::builder(28, len)
        .accept_ranges(false)
        .corrupt_range(512 * 1024..MIB)
        .start()
        .await
        .unwrap();
    let spec = block_spec(&server, &dest, 28, len, block_size);

    let err = Fetcher::builder()
        .build()
        .unwrap()
        .download(&spec, None, CancellationToken::new())
        .await
        .unwrap_err();
    assert!(
        matches!(err, FetchError::BlockVerifyFailed { block: 1, offset, .. } if offset == 512 * 1024),
        "got {err:?}"
    );
    assert!(!dest.exists());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_se_patch_header_policy_is_sent_on_every_request() {
    let dir = tempfile::tempdir().unwrap();
    let dest = dir.path().join("out.bin");
    let (len, block_size) = (48 * MIB, 4 * MIB as u32);
    let server = ChaosServer::builder(29, len).start().await.unwrap();
    let spec = DownloadSpec::builder(
        server.url("f.bin"),
        &dest,
        Validator::BlockSha1 {
            block_size,
            hashes: block_hashes(29, len, block_size),
        },
    )
    .expected_len(len)
    .header_policy(HeaderPolicy::SePatch {
        unique_id: Some("unique-123".to_owned()),
    })
    .build()
    .unwrap();
    let fetcher = Fetcher::builder().max_connections_per_file(4).build().unwrap();

    fetcher
        .download(&spec, None, CancellationToken::new())
        .await
        .unwrap();

    let user_agents = server.stats().user_agents();
    assert!(!user_agents.is_empty());
    assert!(
        user_agents
            .iter()
            .all(|ua| ua.as_deref() == Some("FFXIV PATCH CLIENT")),
        "every request carries the patch-client UA: {user_agents:?}"
    );
    assert!(
        server
            .stats()
            .patch_unique_ids()
            .iter()
            .all(|id| id.as_deref() == Some("unique-123")),
        "every request carries the unique id"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_dirty_block_rotates_to_a_mirror_and_verifies() {
    let dir = tempfile::tempdir().unwrap();
    let dest = dir.path().join("out.bin");
    let (len, block_size) = (48 * MIB, 4 * MIB as u32);
    // The primary serves block 5 corrupt on every attempt; the mirror serves the same body clean.
    let primary = ChaosServer::builder(30, len)
        .corrupt_range(20 * MIB..24 * MIB)
        .start()
        .await
        .unwrap();
    let mirror = ChaosServer::builder(30, len).start().await.unwrap();
    let spec = DownloadSpec::builder(
        primary.url("f.bin"),
        &dest,
        Validator::BlockSha1 {
            block_size,
            hashes: block_hashes(30, len, block_size),
        },
    )
    .expected_len(len)
    .mirror(mirror.url("f.bin"))
    .build()
    .unwrap();
    let fetcher = Fetcher::builder().max_connections_per_file(4).build().unwrap();

    let verified = fetcher
        .download(&spec, None, CancellationToken::new())
        .await
        .unwrap();

    assert_eq!(
        tokio::fs::read(verified.path()).await.unwrap(),
        generated_vec(30, 0, len as usize)
    );
    // The repair rotated off the always-corrupt primary onto the mirror, which served the block.
    assert!(
        mirror.stats().requests() > 0,
        "the dirty block was re-fetched from the mirror"
    );
    assert!(
        mirror
            .stats()
            .served_ranges()
            .iter()
            .any(|r| r.start == 20 * MIB),
        "the mirror served the dirty block's range"
    );
}

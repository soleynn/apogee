//! Per-block SHA1 verification end to end: a block-hashed download verifies while it streams,
//! re-fetches only a dirty block, rotates to a mirror on repeated failure, honors the patch header
//! policy, and falls back to a whole-file block check when the host ignores ranges.

use std::path::{Path, PathBuf};
use std::time::Duration;

use apogee_fetch::{
    DownloadSpec, DownloadSpecBuilder, FetchError, Fetcher, HeaderPolicy, Progress, Validator,
    VerifiedFile,
};
use apogee_test_support::chaos::{ChaosServer, block_hashes, generated_vec};
use tokio_util::sync::CancellationToken;

const MIB: u64 = 1024 * 1024;
/// The one byte a `bytes=0-0` range-capability probe serves before the transfer starts.
const PROBE: u64 = 1;

fn sidecar(dest: &Path, suffix: &str) -> PathBuf {
    let mut name = dest.as_os_str().to_owned();
    name.push(suffix);
    PathBuf::from(name)
}

/// A `BlockSha1` spec builder for `len` bytes from `seed`, verified at `block_size`, served by
/// `server`. Returns the builder (unbuilt) so a caller stays clear of `unwrap` outside a test body.
fn block_spec(
    server: &ChaosServer,
    dest: &std::path::Path,
    seed: u64,
    len: u64,
    block_size: u32,
) -> DownloadSpecBuilder {
    DownloadSpec::builder(
        server.url("f.bin"),
        dest,
        Validator::BlockSha1 {
            block_size,
            hashes: block_hashes(seed, len, block_size),
        },
    )
    .expected_len(len)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_multi_block_multi_segment_download_verifies_and_publishes() {
    let dir = tempfile::tempdir().unwrap();
    let dest = dir.path().join("out.bin");
    let (len, block_size) = (48 * MIB, 4 * MIB as u32); // twelve blocks across four segments
    let server = ChaosServer::builder(21, len).start().await.unwrap();
    let spec = block_spec(&server, &dest, 21, len, block_size)
        .build()
        .unwrap();
    let fetcher = Fetcher::builder()
        .max_connections_per_file(4)
        .build()
        .unwrap();

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
    let spec = block_spec(&server, &dest, 22, len, block_size)
        .build()
        .unwrap();
    let fetcher = Fetcher::builder()
        .max_connections_per_file(4)
        .build()
        .unwrap();

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
    let spec = block_spec(&server, &dest, 23, len, block_size)
        .build()
        .unwrap();
    let fetcher = Fetcher::builder()
        .max_connections_per_file(4)
        .build()
        .unwrap();

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
    let spec = block_spec(&server, &dest, 24, len, block_size)
        .build()
        .unwrap();
    let fetcher = Fetcher::builder()
        .max_connections_per_file(4)
        .build()
        .unwrap();

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
    let spec = block_spec(&server, &dest, 25, len, block_size)
        .build()
        .unwrap();

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

/// Download `spec` on four connections, cancelling once `threshold` bytes are durable, and return the
/// (expected `Cancelled`) result. A caller pairs this with a server whose last segment hangs one-shot,
/// so the first attempt cannot complete before the cancel lands regardless of runner scheduling. Errors
/// propagate with `?` so no `unwrap` lives in this free helper.
async fn cancel_partway(spec: &DownloadSpec, threshold: u64) -> Result<VerifiedFile, FetchError> {
    let fetcher = Fetcher::builder().max_connections_per_file(4).build()?;
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<Progress>();
    let cancel = CancellationToken::new();
    let trigger = cancel.clone();
    let watcher = tokio::spawn(async move {
        while let Some(p) = rx.recv().await {
            if p.bytes_done >= threshold {
                trigger.cancel();
                break;
            }
        }
    });
    let result = fetcher.download(spec, Some(tx), cancel).await;
    watcher.abort();
    let _ = watcher.await;
    result
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_killed_block_download_keeps_the_journal_and_resumes() {
    let dir = tempfile::tempdir().unwrap();
    let dest = dir.path().join("out.bin");
    let (len, block_size) = (16 * MIB, 4 * MIB as u32);
    let server = ChaosServer::builder(26, len)
        .etag("\"v1\"")
        .throttle(Duration::from_millis(1))
        .chunk(64 * 1024)
        .stall_range_at(8 * MIB, 512 * 1024) // the second segment hangs; the first attempt can't finish
        .start()
        .await
        .unwrap();
    let spec = block_spec(&server, &dest, 26, len, block_size)
        .build()
        .unwrap();

    let err = cancel_partway(&spec, 6 * MIB).await.unwrap_err();
    assert!(matches!(err, FetchError::Cancelled), "got {err:?}");
    assert!(!dest.exists(), "a cancelled download never publishes");
    // The cancel leaves a resumable journal and its part, not a clean slate.
    assert!(
        sidecar(&dest, ".apdl").exists(),
        "the journal survives the cancel"
    );
    assert!(
        sidecar(&dest, ".part").exists(),
        "the part survives the cancel"
    );
    let after_first = server.stats().bytes_served();

    // Resuming re-hashes the durable blocks from disk and fetches only the rest.
    let verified = Fetcher::builder()
        .max_connections_per_file(4)
        .build()
        .unwrap()
        .download(&spec, None, CancellationToken::new())
        .await
        .unwrap();
    assert_eq!(
        tokio::fs::read(verified.path()).await.unwrap(),
        generated_vec(26, 0, len as usize)
    );
    let resumed = server.stats().bytes_served() - after_first;
    assert!(
        resumed < len,
        "the resume fetched only the gaps ({resumed} of {len}), not the whole file",
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_corrupt_durable_block_is_caught_and_repaired_on_resume() {
    let dir = tempfile::tempdir().unwrap();
    let dest = dir.path().join("out.bin");
    let (len, block_size) = (16 * MIB, 4 * MIB as u32); // block 0 == [0, 4 MiB)
    let server = ChaosServer::builder(34, len)
        .etag("\"v1\"")
        .throttle(Duration::from_millis(1))
        .chunk(64 * 1024)
        .stall_range_at(8 * MIB, 512 * 1024)
        .start()
        .await
        .unwrap();
    let spec = block_spec(&server, &dest, 34, len, block_size)
        .build()
        .unwrap();

    // Interrupt with the leading segment (so block 0) fully durable and journaled.
    let err = cancel_partway(&spec, 6 * MIB).await.unwrap_err();
    assert!(matches!(err, FetchError::Cancelled), "got {err:?}");
    assert!(!dest.exists(), "a cancelled download never publishes");
    let part = sidecar(&dest, ".part");
    assert!(part.exists());
    // Corrupt block 0 on disk: the journal still records it as durable, so only the re-hash-on-resume
    // can catch it. Without that re-hash the wrong bytes would publish as a VerifiedFile.
    let mut bytes = tokio::fs::read(&part).await.unwrap();
    bytes[0] ^= 0xFF;
    tokio::fs::write(&part, &bytes).await.unwrap();
    let after_first = server.stats().bytes_served();

    let verified = Fetcher::builder()
        .max_connections_per_file(4)
        .build()
        .unwrap()
        .download(&spec, None, CancellationToken::new())
        .await
        .unwrap();
    assert_eq!(
        tokio::fs::read(verified.path()).await.unwrap(),
        generated_vec(34, 0, len as usize),
        "the corrupted durable block was detected and repaired",
    );
    // The re-hash forced a re-fetch of block 0's range on the resume (a range starting at 0 served
    // again), proving the resume did not trust the journaled coverage.
    let refetched_block_0 = server
        .stats()
        .served_ranges()
        .into_iter()
        .filter(|r| r.start == 0)
        .count();
    assert!(
        refetched_block_0 >= 2,
        "block 0 was served on both the first attempt and the resume repair",
    );
    assert!(server.stats().bytes_served() > after_first);
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
    let spec = block_spec(&server, &dest, 27, len, block_size)
        .build()
        .unwrap();

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
    let spec = block_spec(&server, &dest, 28, len, block_size)
        .build()
        .unwrap();

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
    let spec = block_spec(&server, &dest, 29, len, block_size)
        .header_policy(HeaderPolicy::SePatch {
            unique_id: Some("unique-123".to_owned()),
        })
        .build()
        .unwrap();
    let fetcher = Fetcher::builder()
        .max_connections_per_file(4)
        .build()
        .unwrap();

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
    let spec = block_spec(&primary, &dest, 30, len, block_size)
        .mirror(mirror.url("f.bin"))
        .build()
        .unwrap();
    let fetcher = Fetcher::builder()
        .max_connections_per_file(4)
        .build()
        .unwrap();

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

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn all_corrupt_sources_exhaust_the_block_budget_and_fail() {
    let dir = tempfile::tempdir().unwrap();
    let dest = dir.path().join("out.bin");
    let (len, block_size) = (48 * MIB, 4 * MIB as u32); // block 5 == [20 MiB, 24 MiB)
    // Every source serves block 5 corrupt, so rotation cycles primary/mirror across all attempts.
    let primary = ChaosServer::builder(35, len)
        .corrupt_range(20 * MIB..24 * MIB)
        .start()
        .await
        .unwrap();
    let mirror = ChaosServer::builder(35, len)
        .corrupt_range(20 * MIB..24 * MIB)
        .start()
        .await
        .unwrap();
    let spec = block_spec(&primary, &dest, 35, len, block_size)
        .mirror(mirror.url("f.bin"))
        .build()
        .unwrap();

    let err = Fetcher::builder()
        .max_connections_per_file(4)
        .build()
        .unwrap()
        .download(&spec, None, CancellationToken::new())
        .await
        .unwrap_err();

    assert!(
        matches!(err, FetchError::BlockVerifyFailed { block: 5, offset, attempts: 6 } if offset == 20 * MIB),
        "got {err:?}"
    );
    // Rotation actually visited both sources before giving up.
    assert!(
        primary
            .stats()
            .served_ranges()
            .iter()
            .any(|r| r.start == 20 * MIB),
        "the primary served the block"
    );
    assert!(
        mirror
            .stats()
            .served_ranges()
            .iter()
            .any(|r| r.start == 20 * MIB),
        "rotation reached the mirror"
    );
    assert!(!dest.exists());
}

// A mirror that ignores ranges cannot serve a block re-fetch: it answers the ranged request with a
// full 200, which the engine currently treats as a changed source and fails the whole download. This
// pins that (suboptimal) behavior; a future improvement could skip a range-incapable mirror instead.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_range_ignoring_mirror_on_repair_fails_as_a_changed_source() {
    let dir = tempfile::tempdir().unwrap();
    let dest = dir.path().join("out.bin");
    let (len, block_size) = (48 * MIB, 4 * MIB as u32);
    let primary = ChaosServer::builder(36, len)
        .corrupt_range(20 * MIB..24 * MIB) // block 5 is always corrupt, forcing a rotation
        .start()
        .await
        .unwrap();
    let mirror = ChaosServer::builder(36, len)
        .accept_ranges(false)
        .start()
        .await
        .unwrap();
    let spec = block_spec(&primary, &dest, 36, len, block_size)
        .mirror(mirror.url("f.bin"))
        .build()
        .unwrap();

    let err = Fetcher::builder()
        .max_connections_per_file(4)
        .build()
        .unwrap()
        .download(&spec, None, CancellationToken::new())
        .await
        .unwrap_err();
    assert!(
        matches!(err, FetchError::ServerFileChanged { .. }),
        "got {err:?}"
    );
}

#[tokio::test]
async fn the_header_policy_reaches_the_single_connection_path() {
    let dir = tempfile::tempdir().unwrap();
    let dest = dir.path().join("out.bin");
    let (len, block_size) = (2 * MIB, 512 * 1024u32);
    // A range-ignoring host demotes to the single-connection engine; its requests must still carry the
    // policy's headers.
    let server = ChaosServer::builder(37, len)
        .accept_ranges(false)
        .start()
        .await
        .unwrap();
    let spec = block_spec(&server, &dest, 37, len, block_size)
        .header_policy(HeaderPolicy::SePatch {
            unique_id: Some("uid-9".to_owned()),
        })
        .build()
        .unwrap();

    Fetcher::builder()
        .build()
        .unwrap()
        .download(&spec, None, CancellationToken::new())
        .await
        .unwrap();

    let user_agents = server.stats().user_agents();
    assert!(!user_agents.is_empty());
    assert!(
        user_agents
            .iter()
            .all(|ua| ua.as_deref() == Some("FFXIV PATCH CLIENT")),
        "every single-connection request carries the patch-client UA: {user_agents:?}"
    );
    assert!(
        server
            .stats()
            .patch_unique_ids()
            .iter()
            .all(|id| id.as_deref() == Some("uid-9")),
    );
}

#[tokio::test]
async fn a_satisfied_block_destination_skips_the_network() {
    let dir = tempfile::tempdir().unwrap();
    let dest = dir.path().join("out.bin");
    let (len, block_size) = (2 * MIB, 512 * 1024u32);
    // An already-complete, block-correct file is returned without touching the network.
    tokio::fs::write(&dest, generated_vec(38, 0, len as usize))
        .await
        .unwrap();
    let server = ChaosServer::builder(38, len).start().await.unwrap();
    let spec = block_spec(&server, &dest, 38, len, block_size)
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
        server.stats().requests(),
        0,
        "a fully block-verified destination skips the network",
    );
}

#[tokio::test]
async fn a_block_destination_with_one_bad_block_is_re_downloaded() {
    let dir = tempfile::tempdir().unwrap();
    let dest = dir.path().join("out.bin");
    let (len, block_size) = (2 * MIB, 512 * 1024u32);
    // Same length, but one block's bytes are wrong: the per-block re-hash rejects the skip and the file
    // is re-downloaded rather than trusted.
    let mut body = generated_vec(39, 0, len as usize);
    body[600 * 1024] ^= 0xFF; // a byte inside the second block
    tokio::fs::write(&dest, &body).await.unwrap();
    let server = ChaosServer::builder(39, len).start().await.unwrap();
    let spec = block_spec(&server, &dest, 39, len, block_size)
        .build()
        .unwrap();

    let verified = Fetcher::builder()
        .build()
        .unwrap()
        .download(&spec, None, CancellationToken::new())
        .await
        .unwrap();
    assert!(
        server.stats().requests() > 0,
        "a destination with a bad block is re-downloaded, not trusted",
    );
    assert_eq!(
        tokio::fs::read(verified.path()).await.unwrap(),
        generated_vec(39, 0, len as usize),
    );
}

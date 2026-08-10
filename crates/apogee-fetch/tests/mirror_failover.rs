//! Failover across the whole transfer, not just for a block that failed its hash.
//!
//! A source that will not deliver bytes hands its work to the next one in the spec's list: a refused
//! connection, a body that never arrives, or a ranged request answered with a whole body. These pin
//! *which* source served *what*, by request count and served range, because a returned error alone
//! cannot tell a transfer that failed over from one that never tried.

use std::time::Duration;

use apogee_fetch::{DownloadSpec, FetchError, Fetcher, Progress, RetryPolicy, Validator};
use apogee_test_support::chaos::{
    ChaosServer, block_hashes, body_sha256, generated_vec, sha256_of,
};
use tokio_util::sync::CancellationToken;
use url::Url;

const MIB: u64 = 1024 * 1024;

/// The slack the one `bytes=0-0` range-capability probe is worth in an exact byte count: its body is
/// dropped unread, so whether that byte is counted depends on a scheduling race the client loses
/// often enough to matter. The request count it rides on is exact.
const PROBE: u64 = 1;

/// A source nothing can ever answer: port 1 is inside the privileged range, so no test fixture can
/// bind it, and a connect there is refused rather than left hanging. Deterministic in a way a
/// bound-then-released ephemeral port is not, since that one can be handed to a concurrent test.
fn dead_source() -> Result<Url, url::ParseError> {
    Url::parse("http://127.0.0.1:1/f.bin")
}

/// The default policy with its waits compressed. What these tests measure is which source was asked
/// and in what order, never how long the transfer was polite for.
fn brisk() -> RetryPolicy {
    RetryPolicy::default()
        .base_delay(Duration::from_millis(1))
        .max_delay(Duration::from_millis(5))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_dead_primary_fails_over_to_a_healthy_mirror() {
    // The headline case: the primary host is simply not there. Every request to it is refused, from
    // the range-capability probe onward, and the transfer still completes off the mirror.
    let dir = tempfile::tempdir().unwrap();
    let dest = dir.path().join("out.bin");
    let len = 16 * MIB; // two 8 MiB segments on two connections
    let mirror = ChaosServer::builder(60, len).start().await.unwrap();
    let spec = DownloadSpec::builder(
        dead_source().unwrap(),
        &dest,
        Validator::Sha256(body_sha256(60, len)),
    )
    .expected_len(len)
    .mirror(mirror.url("f.bin"))
    .build()
    .unwrap();

    let verified = tokio::time::timeout(
        Duration::from_secs(30),
        Fetcher::builder()
            .max_connections_per_file(2)
            .retry_policy(brisk())
            .build()
            .unwrap()
            .download(&spec, None, CancellationToken::new()),
    )
    .await
    .expect("a dead primary must fail over, not hang")
    .unwrap();

    assert_eq!(
        sha256_of(&tokio::fs::read(verified.path()).await.unwrap()),
        body_sha256(60, len),
    );
    // Three requests and no more: the probe, then one per segment. Each of those took two refusals
    // from the primary first (the free same-source retry, then the step onto the mirror), so this
    // count is also the proof that failing over costs the transfer nothing beyond that.
    assert_eq!(
        mirror.stats().requests(),
        3,
        "the probe and one request per segment; ranges served: {:?}",
        mirror.stats().served_ranges(),
    );
    let served = mirror.stats().bytes_served();
    assert!(
        (len..=len + PROBE).contains(&served),
        "the mirror served the file exactly once, got {served}",
    );
    let ranges = mirror.stats().served_ranges();
    for want in [0..8 * MIB, 8 * MIB..16 * MIB] {
        assert!(ranges.contains(&want), "{want:?} missing from {ranges:?}");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_permanently_stalled_segment_moves_to_a_mirror_and_completes() {
    // One segment goes silent on the primary on every attempt while the rest of the file streams
    // fine. Before failover reached a transport failure this exhausted the range's budget and failed
    // the whole transfer; now that one segment, and only that one, comes off the mirror.
    let dir = tempfile::tempdir().unwrap();
    let dest = dir.path().join("out.bin");
    let len = 24 * MIB; // three 8 MiB segments
    let primary = ChaosServer::builder(61, len)
        .slow_range(8 * MIB, Duration::from_secs(30))
        .chunk(256 * 1024)
        .start()
        .await
        .unwrap();
    let mirror = ChaosServer::builder(61, len).start().await.unwrap();
    let spec = DownloadSpec::builder(
        primary.url("f.bin"),
        &dest,
        Validator::Sha256(body_sha256(61, len)),
    )
    .expected_len(len)
    .mirror(mirror.url("f.bin"))
    .build()
    .unwrap();

    let verified = tokio::time::timeout(
        Duration::from_secs(30),
        Fetcher::builder()
            .max_connections_per_file(3)
            .stall_timeout(Duration::from_millis(150))
            .retry_policy(brisk())
            .build()
            .unwrap()
            .download(&spec, None, CancellationToken::new()),
    )
    .await
    .expect("a stuck segment must fail over, not hang")
    .unwrap();

    assert_eq!(
        sha256_of(&tokio::fs::read(verified.path()).await.unwrap()),
        body_sha256(61, len),
    );
    // The mirror was asked once, for exactly the stuck segment. Failover is not a whole-transfer
    // switch: the two segments the primary was serving perfectly well stayed with it.
    assert_eq!(
        mirror.stats().served_ranges(),
        vec![8 * MIB..16 * MIB],
        "the mirror served the stuck segment and nothing else",
    );
    assert_eq!(mirror.stats().requests(), 1);
    // The primary answered five: the probe, one per segment, and one same-source retry of the stuck
    // one before the rotation stepped off it.
    assert_eq!(
        primary.stats().requests(),
        5,
        "ranges served: {:?}",
        primary.stats().served_ranges(),
    );
    let from_primary = primary.stats().bytes_served();
    assert!(
        (16 * MIB..=16 * MIB + PROBE).contains(&from_primary),
        "the primary served its two good segments and no byte of the stuck one, got {from_primary}",
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_range_ignoring_mirror_is_passed_over_for_the_next_source() {
    // A mirror that answers a ranged request with the whole body cannot serve a block repair. It
    // costs the transfer that one source, not the download: the repair steps past it to the next
    // mirror and the file verifies.
    let dir = tempfile::tempdir().unwrap();
    let dest = dir.path().join("out.bin");
    let (len, block_size) = (48 * MIB, 4 * MIB as u32); // block 5 spans [20 MiB, 24 MiB)
    let primary = ChaosServer::builder(62, len)
        .corrupt_range(20 * MIB..24 * MIB) // always corrupt, so the repair has to leave the primary
        .start()
        .await
        .unwrap();
    let deaf = ChaosServer::builder(62, len)
        .accept_ranges(false)
        .start()
        .await
        .unwrap();
    let good = ChaosServer::builder(62, len).start().await.unwrap();
    let spec = DownloadSpec::builder(
        primary.url("f.bin"),
        &dest,
        Validator::BlockSha1 {
            block_size,
            hashes: block_hashes(62, len, block_size),
        },
    )
    .expected_len(len)
    .mirror(deaf.url("f.bin"))
    .mirror(good.url("f.bin"))
    .build()
    .unwrap();

    let verified = tokio::time::timeout(
        Duration::from_secs(60),
        Fetcher::builder()
            .max_connections_per_file(4)
            .retry_policy(brisk())
            .build()
            .unwrap()
            .download(&spec, None, CancellationToken::new()),
    )
    .await
    .expect("a range-ignoring mirror must be passed over, not hang")
    .unwrap();

    assert_eq!(
        tokio::fs::read(verified.path()).await.unwrap(),
        generated_vec(62, 0, len as usize),
    );
    assert_eq!(
        deaf.stats().requests(),
        1,
        "the range-ignoring mirror was asked once and then left out of the rotation",
    );
    assert!(
        good.stats()
            .served_ranges()
            .iter()
            .any(|r| r.start == 20 * MIB),
        "the source after it served the dirty block: {:?}",
        good.stats().served_ranges(),
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_primary_answering_a_conditional_range_is_still_a_changed_source() {
    // The guard that keeps failover from swallowing a real problem. A whole body from a *mirror* is
    // a capability verdict, but the same answer from the primary is the file changing under a
    // resume's `If-Range`, and it must still drop the journal and fail rather than quietly pull the
    // rest of a different file off a mirror.
    let dir = tempfile::tempdir().unwrap();
    let dest = dir.path().join("out.bin");
    let len = 24 * MIB;
    // "v1" for the fresh run's probe, "v2" from then on, so the resume's `If-Range: "v1"` misses.
    let primary = ChaosServer::builder(63, len)
        .etag("\"v1\"")
        .change_etag_after(1, "\"v2\"")
        .throttle(Duration::from_millis(1))
        .chunk(256 * 1024)
        .start()
        .await
        .unwrap();
    let mirror = ChaosServer::builder(63, len).start().await.unwrap();
    let spec = DownloadSpec::builder(
        primary.url("f.bin"),
        &dest,
        Validator::Sha256(body_sha256(63, len)),
    )
    .expected_len(len)
    .mirror(mirror.url("f.bin"))
    .build()
    .unwrap();

    // Fresh run, cancelled part way, leaving a journal that recorded ETag "v1".
    {
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
        let _ = Fetcher::builder()
            .max_connections_per_file(4)
            .build()
            .unwrap()
            .download(&spec, Some(tx), cancel)
            .await;
        watcher.abort();
        let _ = watcher.await;
    }
    let mut apdl = dest.clone().into_os_string();
    apdl.push(".apdl");
    let apdl = std::path::PathBuf::from(apdl);
    assert!(apdl.exists(), "the journal survives the cancel");
    let asked_before = mirror.stats().requests();

    let err = Fetcher::builder()
        .max_connections_per_file(4)
        .retry_policy(brisk())
        .build()
        .unwrap()
        .download(&spec, None, CancellationToken::new())
        .await
        .unwrap_err();

    assert!(
        matches!(err, FetchError::ServerFileChanged { .. }),
        "a changed primary is not a mirror's capability problem, got {err:?}",
    );
    assert!(
        !apdl.exists(),
        "the stale journal is dropped so a retry restarts clean",
    );
    assert!(!dest.exists());
    assert_eq!(
        mirror.stats().requests(),
        asked_before,
        "the mirror was never asked to paper over a changed primary",
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn every_source_failing_ends_the_transfer_instead_of_spinning() {
    // Rotation moves work between sources, so a rotation that forgot to spend budget would loop
    // forever. Both sources go silent on the same segment; the transfer must run out of attempts and
    // say so, having visited each source on the way. The timeout is what turns a regression into a
    // failing test rather than a stuck run.
    let dir = tempfile::tempdir().unwrap();
    let dest = dir.path().join("out.bin");
    let len = 16 * MIB; // segments at 0 and 8 MiB; only the second one is starved
    let silent = |seed| {
        ChaosServer::builder(seed, len)
            .slow_range(8 * MIB, Duration::from_secs(30))
            .chunk(256 * 1024)
    };
    let primary = silent(64).start().await.unwrap();
    let mirror = silent(64).start().await.unwrap();
    let spec = DownloadSpec::builder(
        primary.url("f.bin"),
        &dest,
        Validator::Sha256(body_sha256(64, len)),
    )
    .expected_len(len)
    .mirror(mirror.url("f.bin"))
    .build()
    .unwrap();

    let err = tokio::time::timeout(
        Duration::from_secs(30),
        Fetcher::builder()
            .max_connections_per_file(2)
            .stall_timeout(Duration::from_millis(150))
            .retry_policy(brisk().max_attempts(4))
            .build()
            .unwrap()
            .download(&spec, None, CancellationToken::new()),
    )
    .await
    .expect("an exhausted source list must fail, not spin")
    .unwrap_err();

    match err {
        FetchError::AllSourcesFailed {
            ref url,
            sources,
            attempts,
            ..
        } => {
            assert_eq!(sources, 2);
            assert_eq!(attempts, 4, "the budget was spent, not overrun");
            assert_eq!(url, &primary.url("f.bin"), "the primary names the transfer");
        }
        other => panic!("got {other:?}"),
    }
    // The budget was spent across both sources rather than all on the primary: four tries of the
    // starved segment, alternating one source at a time, of which the mirror took one.
    assert_eq!(
        primary.stats().requests(),
        5,
        "the probe, the segment that streamed, and three tries of the starved one",
    );
    assert_eq!(mirror.stats().requests(), 1, "rotation reached the mirror");
    assert!(!dest.exists(), "a failed download never publishes");
}

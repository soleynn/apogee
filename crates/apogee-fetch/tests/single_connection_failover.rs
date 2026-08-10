//! Failover on the single-connection engine, which owns the three transfers the segmented one will
//! not take: an unknown length, a file too small to be worth splitting, and a job demoted because the
//! primary answered a ranged probe with a whole body.
//!
//! Each of those used to be pinned to `spec.url()` for its whole life, so a mirror in the spec bought
//! them nothing. These pin *which* source served *what*, by request count and served range per
//! server, because a returned error alone cannot tell a transfer that failed over from one that never
//! tried. They also pin what must not travel between sources: a validator describes one source's copy
//! of the file, so the primary's is never offered to a mirror and a mirror's is never journaled.

use std::path::{Path, PathBuf};
use std::time::Duration;

use apogee_fetch::{DownloadSpec, FetchError, Fetcher, RetryPolicy, Validator};
use apogee_test_support::chaos::{ChaosServer, body_sha256, sha256_of};
use tokio_util::sync::CancellationToken;
use url::Url;

const MIB: u64 = 1024 * 1024;

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

fn sidecar(dest: &Path, suffix: &str) -> PathBuf {
    let mut name = dest.as_os_str().to_owned();
    name.push(suffix);
    PathBuf::from(name)
}

/// Whether `haystack` contains `needle` anywhere, for reading a validator back out of the raw journal
/// header without reaching into the crate's private encoding.
fn contains(haystack: &[u8], needle: &str) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle.as_bytes())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_demoted_transfer_whose_primary_goes_quiet_completes_off_a_mirror() {
    // The sharpest of the three. The primary ignores `Range`, so the probe demotes the whole job to
    // one connection, and that verdict used to pin the job to the primary for good: a range-capable
    // mirror sat idle while the demoted transfer died against a host that never delivered a byte.
    // Demotion is still the primary's verdict, but it now costs throughput rather than the download.
    let dir = tempfile::tempdir().unwrap();
    let dest = dir.path().join("out.bin");
    let len = 16 * MIB; // two 8 MiB segments, so the probe runs and the demotion is a real decision
    let primary = ChaosServer::builder(70, len)
        .accept_ranges(false)
        .throttle(Duration::from_secs(30)) // every body goes silent before its first chunk
        .chunk(256 * 1024)
        .start()
        .await
        .unwrap();
    let mirror = ChaosServer::builder(70, len).start().await.unwrap();
    let spec = DownloadSpec::builder(
        primary.url("f.bin"),
        &dest,
        Validator::Sha256(body_sha256(70, len)),
    )
    .expected_len(len)
    .mirror(mirror.url("f.bin"))
    .build()
    .unwrap();

    let verified = tokio::time::timeout(
        Duration::from_secs(30),
        Fetcher::builder()
            .max_connections_per_file(2)
            .stall_timeout(Duration::from_millis(150))
            .retry_policy(brisk())
            .build()
            .unwrap()
            .download(&spec, None, CancellationToken::new()),
    )
    .await
    .expect("a demoted transfer must fail over, not hang")
    .unwrap();

    assert_eq!(
        sha256_of(&tokio::fs::read(verified.path()).await.unwrap()),
        body_sha256(70, len),
    );
    // Three requests to the primary and no more: the range-capability probe, then the free
    // same-source retry, then the rotation steps off it. Nothing else is charged to it.
    assert_eq!(
        primary.stats().requests(),
        3,
        "the probe, one try, and the free retry of it",
    );
    assert_eq!(
        mirror.stats().served_ranges(),
        vec![0..len],
        "the mirror streamed the whole file on one connection",
    );
    assert_eq!(mirror.stats().requests(), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_small_files_resume_moves_to_a_mirror_without_offering_it_the_primarys_validator() {
    // A file under the segment floor never reaches the segmented engine, and never spends a probe.
    // The primary here delivers a prefix and then goes silent on every later try, so the rotation
    // hands the *rest* to the mirror, which is where the identity rule bites: `If-Range` is the
    // primary's validator, and the mirror is deliberately configured with none. Offering it anyway
    // would be a mismatch, the mirror would answer the whole body, and the durable prefix would be
    // thrown away - which is exactly what the served range below would show.
    let dir = tempfile::tempdir().unwrap();
    let dest = dir.path().join("out.bin");
    let len = 4 * MIB; // under the 8 MiB floor: single-connection, no probe
    let primary = ChaosServer::builder(71, len)
        .etag("\"primary-copy\"")
        .stall_after(MIB) // the first body stops at 1 MiB
        .slow_range(MIB, Duration::from_secs(30)) // and every resume of it delivers nothing
        .chunk(64 * 1024)
        .start()
        .await
        .unwrap();
    let mirror = ChaosServer::builder(71, len).start().await.unwrap();
    let spec = DownloadSpec::builder(
        primary.url("f.bin"),
        &dest,
        Validator::Sha256(body_sha256(71, len)),
    )
    .expected_len(len)
    .mirror(mirror.url("f.bin"))
    .build()
    .unwrap();

    let verified = tokio::time::timeout(
        Duration::from_secs(30),
        Fetcher::builder()
            .max_connections_per_file(2)
            .stall_timeout(Duration::from_millis(150))
            .retry_policy(brisk())
            .build()
            .unwrap()
            .download(&spec, None, CancellationToken::new()),
    )
    .await
    .expect("a stuck small-file transfer must fail over, not hang")
    .unwrap();

    assert_eq!(
        sha256_of(&tokio::fs::read(verified.path()).await.unwrap()),
        body_sha256(71, len),
    );
    assert_eq!(
        mirror.stats().served_ranges(),
        vec![MIB..len],
        "the mirror continued the primary's prefix instead of restarting from zero",
    );
    assert_eq!(mirror.stats().requests(), 1);
    // Two requests, not three: a file this small is never probed for range support, so the primary's
    // whole budget went on the transfer itself.
    assert_eq!(
        primary.stats().requests(),
        2,
        "one try and the free retry of it, with no probe spent; ranges served: {:?}",
        primary.stats().served_ranges(),
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_unknown_length_transfer_fails_over_to_a_mirror() {
    // No declared length means no segmentation and no probe: the length is whatever the body turns
    // out to be. The primary is simply not there, and the transfer still lands.
    let dir = tempfile::tempdir().unwrap();
    let dest = dir.path().join("out.bin");
    let len = 3 * MIB;
    let mirror = ChaosServer::builder(72, len).start().await.unwrap();
    let spec = DownloadSpec::builder(
        dead_source().unwrap(),
        &dest,
        Validator::Sha256(body_sha256(72, len)),
    )
    .mirror(mirror.url("f.bin"))
    .build()
    .unwrap();

    let verified = tokio::time::timeout(
        Duration::from_secs(30),
        Fetcher::builder()
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
        body_sha256(72, len),
    );
    assert_eq!(
        mirror.stats().served_ranges(),
        vec![0..len],
        "the mirror streamed the whole file, its length learned from the body",
    );
    assert_eq!(
        mirror.stats().requests(),
        1,
        "two refusals from the primary cost the mirror nothing extra",
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn only_the_primarys_validator_is_journaled_for_a_later_resume() {
    // The journal's identity is the primary's URL, so the validators recorded beside it have to be
    // the primary's too. A mirror-served transfer therefore records none: writing the mirror's would
    // hand the next run an `If-Range` for a copy the primary was never asked about, and the primary
    // would answer the whole body, discarding durable bytes over a difference that means nothing.
    //
    // Both halves run the same shape, differing only in which server answered, because "the string is
    // absent" proves nothing on its own - the second half is what shows a validator reaches the
    // journal at all.
    let dir = tempfile::tempdir().unwrap();
    let len = 4 * MIB;

    // A mirror answered, so nothing of its identity may reach the journal.
    let dest = dir.path().join("from-mirror.bin");
    let mirror = ChaosServer::builder(73, len)
        .etag("\"mirror-copy\"")
        .stall_after(MIB)
        .chunk(64 * 1024)
        .start()
        .await
        .unwrap();
    let spec = DownloadSpec::builder(
        dead_source().unwrap(),
        &dest,
        Validator::Sha256(body_sha256(73, len)),
    )
    .expected_len(len)
    .mirror(mirror.url("f.bin"))
    .build()
    .unwrap();

    let err = tokio::time::timeout(
        Duration::from_secs(30),
        Fetcher::builder()
            .stall_timeout(Duration::from_millis(150))
            .retry_policy(brisk().max_attempts(4))
            .build()
            .unwrap()
            .download(&spec, None, CancellationToken::new()),
    )
    .await
    .expect("an exhausted source list must fail, not spin")
    .unwrap_err();

    // The budget was spent across both sources: two refusals, the mirror's stalled prefix, then one
    // more refusal. What survives is a journal naming the megabyte the mirror did deliver.
    match err {
        FetchError::AllSourcesFailed {
            ref url,
            sources,
            attempts,
            at_bytes,
        } => {
            assert_eq!(sources, 2);
            assert_eq!(attempts, 4, "the budget was spent, not overrun");
            assert_eq!(at_bytes, MIB, "the mirror's prefix is durable");
            assert_eq!(
                url,
                &dead_source().unwrap(),
                "the primary names the transfer"
            );
        }
        other => panic!("got {other:?}"),
    }
    let apdl = sidecar(&dest, ".apdl");
    let journaled = tokio::fs::read(&apdl)
        .await
        .expect("the journal survives a failed transfer");
    assert!(
        !contains(&journaled, "mirror-copy"),
        "a mirror's validator must never be recorded under the primary's identity",
    );
    assert!(
        contains(&journaled, dead_source().unwrap().as_str()),
        "the identity recorded is still the primary's",
    );

    // The same shape with the answering server as the primary: its validator does reach the journal.
    let dest = dir.path().join("from-primary.bin");
    let primary = ChaosServer::builder(74, len)
        .etag("\"primary-copy\"")
        .stall_after(MIB)
        .slow_range(MIB, Duration::from_secs(30))
        .chunk(64 * 1024)
        .start()
        .await
        .unwrap();
    let spec = DownloadSpec::builder(
        primary.url("f.bin"),
        &dest,
        Validator::Sha256(body_sha256(74, len)),
    )
    .expected_len(len)
    .build()
    .unwrap();

    tokio::time::timeout(
        Duration::from_secs(30),
        Fetcher::builder()
            .stall_timeout(Duration::from_millis(150))
            .retry_policy(brisk().max_attempts(2))
            .build()
            .unwrap()
            .download(&spec, None, CancellationToken::new()),
    )
    .await
    .expect("an exhausted budget must fail, not spin")
    .unwrap_err();

    let journaled = tokio::fs::read(sidecar(&dest, ".apdl"))
        .await
        .expect("the journal survives a failed transfer");
    assert!(
        contains(&journaled, "primary-copy"),
        "the primary's own validator is what a later resume revalidates against",
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn every_source_failing_ends_the_transfer_instead_of_spinning() {
    // Rotation moves work between sources, so a rotation that forgot to spend budget would loop
    // forever. Both sources go silent on every try; the transfer must run out of attempts and say so,
    // having visited each source on the way. The timeout is what turns a regression into a failing
    // test rather than a stuck run.
    let dir = tempfile::tempdir().unwrap();
    let dest = dir.path().join("out.bin");
    let len = 4 * MIB; // under the segment floor: single connection, no probe
    let silent = |seed| {
        ChaosServer::builder(seed, len)
            .throttle(Duration::from_secs(30))
            .chunk(64 * 1024)
    };
    let primary = silent(75).start().await.unwrap();
    let mirror = silent(75).start().await.unwrap();
    let spec = DownloadSpec::builder(
        primary.url("f.bin"),
        &dest,
        Validator::Sha256(body_sha256(75, len)),
    )
    .expected_len(len)
    .mirror(mirror.url("f.bin"))
    .build()
    .unwrap();

    let err = tokio::time::timeout(
        Duration::from_secs(30),
        Fetcher::builder()
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
            at_bytes,
        } => {
            assert_eq!(sources, 2);
            assert_eq!(attempts, 4, "the budget was spent, not overrun");
            assert_eq!(at_bytes, 0, "neither source delivered a byte");
            assert_eq!(url, &primary.url("f.bin"), "the primary names the transfer");
        }
        other => panic!("got {other:?}"),
    }
    // Four tries spread over the list rather than all spent on the primary, of which the mirror took
    // one. A single-source transfer still reports its own stall; this one reports the failover.
    assert_eq!(primary.stats().requests(), 3);
    assert_eq!(mirror.stats().requests(), 1, "rotation reached the mirror");
    assert!(!dest.exists(), "a failed download never publishes");
}

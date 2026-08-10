//! Backoff and retry against a hostile server: what is retried, what is not, and what the wait costs.
//!
//! The cases here are the ones a flat "re-queue immediately, five times" scheme got wrong: a
//! throttling `503` used to fail the whole transfer, a single-connection body that dropped lost every
//! byte behind it, and nothing anywhere read `Retry-After`. Each test pins one of those, plus the two
//! properties a retry loop must never lose: a fatal status still fails on the first response, and a
//! retry re-fetches only the bytes it is missing.

use std::path::Path;
use std::time::{Duration, Instant};

use apogee_fetch::{
    DownloadSpec, DownloadSpecBuilder, FetchError, Fetcher, RetryPolicy, Validator,
};
use apogee_test_support::chaos::{ChaosServer, RetryAfter, body_sha256, generated_vec, sha256_of};
use tokio_util::sync::CancellationToken;

const MIB: u64 = 1024 * 1024;

/// A policy whose waits are compressed to nothing, for the tests that are about *what* is retried
/// rather than *how long* it waits.
fn instant_retries() -> RetryPolicy {
    RetryPolicy::default()
        .base_delay(Duration::from_micros(1))
        .max_delay(Duration::from_millis(1))
}

/// A whole-file-verified spec for `len` bytes from `seed`, served by `server`.
fn sha_spec(server: &ChaosServer, dest: &Path, seed: u64, len: u64) -> DownloadSpecBuilder {
    DownloadSpec::builder(
        server.url("f.bin"),
        dest,
        Validator::Sha256(body_sha256(seed, len)),
    )
    .expected_len(len)
}

#[tokio::test]
async fn a_throttled_single_connection_transfer_backs_off_and_then_succeeds() {
    // Two 503s before the body: the transfer used to fail on the first one.
    let dir = tempfile::tempdir().unwrap();
    let dest = dir.path().join("out.bin");
    let len = 300_000;
    let server = ChaosServer::builder(41, len)
        .service_unavailable(2, RetryAfter::Seconds(1))
        .start()
        .await
        .unwrap();
    let spec = sha_spec(&server, &dest, 41, len).build().unwrap();

    let verified = Fetcher::builder()
        .max_connections_per_file(1)
        .retry_policy(instant_retries())
        .build()
        .unwrap()
        .download(&spec, None, CancellationToken::new())
        .await
        .unwrap();

    assert_eq!(
        tokio::fs::read(verified.path()).await.unwrap(),
        generated_vec(41, 0, len as usize),
    );
    assert_eq!(
        server.stats().requests(),
        3,
        "two refusals then one served body",
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_throttled_segment_backs_off_without_re_fetching_the_file() {
    // One segment is refused twice while the rest of the transfer proceeds. The refusal must cost
    // that segment a wait and nothing else: no other range may be served twice.
    let dir = tempfile::tempdir().unwrap();
    let dest = dir.path().join("out.bin");
    let len = 24 * MIB;
    let server = ChaosServer::builder(42, len)
        .unavailable_range_at(8 * MIB, 2, RetryAfter::Seconds(1))
        .chunk(256 * 1024)
        .start()
        .await
        .unwrap();
    let spec = sha_spec(&server, &dest, 42, len).build().unwrap();

    let verified = Fetcher::builder()
        .max_connections_per_file(4)
        .retry_policy(instant_retries())
        .build()
        .unwrap()
        .download(&spec, None, CancellationToken::new())
        .await
        .unwrap();

    assert_eq!(
        sha256_of(&tokio::fs::read(verified.path()).await.unwrap()),
        body_sha256(42, len),
    );
    // A refused request carries no body, so the served bytes are still exactly the file (plus at
    // most the capability probe's single byte).
    let served = server.stats().bytes_served();
    assert!(
        (len..=len + 1).contains(&served),
        "a backed-off segment re-fetches nothing already durable; served {served} of {len}",
    );
}

#[tokio::test]
async fn a_fatal_status_fails_on_the_first_response() {
    // A header-size refusal is a request-shaped fault: it will be refused identically forever, so it
    // must not spend the retry budget. The request count is the assertion; the error alone would
    // still pass if the transfer had quietly retried and failed the same way.
    let dir = tempfile::tempdir().unwrap();
    let dest = dir.path().join("out.bin");
    let len = 300_000;
    let server = ChaosServer::builder(43, len)
        .max_request_header_bytes(1)
        .start()
        .await
        .unwrap();
    let spec = sha_spec(&server, &dest, 43, len).build().unwrap();

    let err = Fetcher::builder()
        .max_connections_per_file(1)
        .retry_policy(instant_retries())
        .build()
        .unwrap()
        .download(&spec, None, CancellationToken::new())
        .await
        .unwrap_err();

    assert!(
        matches!(err, FetchError::Http { status: 431, .. }),
        "got {err:?}",
    );
    assert_eq!(
        server.stats().requests(),
        1,
        "a fatal status is asked exactly once",
    );
    assert!(!dest.exists());
}

#[tokio::test]
async fn a_retryable_status_that_never_clears_exhausts_the_budget() {
    // The budget has to actually run out: a server that refuses forever must produce a failure, not
    // an endless loop, and the request count says exactly how many tries it got.
    let dir = tempfile::tempdir().unwrap();
    let dest = dir.path().join("out.bin");
    let len = 300_000;
    let server = ChaosServer::builder(44, len)
        .service_unavailable(u64::MAX, RetryAfter::Seconds(1))
        .start()
        .await
        .unwrap();
    let spec = sha_spec(&server, &dest, 44, len).build().unwrap();

    let err = tokio::time::timeout(
        Duration::from_secs(30),
        Fetcher::builder()
            .max_connections_per_file(1)
            .retry_policy(instant_retries().max_attempts(3))
            .build()
            .unwrap()
            .download(&spec, None, CancellationToken::new()),
    )
    .await
    .expect("an exhausted budget must fail, not spin")
    .unwrap_err();

    assert!(
        matches!(err, FetchError::Http { status: 503, .. }),
        "got {err:?}",
    );
    assert_eq!(
        server.stats().requests(),
        3,
        "three attempts, then the failure is reported",
    );
}

#[tokio::test]
async fn a_retry_after_far_past_the_ceiling_is_clamped_not_obeyed() {
    // The server asks for an hour. Honoring it verbatim is a server-chosen hang, so the wait is
    // clamped to the policy's ceiling; the test's own timeout is what fails if it is not.
    let dir = tempfile::tempdir().unwrap();
    let dest = dir.path().join("out.bin");
    let len = 64 * 1024;
    let server = ChaosServer::builder(45, len)
        .service_unavailable(1, RetryAfter::Seconds(3600))
        .start()
        .await
        .unwrap();
    let spec = sha_spec(&server, &dest, 45, len).build().unwrap();

    let started = Instant::now();
    let verified = tokio::time::timeout(
        Duration::from_secs(20),
        Fetcher::builder()
            .max_connections_per_file(1)
            .retry_policy(
                RetryPolicy::default()
                    .base_delay(Duration::from_millis(10))
                    .max_delay(Duration::from_millis(200)),
            )
            .build()
            .unwrap()
            .download(&spec, None, CancellationToken::new()),
    )
    .await
    .expect("an unclamped Retry-After would park this for an hour")
    .unwrap();

    assert_eq!(
        tokio::fs::read(verified.path()).await.unwrap(),
        generated_vec(45, 0, len as usize),
    );
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "waited {:?}, so the ceiling did not apply",
        started.elapsed(),
    );
}

#[tokio::test]
async fn the_backoff_between_attempts_is_actually_waited_out() {
    // Three refusals under a 300 ms base: equal jitter puts a floor of half the computed term under
    // each wait, so the transfer cannot finish before 150 + 300 + 600 ms have passed. A machine
    // under load only makes this slower, never faster, so the lower bound does not flake.
    let dir = tempfile::tempdir().unwrap();
    let dest = dir.path().join("out.bin");
    let len = 64 * 1024;
    let server = ChaosServer::builder(46, len)
        .service_unavailable(3, RetryAfter::Seconds(0))
        .start()
        .await
        .unwrap();
    let spec = sha_spec(&server, &dest, 46, len).build().unwrap();

    let started = Instant::now();
    Fetcher::builder()
        .max_connections_per_file(1)
        .retry_policy(
            RetryPolicy::default()
                .base_delay(Duration::from_millis(300))
                .max_delay(Duration::from_secs(5)),
        )
        .build()
        .unwrap()
        .download(&spec, None, CancellationToken::new())
        .await
        .unwrap();

    assert!(
        started.elapsed() >= Duration::from_millis(1050),
        "three backoffs took only {:?}; the delays are not being waited out",
        started.elapsed(),
    );
}

#[tokio::test]
async fn a_dropped_single_connection_body_resumes_instead_of_restarting() {
    // The single-connection engine used to abandon the transfer on the first mid-body error, even
    // though every byte behind it was already durable. It must now re-request only the remainder.
    let dir = tempfile::tempdir().unwrap();
    let dest = dir.path().join("out.bin");
    let len = 4 * MIB;
    let server = ChaosServer::builder(47, len)
        .drop_after(3 * MIB)
        .chunk(256 * 1024)
        .start()
        .await
        .unwrap();
    let spec = sha_spec(&server, &dest, 47, len).build().unwrap();

    let verified = Fetcher::builder()
        .max_connections_per_file(1)
        .retry_policy(instant_retries())
        .build()
        .unwrap()
        .download(&spec, None, CancellationToken::new())
        .await
        .unwrap();

    assert_eq!(
        sha256_of(&tokio::fs::read(verified.path()).await.unwrap()),
        body_sha256(47, len),
    );
    assert_eq!(
        server.stats().served_ranges(),
        vec![0..3 * MIB, 3 * MIB..4 * MIB],
        "the retry asked only for the bytes the drop cost",
    );
}

#[tokio::test]
async fn a_source_that_changed_between_attempts_restarts_instead_of_stitching() {
    // The drop and its retry may not be looking at the same file. The retry carries the first
    // response's validator, so a server whose `ETag` has moved on answers with a full `200` and the
    // transfer restarts; without that header it would splice a tail of the new file onto a head of
    // the old one and only a whole-file hash would ever notice.
    let dir = tempfile::tempdir().unwrap();
    let dest = dir.path().join("out.bin");
    let len = 4 * MIB;
    let server = ChaosServer::builder(50, len)
        .etag("\"v1\"")
        .change_etag_after(1, "\"v2\"")
        .drop_after(2 * MIB)
        .chunk(256 * 1024)
        .start()
        .await
        .unwrap();
    let spec = sha_spec(&server, &dest, 50, len).build().unwrap();

    let verified = Fetcher::builder()
        .max_connections_per_file(1)
        .retry_policy(instant_retries())
        .build()
        .unwrap()
        .download(&spec, None, CancellationToken::new())
        .await
        .unwrap();

    assert_eq!(
        sha256_of(&tokio::fs::read(verified.path()).await.unwrap()),
        body_sha256(50, len),
    );
    assert_eq!(
        server.stats().served_ranges(),
        vec![0..2 * MIB, 0..4 * MIB],
        "the retry restarted from zero rather than resuming onto a changed source",
    );
}

#[tokio::test]
async fn a_reset_after_the_last_byte_is_not_retried() {
    // A server that resets instead of closing cleanly has still delivered everything asked for.
    // Treating that error as an interruption would spend an attempt asking for a range starting at
    // the file's own length, which a real server answers with `416` and which then costs a full
    // restart from zero. The body has to be chunked for the client to see the reset at all: behind a
    // `Content-Length` the stream ends on the byte count and the error never surfaces.
    let dir = tempfile::tempdir().unwrap();
    let dest = dir.path().join("out.bin");
    let len = 256 * 1024;
    let server = ChaosServer::builder(51, len)
        .reset_after_range()
        .omit_content_length()
        .chunk(64 * 1024)
        .start()
        .await
        .unwrap();
    let spec = sha_spec(&server, &dest, 51, len).build().unwrap();

    let verified = Fetcher::builder()
        .max_connections_per_file(1)
        .retry_policy(instant_retries())
        .build()
        .unwrap()
        .download(&spec, None, CancellationToken::new())
        .await
        .unwrap();

    assert_eq!(
        sha256_of(&tokio::fs::read(verified.path()).await.unwrap()),
        body_sha256(51, len),
    );
    assert_eq!(
        server.stats().requests(),
        1,
        "a complete body needs no second request",
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_silent_single_connection_body_times_out_and_resumes() {
    // A hung connection with no EOF: without an inactivity timeout this path waits forever, since
    // nothing configures a read timeout on the client.
    let dir = tempfile::tempdir().unwrap();
    let dest = dir.path().join("out.bin");
    let len = 2 * MIB;
    let server = ChaosServer::builder(48, len)
        .stall_after(MIB)
        .chunk(256 * 1024)
        .start()
        .await
        .unwrap();
    let spec = sha_spec(&server, &dest, 48, len).build().unwrap();

    let verified = tokio::time::timeout(
        Duration::from_secs(30),
        Fetcher::builder()
            .max_connections_per_file(1)
            .stall_timeout(Duration::from_millis(200))
            .retry_policy(instant_retries())
            .build()
            .unwrap()
            .download(&spec, None, CancellationToken::new()),
    )
    .await
    .expect("a silent body must time out, not hang the transfer")
    .unwrap();

    assert_eq!(
        sha256_of(&tokio::fs::read(verified.path()).await.unwrap()),
        body_sha256(48, len),
    );
    assert_eq!(
        server.stats().served_ranges(),
        vec![0..MIB, MIB..2 * MIB],
        "the resume asked only for the bytes past the stall",
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_permanently_silent_single_connection_body_fails_as_stalled() {
    // The counterpart to the recovery above: a body that never resumes has to exhaust the budget and
    // report where it stopped, rather than retry forever.
    let dir = tempfile::tempdir().unwrap();
    let dest = dir.path().join("out.bin");
    let len = 2 * MIB;
    let server = ChaosServer::builder(49, len)
        .throttle(Duration::from_secs(30))
        .chunk(256 * 1024)
        .start()
        .await
        .unwrap();
    let spec = sha_spec(&server, &dest, 49, len).build().unwrap();

    let err = tokio::time::timeout(
        Duration::from_secs(30),
        Fetcher::builder()
            .max_connections_per_file(1)
            .stall_timeout(Duration::from_millis(100))
            .retry_policy(instant_retries().max_attempts(2))
            .build()
            .unwrap()
            .download(&spec, None, CancellationToken::new()),
    )
    .await
    .expect("an exhausted budget must fail, not spin")
    .unwrap_err();

    assert!(
        matches!(err, FetchError::Stalled { at_bytes: 0, .. }),
        "got {err:?}",
    );
    assert_eq!(
        server.stats().requests(),
        2,
        "two attempts, then the failure"
    );
    assert!(!dest.exists());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_segment_that_goes_quiet_after_its_last_byte_is_not_a_stuck_segment() {
    // The segmented counterpart to the reset case above. A segment that commits its last byte and
    // only then loses its connection reports a remainder of zero bytes, which is not stuck work:
    // there is nothing left to ask for. Charging it an attempt spends the budget of the *next*
    // segment (the ranges are contiguous, so the empty remainder starts exactly where that one
    // does), and a budget already spent there fails a transfer whose bytes all arrived intact.
    //
    // `max_attempts(1)` is what makes that deterministic rather than a race: it puts every offset one
    // charge away from exhaustion, which a flaky link reaches on its own. The server goes quiet
    // rather than resetting so the whole range survives (a reset discards what is still in flight at
    // this size), and omits the length so the client cannot end the body on a byte count.
    let dir = tempfile::tempdir().unwrap();
    let dest = dir.path().join("out.bin");
    let len = 9 * MIB;
    let server = ChaosServer::builder(52, len)
        .stall_after_range()
        .omit_content_length()
        .chunk(256 * 1024)
        .start()
        .await
        .unwrap();
    let spec = sha_spec(&server, &dest, 52, len).build().unwrap();

    let verified = tokio::time::timeout(
        Duration::from_secs(30),
        Fetcher::builder()
            .max_connections_per_file(4)
            .stall_timeout(Duration::from_millis(200))
            .retry_policy(instant_retries().max_attempts(1))
            .build()
            .unwrap()
            .download(&spec, None, CancellationToken::new()),
    )
    .await
    .expect("a completed segment must not hang the transfer")
    .unwrap();

    assert_eq!(
        sha256_of(&tokio::fs::read(verified.path()).await.unwrap()),
        body_sha256(52, len),
    );
    assert_eq!(
        server.stats().requests(),
        3,
        "one capability probe and two complete segments, with nothing re-asked",
    );
}

//! The single-connection engine's eager `.part` reservation.
//!
//! The engine that owns every transfer whose length the caller did not declare - runner tarballs,
//! DXVK builds, addon artifacts, the largest downloads there are - reserves its `.part` to the full
//! length before the body streams, taking that length from the response when the caller stated none.
//! These cover what the reservation must and must not do: reserve the whole file while the origin has
//! served nothing, leave a resume pointed at the journal's watermark rather than at the reserved end,
//! and reserve nothing at all when no length was ever stated.
//!
//! The disk-full half of the contract lives in `disk_full.rs`, next to the injection helper it needs.

use std::path::{Path, PathBuf};
use std::time::Duration;

use apogee_fetch::{
    DownloadSpec, DownloadSpecBuilder, FetchError, Fetcher, FetcherBuilder, RetryPolicy, Validator,
};
use apogee_test_support::chaos::{ChaosServer, body_sha256, sha256_of};
use tokio_util::sync::CancellationToken;

const MIB: u64 = 1024 * 1024;

/// How long an origin sits on its first chunk when a test needs one that is willing and able to serve
/// but demonstrably has not. Far longer than the stall timeout the test pairs it with, so a regression
/// that streams the body ends in a fast, legible timeout rather than in a hang.
const WILLING_BUT_SLOW: Duration = Duration::from_secs(30);

fn sidecar(dest: &Path, suffix: &str) -> PathBuf {
    let mut name = dest.as_os_str().to_owned();
    name.push(suffix);
    PathBuf::from(name)
}

/// A fetcher that never retries in-process, so one failure is one observable outcome.
fn single_attempt() -> FetcherBuilder {
    Fetcher::builder().retry_policy(RetryPolicy::default().max_attempts(1))
}

/// A spec that declares no length, which is what routes a transfer to the single-connection engine
/// and is how everything outside the patch path is fetched.
fn undeclared_spec(server: &ChaosServer, dest: &Path, seed: u64, len: u64) -> DownloadSpecBuilder {
    DownloadSpec::builder(
        server.url("f.bin"),
        dest,
        Validator::Sha256(body_sha256(seed, len)),
    )
}

/// A fresh transfer holds the whole length before it takes a payload byte.
///
/// The origin is willing and able: it has answered, announced the length, and generated its first
/// chunk, and only the delay keeps that chunk off the wire. So the zero byte count is the client's
/// doing rather than a server that had nothing to give, and the transfer dying of the stall timeout is
/// what pins the observation to a moment after the response and before the body.
#[tokio::test]
async fn a_fresh_transfer_reserves_the_whole_length_before_the_body_streams() {
    let dir = tempfile::tempdir().unwrap();
    let dest = dir.path().join("out.bin");
    let len = 4 * MIB;
    let server = ChaosServer::builder(31, len)
        .throttle(WILLING_BUT_SLOW)
        .start()
        .await
        .unwrap();
    let spec = undeclared_spec(&server, &dest, 31, len).build().unwrap();

    let err = single_attempt()
        .stall_timeout(Duration::from_secs(2))
        .build()
        .unwrap()
        .download(&spec, None, CancellationToken::new())
        .await
        .unwrap_err();
    assert!(matches!(err, FetchError::Stalled { .. }), "got {err:?}");

    assert_eq!(
        server.stats().bytes_served(),
        0,
        "the origin served a payload byte before the reservation was checked",
    );
    let meta = std::fs::metadata(sidecar(&dest, ".part")).unwrap();
    assert_eq!(
        meta.len(),
        len,
        "the response declared {len} bytes and the part file holds {}",
        meta.len(),
    );
    // The length alone would also be what a sparse file looks like, which reserves nothing and so
    // detects nothing. Blocks are the eagerness half of the claim.
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::fs::MetadataExt;
        assert!(
            meta.blocks() * 512 >= len,
            "the part file is sparse: {} blocks for {len} bytes, so no disk was reserved",
            meta.blocks(),
        );
    }
    assert!(!dest.exists(), "a stalled transfer published a destination");
}

/// A resume continues from the journal's watermark, not from the reserved end of the file.
///
/// This is the interaction the reservation creates: the `.part` an interrupted transfer leaves behind
/// is now always full length, so anything that read the resume point off the file size would ask for
/// an empty range and hand back a file of zeros that still passed every length check. The journal is
/// the only thing that knows where the bytes stop.
#[tokio::test]
async fn a_resume_continues_from_the_journal_watermark_and_not_the_reserved_length() {
    let dir = tempfile::tempdir().unwrap();
    let dest = dir.path().join("out.bin");
    let len = 4 * MIB;
    let server = ChaosServer::builder(32, len)
        .etag("\"v1\"")
        .drop_after(2 * MIB)
        .chunk(64 * 1024)
        .start()
        .await
        .unwrap();
    let spec = undeclared_spec(&server, &dest, 32, len).build().unwrap();
    let downloader = single_attempt().build().unwrap();

    downloader
        .download(&spec, None, CancellationToken::new())
        .await
        .unwrap_err();
    let part_len = std::fs::metadata(sidecar(&dest, ".part")).unwrap().len();
    assert_eq!(
        part_len, len,
        "the interrupted transfer left a part of {part_len} bytes, so the reservation did not survive it",
    );

    let verified = downloader
        .download(&spec, None, CancellationToken::new())
        .await
        .unwrap();
    let bytes = tokio::fs::read(verified.path()).await.unwrap();
    assert_eq!(bytes.len() as u64, len);
    assert_eq!(sha256_of(&bytes), body_sha256(32, len));

    // Where the resume asked from is the claim, and the hash above cannot carry it on its own: a
    // restart from zero also produces the right file, at the cost of the whole prefix.
    let starts = server.stats().requested_starts();
    assert_eq!(
        starts.len(),
        2,
        "expected one interrupted request and one resume, got {starts:?}",
    );
    assert!(
        starts[1] > 0 && starts[1] < len,
        "the resume asked from {} of a {len}-byte file, whose end is where the reservation put it",
        starts[1],
    );
    assert!(
        server.stats().bytes_served() < 2 * len,
        "a resume must not re-download the whole file",
    );
}

/// A body nobody states a length for reserves nothing, and still transfers.
///
/// Chunked with no `Content-Length` and no declared length either, so there is no size to reserve and
/// none is invented. The interruption is what makes the absence visible: the `.part` holds exactly
/// what arrived, which is what a guessed size would not leave behind.
///
/// The interruption is a stall rather than a dropped connection because chunked framing does not
/// survive one: an error frame mid-body costs the client every chunk it had already been handed
/// (measured: the origin served 131072 bytes and the `.part` came out empty), which would leave this
/// asserting against zero either way. A silent connection ends the same attempt with everything it
/// received still durable.
#[tokio::test]
async fn an_unknown_length_transfer_reserves_nothing_and_still_completes() {
    let dir = tempfile::tempdir().unwrap();
    let dest = dir.path().join("out.bin");
    let len = 300_000;
    let server = ChaosServer::builder(33, len)
        .omit_content_length()
        .etag("\"v1\"")
        .stall_after(100_000)
        .chunk(64 * 1024)
        .start()
        .await
        .unwrap();
    let spec = undeclared_spec(&server, &dest, 33, len).build().unwrap();
    let downloader = single_attempt()
        .stall_timeout(Duration::from_secs(2))
        .build()
        .unwrap();

    downloader
        .download(&spec, None, CancellationToken::new())
        .await
        .unwrap_err();
    let part_len = std::fs::metadata(sidecar(&dest, ".part")).unwrap().len();
    assert!(
        part_len > 0 && part_len < len,
        "an unknown-length transfer left {part_len} bytes of a {len}-byte file, so a size was invented",
    );

    let verified = downloader
        .download(&spec, None, CancellationToken::new())
        .await
        .unwrap();
    let bytes = tokio::fs::read(verified.path()).await.unwrap();
    assert_eq!(bytes.len() as u64, len);
    assert_eq!(sha256_of(&bytes), body_sha256(33, len));
}

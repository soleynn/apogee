//! Disk-full injection end to end: a transfer whose destination cannot be reserved fails at
//! preallocation, distinctly and before the origin has served a payload byte.
//!
//! The destination sits on a memory-backed filesystem so the request can be sized past what that
//! filesystem can ever hold. That is the only shape of this test that is safe to run anywhere: a
//! disk-backed filesystem answers the same request by reserving blocks until the volume is genuinely
//! full, which on a shared machine takes the host's free space down with it.

#![cfg(target_os = "linux")]

use std::os::unix::fs::MetadataExt;

use apogee_fetch::{DownloadSpec, FetchError, Fetcher, Validator};
use apogee_test_support::capacity::memory_backed_dir;
use apogee_test_support::chaos::ChaosServer;
use tokio_util::sync::CancellationToken;

/// The slack the one `bytes=0-0` range-capability probe is worth in a byte count. The probe drops the
/// body unread, so whether its single byte is counted depends on the server's body task being
/// scheduled before the connection goes away.
const PROBE: u64 = 1;

/// The origin's file is small and never asked for: only the length the *spec* declares matters, and
/// that one is larger than the destination filesystem can hold.
const ORIGIN_LEN: u64 = 64 * 1024;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_transfer_that_cannot_be_reserved_fails_before_the_origin_serves_a_payload_byte() {
    let scratch = memory_backed_dir("apogee-fetch-disk-full-").unwrap();
    let dest = scratch.path().join("out.bin");
    let server = ChaosServer::builder(5, ORIGIN_LEN).start().await.unwrap();
    let fetcher = Fetcher::builder()
        .max_connections_per_file(4)
        .build()
        .unwrap();

    let spec = DownloadSpec::builder(server.url("f.bin"), &dest, Validator::Sha256([0u8; 32]))
        .expected_len(scratch.beyond_capacity())
        .build()
        .unwrap();
    let err = fetcher
        .download(&spec, None, CancellationToken::new())
        .await
        .unwrap_err();

    let FetchError::Io { source, .. } = &err else {
        panic!("want a typed I/O error, got {err:?}");
    };
    assert_eq!(
        source.kind(),
        std::io::ErrorKind::StorageFull,
        "want disk-full and not some other I/O fault, got {source:?}",
    );

    // The byte count is the eagerness claim: an error on its own would also be what a transfer that
    // streamed the whole file and then failed to publish it looks like. The request count carries the
    // half the byte count gives up when it admits the probe's tolerance, and pins which request was
    // the last one: the capability probe, with no segment ever asked for.
    let stats = server.stats();
    assert_eq!(
        stats.requests(),
        1,
        "only the capability probe should have been sent; ranges served: {:?}",
        stats.served_ranges(),
    );
    assert!(
        stats.bytes_served() <= PROBE,
        "origin served {} bytes before the reservation failed",
        stats.bytes_served(),
    );

    // The transfer got as far as creating the part file and no further: nothing was reserved for it,
    // nothing was written into it, and nothing was published.
    let part = scratch.path().join("out.bin.part");
    let meta = std::fs::metadata(&part).unwrap();
    assert_eq!(meta.blocks(), 0, "the refused reservation consumed blocks");
    assert_eq!(meta.len(), 0, "the refused reservation extended the file");
    assert!(!dest.exists(), "a failed transfer published a destination");

    // The same fact through the seam consumers actually route on. `apogee-patcher`,
    // `apogee-runtime`, and `apogee-addons` each turn a full disk into an out-of-space variant of
    // their own, and none of them matches `FetchError` itself: which variants can carry `ENOSPC` is
    // this crate's to know. Asserted here, on a real one, so the accessor is pinned to the shape the
    // kernel produces rather than only to hand-built errors in a unit test.
    let (refused, source) = err.into_out_of_space().expect("a full disk");
    assert_eq!(refused, part, "the accessor named a different file");
    assert_eq!(source.kind(), std::io::ErrorKind::StorageFull);
}

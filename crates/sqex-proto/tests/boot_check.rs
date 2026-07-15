//! Boot-check integration tests, driven through the fixture transport.
//!
//! These live outside the crate (not a `cfg(test)` module) so the `Transport` the fixture implements
//! and the one the surface consumes are the same compiled trait. The request is asserted byte-for-byte
//! (the drift alarm), and each response shape is exercised.

use apogee_test_support::rt::block_on;
use apogee_test_support::transport::{FixtureTransport, canonical_request};
use sqex_proto::{
    LauncherTime, ProtoError, ProtoResponse, Step, TransportError, check_boot_version,
};

const BOOT_VERSION: &str = "2012.01.01.0000.0000";

fn fixed_time() -> LauncherTime {
    // 03:47 UTC; the boot check floors the minute to 03:40.
    LauncherTime::from_parts(2024, 1, 2, 3, 47, 0)
}

/// Wrap synthetic six-field boot entries in the multipart envelope.
fn boot_patchlist(entries: &[&str]) -> Vec<u8> {
    let boundary = "--SYNTHETIC_BOUNDARY_APOGEE";
    let mut body = String::new();
    for header in [
        boundary,
        "Content-Type: application/octet-stream",
        "Content-Location: ffxivpatch/synthetic/metainfo/x.http",
        "X-Patch-Length: 0",
        "",
    ] {
        body.push_str(header);
        body.push_str("\r\n");
    }
    for entry in entries {
        body.push_str(entry);
        body.push_str("\r\n");
    }
    body.push_str(boundary);
    body.push_str("--\r\n");
    body.into_bytes()
}

#[test]
fn builds_the_fingerprinted_request() {
    let transport = FixtureTransport::once(ProtoResponse::new(200, Vec::new()));
    block_on(check_boot_version(&transport, BOOT_VERSION, &fixed_time())).unwrap();

    let recorded = transport.recorded();
    assert_eq!(recorded.len(), 1);
    assert_eq!(
        canonical_request(&recorded[0]),
        "GET http://patch-bootver.ffxiv.com/http/win32/ffxivneo_release_boot/2012.01.01.0000.0000/?time=2024-01-02-03-40\n\
         user-agent: FFXIV PATCH CLIENT\n\
         host: patch-bootver.ffxiv.com\n"
    );
}

#[test]
fn empty_body_means_boot_is_current() {
    let transport = FixtureTransport::once(ProtoResponse::new(200, Vec::new()));
    let entries = block_on(check_boot_version(&transport, BOOT_VERSION, &fixed_time())).unwrap();
    assert!(entries.is_empty());
}

#[test]
fn whitespace_body_means_boot_is_current() {
    let transport = FixtureTransport::once(ProtoResponse::new(200, b"  \r\n\t".to_vec()));
    let entries = block_on(check_boot_version(&transport, BOOT_VERSION, &fixed_time())).unwrap();
    assert!(entries.is_empty());
}

#[test]
fn parses_a_returned_boot_patchlist() {
    let entry = "900\t0\t0\t0\tD2024.01.01.0000.0000\t\
        http://patch-dl.example.invalid/boot/2b5cbc63/D2024.01.01.0000.0000.patch";
    let transport = FixtureTransport::once(ProtoResponse::new(200, boot_patchlist(&[entry])));
    let entries = block_on(check_boot_version(&transport, BOOT_VERSION, &fixed_time())).unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].length, 900);
    assert!(entries[0].hashes.is_none());
}

#[test]
fn a_non_200_status_is_an_invalid_response() {
    let transport = FixtureTransport::once(ProtoResponse::new(503, b"maintenance".to_vec()));
    let err = block_on(check_boot_version(&transport, BOOT_VERSION, &fixed_time())).unwrap_err();
    assert!(matches!(
        err,
        ProtoError::InvalidResponse {
            step: Step::BootVersion,
            status: 503,
            ..
        }
    ));
}

#[test]
fn a_transport_failure_propagates() {
    let transport = FixtureTransport::failing(TransportError::new("connection refused"));
    let err = block_on(check_boot_version(&transport, BOOT_VERSION, &fixed_time())).unwrap_err();
    assert!(matches!(err, ProtoError::Transport(_)));
}

//! Patchlist parser tests over synthetic bodies (no SE bytes): both entry shapes, the multipart-frame
//! validation, line-numbered errors, line-ending equivalence, and a panic-freedom property.

use proptest::prelude::*;

use super::parse_patch_list;
use crate::ProtoError;

/// An obviously-synthetic multipart boundary. The parser only requires it to open with `--`.
const BOUNDARY: &str = "--SYNTHETIC_BOUNDARY_APOGEE";

/// Wrap synthetic entry lines in the five-line preamble and two-line trailer, CRLF-joined.
fn envelope(entries: &[&str]) -> String {
    let mut body = String::new();
    for header in [
        BOUNDARY,
        "Content-Type: application/octet-stream",
        "Content-Location: ffxivpatch/synthetic/metainfo/D2024.01.01.0000.0000.http",
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
    body.push_str(BOUNDARY);
    body.push_str("--\r\n");
    body
}

/// A nine-field game entry line. Fields 1-3 are filler (their meaning is unpinned).
fn game_entry(length: u64, version: &str, block_size: u64, hashes: &str, url: &str) -> String {
    format!("{length}\t0\t0\t0\t{version}\tsha1\t{block_size}\t{hashes}\t{url}")
}

/// A six-field boot entry line: no hashes, URL in field 5.
fn boot_entry(length: u64, version: &str, url: &str) -> String {
    format!("{length}\t0\t0\t0\t{version}\t{url}")
}

const TWO_HASHES: &str =
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa,bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

#[test]
fn parses_a_game_entry_with_block_hashes() {
    let url = "http://patch-dl.example.invalid/game/ex1/abcd1234/D2024.01.02.0000.0000.patch";
    let line = game_entry(1200, "D2024.01.02.0000.0000", 52_428_800, TWO_HASHES, url);
    let entries = parse_patch_list(&envelope(&[line.as_str()])).unwrap();

    assert_eq!(entries.len(), 1);
    let entry = &entries[0];
    assert_eq!(entry.length, 1200);
    assert_eq!(entry.version_id, "D2024.01.02.0000.0000");
    assert_eq!(entry.url, url);
    let hashes = entry.hashes.as_ref().unwrap();
    assert_eq!(hashes.hash_type, "sha1");
    assert_eq!(hashes.block_size, 52_428_800);
    assert_eq!(hashes.hashes.len(), 2);
}

#[test]
fn parses_a_boot_entry_with_no_hashes() {
    let url = "http://patch-dl.example.invalid/boot/2b5cbc63/D2024.01.01.0000.0000.patch";
    let line = boot_entry(900, "D2024.01.01.0000.0000", url);
    let entries = parse_patch_list(&envelope(&[line.as_str()])).unwrap();

    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].url, url);
    assert!(entries[0].hashes.is_none());
}

#[test]
fn an_empty_entry_window_is_valid() {
    let entries = parse_patch_list(&envelope(&[])).unwrap();
    assert!(entries.is_empty());
}

#[test]
fn rejects_a_body_that_is_too_short() {
    let err = parse_patch_list("--x\r\na\r\nb\r\n").unwrap_err();
    assert!(matches!(
        err,
        ProtoError::PatchListParse {
            reason: "patchlist too short",
            ..
        }
    ));
}

#[test]
fn rejects_a_missing_opening_boundary() {
    let body = envelope(&[]).replacen(BOUNDARY, "NOT-A-BOUNDARY", 1);
    let err = parse_patch_list(&body).unwrap_err();
    assert!(matches!(
        err,
        ProtoError::PatchListParse {
            line: 1,
            reason: "missing opening multipart boundary",
        }
    ));
}

#[test]
fn rejects_a_mismatched_closing_boundary() {
    let body = envelope(&[]).replace(&format!("{BOUNDARY}--"), "--WRONG--");
    let err = parse_patch_list(&body).unwrap_err();
    assert!(matches!(
        err,
        ProtoError::PatchListParse {
            reason: "missing or mismatched closing multipart boundary",
            ..
        }
    ));
}

#[test]
fn rejects_an_invalid_patch_length() {
    let bad = "notanumber\t0\t0\t0\tD2024\thttp://x/boot/y/z.patch";
    let err = parse_patch_list(&envelope(&[bad])).unwrap_err();
    assert!(matches!(
        err,
        ProtoError::PatchListParse {
            reason: "invalid patch length",
            ..
        }
    ));
}

#[test]
fn rejects_a_malformed_block_hash() {
    let line = game_entry(10, "D2024", 100, "tooshort", "http://x/game/y/z.patch");
    let err = parse_patch_list(&envelope(&[line.as_str()])).unwrap_err();
    assert!(matches!(
        err,
        ProtoError::PatchListParse {
            reason: "malformed block hash",
            ..
        }
    ));
}

#[test]
fn reports_the_one_based_line_of_a_bad_entry() {
    // preamble is lines 1-5; entries at 6, 7, 8; the bad one is line 8.
    let good = boot_entry(1, "D1", "http://x/boot/y/a.patch");
    let bad = "oops\t0\t0\t0\tD3\thttp://x/boot/y/c.patch";
    let body = envelope(&[good.as_str(), good.as_str(), bad]);
    let err = parse_patch_list(&body).unwrap_err();
    assert!(matches!(
        err,
        ProtoError::PatchListParse {
            line: 8,
            reason: "invalid patch length",
        }
    ));
}

#[test]
fn crlf_and_lf_parse_identically() {
    let line = boot_entry(5, "D1", "http://x/boot/y/a.patch");
    let crlf = envelope(&[line.as_str()]);
    let lf = crlf.replace("\r\n", "\n");
    assert_eq!(
        parse_patch_list(&crlf).unwrap(),
        parse_patch_list(&lf).unwrap()
    );
}

#[test]
fn full_parse_is_pinned() {
    let game = game_entry(
        52_430_000,
        "D2024.01.02.0000.0000",
        52_428_800,
        TWO_HASHES,
        "http://patch-dl.example.invalid/game/ex1/abcd1234/D2024.01.02.0000.0000.patch",
    );
    let boot = boot_entry(
        900,
        "D2024.01.01.0000.0000",
        "http://patch-dl.example.invalid/boot/2b5cbc63/D2024.01.01.0000.0000.patch",
    );
    let entries = parse_patch_list(&envelope(&[game.as_str(), boot.as_str()])).unwrap();
    insta::assert_debug_snapshot!("patchlist_game_and_boot", entries);
}

proptest! {
    /// Structural fuzz over the characters a patchlist is built from: never panics, always a clean
    /// `Ok`/`Err`.
    #[test]
    fn parse_never_panics(input in "[0-9a-zA-Z\\t\\r\\n:/., -]{0,300}") {
        let _ = parse_patch_list(&input);
    }
}

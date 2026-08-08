use proptest::prelude::*;

use super::{MAX_BODY_BYTES, MAX_ENTRIES, parse_patch_list};
use crate::ProtoError;

const BOUNDARY: &str = "--SYNTHETIC_BOUNDARY_APOGEE";

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

fn game_entry(length: u64, version: &str, block_size: u64, hashes: &str, url: &str) -> String {
    format!("{length}\t0\t0\t0\t{version}\tsha1\t{block_size}\t{hashes}\t{url}")
}

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
fn rejects_an_entry_with_too_few_fields() {
    // Five tab fields: one short of the six a boot entry needs.
    let bad = "1\t0\t0\t0\tD2024.01.01.0000.0000";
    let err = parse_patch_list(&envelope(&[bad])).unwrap_err();
    assert!(matches!(
        err,
        ProtoError::PatchListParse {
            reason: "too few tab-separated fields",
            ..
        }
    ));
}

#[test]
fn rejects_a_non_numeric_hash_block_size() {
    // A nine-field game entry whose block-size field (index 6) is not a number.
    let bad =
        format!("10\t0\t0\t0\tD2024\tsha1\tnotanumber\t{TWO_HASHES}\thttp://x/game/y/z.patch");
    let err = parse_patch_list(&envelope(&[bad.as_str()])).unwrap_err();
    assert!(matches!(
        err,
        ProtoError::PatchListParse {
            reason: "invalid hash block size",
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

fn reason_of(err: ProtoError) -> &'static str {
    match err {
        ProtoError::PatchListParse { reason, .. } => reason,
        other => panic!("expected a patchlist parse error, got {other:?}"),
    }
}

#[test]
fn rejects_a_game_entry_with_a_stray_trailing_tab() {
    // A well-formed nine-field game entry plus one stray tab. XL's parser reclassifies any non-nine
    // count as a boot entry, which would read field 5 (`sha1`) as the URL and silently drop the
    // block hashes; the exact dispatch refuses it instead.
    let line = game_entry(
        1200,
        "D2024.01.02.0000.0000",
        52_428_800,
        TWO_HASHES,
        "http://patch-dl.example.invalid/game/ex1/abcd1234/D2024.01.02.0000.0000.patch",
    );
    let err = parse_patch_list(&envelope(&[format!("{line}\t").as_str()])).unwrap_err();
    assert_eq!(reason_of(err), "unexpected tab-separated field count");
}

#[test]
fn only_six_and_nine_field_entries_are_accepted() {
    // Field counts between and beyond the two real shapes are errors, not boot entries. Seven and
    // eight sit between them; ten is a game entry that grew a field.
    for extra in [1, 2, 4] {
        let line = format!(
            "100\t0\t0\t0\tD2024\thttp://x/boot/y/z.patch{}",
            "\tx".repeat(extra)
        );
        let err = parse_patch_list(&envelope(&[line.as_str()])).unwrap_err();
        assert_eq!(
            reason_of(err),
            "unexpected tab-separated field count",
            "a {}-field entry must not parse",
            6 + extra
        );
    }
}

#[test]
fn rejects_content_in_the_final_blank_trailer_line() {
    // A full entry line placed where the envelope's final blank belongs is outside the window XL
    // (and this parser) reads, so it would be dropped with an `Ok`.
    let good = boot_entry(1, "D1", "http://x/boot/y/a.patch");
    let smuggled = boot_entry(2, "D2", "http://x/boot/y/b.patch");
    // No trailing newline: the smuggled line lands *in* the final-blank slot rather than shifting
    // the window (which the closing-boundary check would already catch).
    let body = format!("{}{smuggled}", envelope(&[good.as_str()]));
    let err = parse_patch_list(&body).unwrap_err();
    assert!(matches!(
        err,
        ProtoError::PatchListParse {
            line: 8,
            reason: "unexpected content after closing multipart boundary",
        }
    ));
}

#[test]
fn a_whitespace_trailer_line_is_still_valid() {
    let line = boot_entry(1, "D1", "http://x/boot/y/a.patch");
    let body = envelope(&[line.as_str()]).replace("--\r\n", "--\r\n  \t");
    assert_eq!(parse_patch_list(&body).unwrap().len(), 1);
}

#[test]
fn rejects_a_body_over_the_size_cap() {
    let body = "x".repeat(MAX_BODY_BYTES + 1);
    let err = parse_patch_list(&body).unwrap_err();
    assert_eq!(reason_of(err), "patchlist body too large");
}

#[test]
fn rejects_more_entry_lines_than_the_cap_allows() {
    // Blank filler, not real entries: the cap has to reject before the entry loop can allocate, so
    // a body that never reaches `parse_entry` still has to be refused on its line count alone.
    let filler = vec![""; MAX_ENTRIES + 1];
    let err = parse_patch_list(&envelope(&filler)).unwrap_err();
    assert_eq!(reason_of(err), "too many patchlist entries");
}

#[test]
fn an_entry_count_at_the_cap_is_accepted() {
    let line = boot_entry(1, "D1", "http://x/boot/y/a.patch");
    let entries = vec![line.as_str(); MAX_ENTRIES];
    assert_eq!(
        parse_patch_list(&envelope(&entries)).unwrap().len(),
        MAX_ENTRIES
    );
}

#[test]
fn rejects_a_url_field_that_is_not_a_url() {
    // The value a stray-tab game entry used to land in `url` before the field count was matched
    // exactly: a second line of defense on the same mis-slice.
    let bad = "100\t0\t0\t0\tD2024\tsha1";
    let err = parse_patch_list(&envelope(&[bad])).unwrap_err();
    assert_eq!(reason_of(err), "malformed patch URL");

    // A relative path and a non-HTTP scheme are likewise not fetchable.
    for url in ["/boot/y/z.patch", "file:///etc/passwd"] {
        let line = boot_entry(100, "D2024", url);
        let err = parse_patch_list(&envelope(&[line.as_str()])).unwrap_err();
        assert_eq!(
            reason_of(err),
            "malformed patch URL",
            "{url} must not parse"
        );
    }
}

#[test]
fn the_stored_url_is_the_normalized_form_not_the_raw_field() {
    // `Url::parse` both validates and normalizes: it trims surrounding whitespace and fills in a
    // missing `//` authority separator for a special scheme like `http`. The stored `url` must be
    // what was actually validated, or a consumer deriving a cache key or filename from it would
    // inherit un-normalized bytes that never went through the check above.
    let cases = [
        (
            "  http://patch-dl.example.invalid/boot/y/z.patch  ",
            "http://patch-dl.example.invalid/boot/y/z.patch",
        ),
        (
            "http:patch-dl.example.invalid/boot/y/z.patch",
            "http://patch-dl.example.invalid/boot/y/z.patch",
        ),
    ];
    for (field, normalized) in cases {
        let line = boot_entry(100, "D2024", field);
        let entries = parse_patch_list(&envelope(&[line.as_str()])).unwrap();
        assert_eq!(entries[0].url, normalized, "raw field was {field:?}");
    }
}

#[test]
fn repo_resolution_is_deliberately_left_to_the_consumer() {
    // Pins the scope decision documented on `parse_url`: a URL with no `/(game|boot)/{repoId}/`
    // segment, and one naming a repo beyond the range this workspace enumerates, are both accepted
    // here. Classifying them is the consumer's call (`apogee_core::patch::classify_repo`), and
    // rejecting an unknown-but-fetchable repo would make a new expansion a hard patch-day failure.
    for url in [
        "http://patch-dl.example.invalid/not-a-repo-segment/x.patch",
        "http://patch-dl.example.invalid/game/ex6/abcd1234/D2024.01.02.0000.0000.patch",
    ] {
        let line = boot_entry(100, "D2024", url);
        let entries = parse_patch_list(&envelope(&[line.as_str()])).unwrap();
        assert_eq!(entries[0].url, url);
    }
}

proptest! {
    #[test]
    fn parse_never_panics(input in "[0-9a-zA-Z\\t\\r\\n:/., -]{0,300}") {
        let _ = parse_patch_list(&input);
    }
}

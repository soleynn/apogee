// Peak-memory bound for a single hostile patchlist entry line. parse_entry must count a line's
// tab-separated fields before collecting them into a Vec<&str>. Before that fix, a single entry line
// made of tab bytes, sized within the crate's own overall body cap, materialized one &str slice per
// field before the field count was ever checked: ~16 MiB of tab bytes produced roughly 16.7 million
// slices, about 267 MB of peak RSS from 16 MB of wire input, a ~16.9x amplification measured on a
// release build via /proc/self/status (VmHWM). Linux-only (reads /proc/self/status).

#![cfg(target_os = "linux")]

use sqex_proto::{ProtoError, parse_patch_list};

const BOUNDARY: &str = "--SYNTHETIC_BOUNDARY_APOGEE";

const MAX_BODY_BYTES: usize = 16 * 1024 * 1024;

fn envelope(entry: &str) -> String {
    let mut body = String::new();
    for header in [
        BOUNDARY,
        "Content-Type: application/octet-stream",
        "Content-Location: ffxivpatch/synthetic/metainfo/x.http",
        "X-Patch-Length: 0",
        "",
    ] {
        body.push_str(header);
        body.push_str("\r\n");
    }
    body.push_str(entry);
    body.push_str("\r\n");
    body.push_str(BOUNDARY);
    body.push_str("--\r\n");
    body
}

fn peak_rss_kib() -> Option<u64> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("VmHWM:") {
            return rest.split_whitespace().next()?.parse::<u64>().ok();
        }
    }
    None
}

#[test]
fn a_hostile_entry_line_does_not_amplify_into_a_per_field_allocation() {
    // The preamble, boundary, and CRLFs around the entry line; the entry itself is sized so the whole
    // body stays under the cap with room to spare.
    const ENVELOPE_OVERHEAD: usize = 256;
    let entry_len = MAX_BODY_BYTES - ENVELOPE_OVERHEAD;
    let entry = "\t".repeat(entry_len);
    let body = envelope(&entry);
    assert!(
        body.len() <= MAX_BODY_BYTES,
        "test body of {} bytes exceeds the crate's own {MAX_BODY_BYTES}-byte cap; \
         the cap would reject it before the per-line guard runs",
        body.len(),
    );

    let before = peak_rss_kib().unwrap_or(0);
    let err = parse_patch_list(&body).unwrap_err();
    let after = peak_rss_kib().unwrap_or(0);

    assert!(
        matches!(
            err,
            ProtoError::PatchListParse {
                reason: "unexpected tab-separated field count",
                ..
            }
        ),
        "expected the field-count guard to fire, got {err:?}",
    );

    // The fixed parser allocates the newline-normalized copy of the body (~16 MB) plus a small line
    // vector; it never collects the hostile line's ~16.7 million fields into a `Vec<&str>`, which cost
    // roughly 267 MB (16 bytes per slice) before this fix. 64 MiB leaves generous headroom above the
    // expected growth while staying far under what the unpatched parser cost.
    let growth_kib = after.saturating_sub(before);
    assert!(
        growth_kib < 64 * 1024,
        "peak RSS grew by {growth_kib} KiB parsing one hostile entry line; \
         the per-field Vec<&str> amplification is back",
    );
}

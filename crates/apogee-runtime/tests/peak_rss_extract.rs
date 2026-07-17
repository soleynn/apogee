//! Peak-memory bound: extraction's resident set stays a function of the decoder window, not the
//! archive's decompressed size. The fixture is streamed to disk (never a payload-sized buffer) so
//! the process high-water mark reflects extraction alone. Linux-only (reads `/proc/self/status`);
//! the multi-gigabyte run is `#[ignore]`d for local soak.

#![cfg(target_os = "linux")]

use std::fs::File;
use std::io::{self, Read};
use std::path::Path;

use apogee_runtime::{ArchiveFormat, ArchiveLayout, extract_archive};

/// The process's peak resident set in KiB (`VmHWM`), if readable.
fn peak_rss_kib() -> Option<u64> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("VmHWM:") {
            return rest.split_whitespace().next()?.parse::<u64>().ok();
        }
    }
    None
}

/// Stream a gzip'd tar holding one `file_len`-byte file to `path`, without buffering the payload.
fn write_big_gz_archive(path: &Path, file_len: u64) -> io::Result<()> {
    let file = File::create(path)?;
    let encoder = flate2::write::GzEncoder::new(file, flate2::Compression::fast());
    let mut builder = tar::Builder::new(encoder);
    let mut header = tar::Header::new_gnu();
    header.set_size(file_len);
    header.set_mode(0o644);
    header.set_entry_type(tar::EntryType::Regular);
    builder.append_data(
        &mut header,
        "runner-1.0/big.bin",
        io::repeat(0u8).take(file_len),
    )?;
    builder.into_inner()?.finish()?;
    Ok(())
}

fn assert_bounded_extraction(file_len: u64) -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let archive = dir.path().join("big.tar.gz");
    write_big_gz_archive(&archive, file_len)?;
    let dest = dir.path().join("out");
    let layout = ArchiveLayout {
        format: ArchiveFormat::TarGz,
        strip_prefix: Some("runner-1.0".to_owned()),
    };

    let before = peak_rss_kib().unwrap_or(0);
    extract_archive(&archive, &layout, &dest)?;
    let after = peak_rss_kib().unwrap_or(0);

    assert_eq!(std::fs::metadata(dest.join("big.bin"))?.len(), file_len);
    let growth_kib = after.saturating_sub(before);
    assert!(
        growth_kib < 64 * 1024,
        "peak RSS grew by {growth_kib} KiB extracting a {} MiB payload; memory must not scale with it",
        file_len / 1024 / 1024,
    );
    Ok(())
}

#[test]
fn extracting_a_large_archive_holds_memory_flat() {
    assert_bounded_extraction(256 * 1024 * 1024).unwrap();
}

#[test]
#[ignore = "multi-gigabyte soak; run locally"]
fn extracting_two_gib_holds_memory_flat() {
    assert_bounded_extraction(2 * 1024 * 1024 * 1024).unwrap();
}

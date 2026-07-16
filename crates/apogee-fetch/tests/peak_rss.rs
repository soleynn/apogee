//! Peak-memory bound: a download's resident memory stays a function of the buffer, not the file.
//!
//! Streams a file that dwarfs any internal buffer and checks that the process's peak resident set
//! (`VmHWM`) barely grows: a download that buffered the whole body would spike by hundreds of
//! megabytes. Linux-only (it reads `/proc/self/status`); the aspirational multi-gigabyte run is
//! `#[ignore]`d for local soak.

#![cfg(target_os = "linux")]

use apogee_fetch::{DownloadSpec, Fetcher, Validator};
use apogee_test_support::chaos::{ChaosServer, generate_into};
use sha2::{Digest, Sha256};
use tokio_util::sync::CancellationToken;

fn body_sha256(seed: u64, len: u64) -> [u8; 32] {
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 256 * 1024];
    let mut off = 0u64;
    while off < len {
        let want = (len - off).min(buf.len() as u64) as usize;
        generate_into(seed, off, &mut buf[..want]);
        hasher.update(&buf[..want]);
        off += want as u64;
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&hasher.finalize());
    out
}

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

async fn assert_bounded_peak_rss(len: u64) -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let dest = dir.path().join("big.bin");
    let server = ChaosServer::builder(1, len)
        .chunk(256 * 1024)
        .start()
        .await?;
    let spec = DownloadSpec::builder(
        server.url("big.bin"),
        &dest,
        Validator::Sha256(body_sha256(1, len)),
    )
    .expected_len(len)
    .build()?;

    let before = peak_rss_kib().unwrap_or(0);
    let verified = Fetcher::builder()
        .build()?
        .download(&spec, None, CancellationToken::new())
        .await?;
    let after = peak_rss_kib().unwrap_or(0);

    assert_eq!(tokio::fs::metadata(verified.path()).await?.len(), len);
    let growth_kib = after.saturating_sub(before);
    assert!(
        growth_kib < 64 * 1024,
        "peak RSS grew by {growth_kib} KiB while streaming {} MiB; memory must not scale with file size",
        len / 1024 / 1024,
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn streaming_a_large_file_holds_memory_flat() {
    assert_bounded_peak_rss(128 * 1024 * 1024).await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "multi-gigabyte soak; run locally"]
async fn streaming_four_gib_holds_memory_flat() {
    assert_bounded_peak_rss(4 * 1024 * 1024 * 1024)
        .await
        .unwrap();
}

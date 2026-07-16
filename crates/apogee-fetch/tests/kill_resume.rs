//! Property test: repeated interruptions converge to a byte-identical file within a bounded amount
//! of re-downloaded data.
//!
//! Each case interrupts a download at a random set of progress points, resumes from the journal after
//! every interruption, and finally lets it complete. The final file must hash to the source, and the
//! total bytes the server handed out must stay within `file + interruptions * batch`: a download that
//! restarted from zero on each resume would serve several times the file and blow the budget.

use apogee_fetch::{DownloadSpec, Fetcher, Progress, Validator};
use apogee_test_support::chaos::{ChaosServer, body_sha256, sha256_of};
use proptest::prelude::*;
use tokio_util::sync::CancellationToken;

/// The whole-file size each case downloads (a few fsync batches' worth).
const FILE_LEN: u64 = 3 * 1024 * 1024;
/// Mirrors the engine's fsync/journal cadence: a resume re-fetches at most this much per interruption.
const BATCH: u64 = 1024 * 1024;

/// Download `FILE_LEN` bytes from `seed`, cancelling once each time progress crosses a point in
/// `interrupt_at`, then completing. Returns the final file's hash and the server's total bytes served.
async fn download_with_interruptions(
    seed: u64,
    interrupt_at: &[u64],
) -> Result<([u8; 32], u64), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let dest = dir.path().join("out.bin");
    let server = ChaosServer::builder(seed, FILE_LEN)
        .etag("\"v1\"")
        .chunk(64 * 1024)
        .start()
        .await?;
    let spec = DownloadSpec::builder(
        server.url("file.bin"),
        &dest,
        Validator::Sha256(body_sha256(seed, FILE_LEN)),
    )
    .expected_len(FILE_LEN)
    .build()?;
    let downloader = Fetcher::builder().build()?;

    for &point in interrupt_at {
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<Progress>();
        let cancel = CancellationToken::new();
        let trigger = cancel.clone();
        let watcher = tokio::spawn(async move {
            while let Some(progress) = rx.recv().await {
                if progress.bytes_done >= point {
                    trigger.cancel();
                    break;
                }
            }
        });
        // Ignore the outcome: a cancel is an error, and a race that completes first is fine.
        let _ = downloader.download(&spec, Some(tx), cancel).await;
        watcher.abort();
        let _ = watcher.await;
    }

    let verified = downloader
        .download(&spec, None, CancellationToken::new())
        .await?;
    let bytes = tokio::fs::read(verified.path()).await?;
    Ok((sha256_of(&bytes), server.stats().bytes_served()))
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(24))]

    #[test]
    fn resumes_byte_identically_within_a_waste_budget(
        seed in any::<u64>(),
        interrupt_at in prop::collection::vec(1u64..FILE_LEN, 0..5),
    ) {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        let (hash, served) = runtime
            .block_on(download_with_interruptions(seed, &interrupt_at))
            .unwrap();

        prop_assert_eq!(hash, body_sha256(seed, FILE_LEN));
        let budget = FILE_LEN + (interrupt_at.len() as u64 + 1) * BATCH;
        prop_assert!(
            served <= budget,
            "served {} bytes for a {}-byte file with {} interruptions (budget {})",
            served,
            FILE_LEN,
            interrupt_at.len(),
            budget,
        );
    }
}

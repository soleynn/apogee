//! Property test: an arbitrary set of dirty blocks is each re-fetched exactly once, and the file
//! still verifies byte-for-byte, with no other range re-served.

use apogee_fetch::{DownloadSpec, Fetcher, Validator};
use apogee_test_support::chaos::{ChaosServer, block_hashes, generated_vec};
use proptest::prelude::*;
use tokio_util::sync::CancellationToken;

const MIB: u64 = 1024 * 1024;
const LEN: u64 = 12 * MIB;
const BLOCK_SIZE: u32 = 2 * MIB as u32; // six blocks across two segments
const BLOCKS: u32 = 6;
/// The one byte a `bytes=0-0` range-capability probe serves before the transfer starts.
const PROBE: u64 = 1;

proptest! {
    #![proptest_config(ProptestConfig::with_cases(16))]

    #[test]
    fn each_dirty_block_is_re_fetched_once_and_the_file_verifies(
        seed in any::<u64>(),
        dirty in prop::collection::hash_set(0u32..BLOCKS, 0..BLOCKS as usize),
    ) {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(4)
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let dir = tempfile::tempdir().unwrap();
            let dest = dir.path().join("out.bin");

            let mut builder = ChaosServer::builder(seed, LEN);
            for &b in &dirty {
                let start = u64::from(b) * u64::from(BLOCK_SIZE);
                builder = builder.corrupt_range_once(start..start + u64::from(BLOCK_SIZE));
            }
            let server = builder.start().await.unwrap();

            let spec = DownloadSpec::builder(
                server.url("f.bin"),
                &dest,
                Validator::BlockSha1 { block_size: BLOCK_SIZE, hashes: block_hashes(seed, LEN, BLOCK_SIZE) },
            )
            .expected_len(LEN)
            .build()
            .unwrap();

            let verified = Fetcher::builder()
                .max_connections_per_file(4)
                .build()
                .unwrap()
                .download(&spec, None, CancellationToken::new())
                .await
                .unwrap();

            let bytes = tokio::fs::read(verified.path()).await.unwrap();
            prop_assert_eq!(bytes, generated_vec(seed, 0, LEN as usize));
            // The whole file once, one re-fetch per dirty block, and the probe byte: nothing else.
            let expected = LEN + dirty.len() as u64 * u64::from(BLOCK_SIZE) + PROBE;
            prop_assert_eq!(server.stats().bytes_served(), expected);
            Ok(())
        })?;
    }
}

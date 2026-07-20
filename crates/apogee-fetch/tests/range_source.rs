//! `HttpRangeSource` implementing `apogee-zipatch`'s `RangeSource` seam: it fetches a patch's byte
//! ranges over HTTP and hands them to the planner's callback. `read_ranges` is synchronous and
//! bridges to the async fetcher with `Handle::block_on`, so it is driven from `spawn_blocking` (off
//! the runtime) exactly as `apogee-zipatch`'s repair will run it.

use std::collections::BTreeMap;
use std::error::Error;
use std::ops::Range;

use apogee_fetch::{Fetcher, HttpRangeSource, HttpSource};
use apogee_test_support::chaos::{ChaosServer, generated_vec};
use apogee_zipatch::{PatchId, RangeSource};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn read_ranges_fetches_a_patch_over_http() -> Result<(), Box<dyn Error>> {
    let (seed, len) = (5, 4096);
    let server = ChaosServer::builder(seed, len).start().await?;
    let fetcher = Fetcher::builder().build()?;
    let handle = tokio::runtime::Handle::current();
    let sources = vec![HttpSource {
        url: server.url("p0.patch"),
        expected_len: len,
        policy: None,
    }];
    let mut src = HttpRangeSource::new(fetcher, handle, sources);

    let ranges: Vec<Range<u64>> = vec![100..200, 3000..3100];
    let ranges_for_task = ranges.clone();
    // Repair runs off the runtime; `Handle::block_on` inside `read_ranges` requires it.
    let got = tokio::task::spawn_blocking(
        move || -> Result<BTreeMap<u64, u8>, apogee_zipatch::Error> {
            let mut got: BTreeMap<u64, u8> = BTreeMap::new();
            let mut out = |off: u64, bytes: &[u8]| -> apogee_zipatch::Result<()> {
                for (i, b) in bytes.iter().enumerate() {
                    got.insert(off + i as u64, *b);
                }
                Ok(())
            };
            src.read_ranges(PatchId(0), &ranges_for_task, &mut out)?;
            Ok(got)
        },
    )
    .await??;

    for r in &ranges {
        let expected = generated_vec(seed, r.start, (r.end - r.start) as usize);
        let actual: Vec<u8> = (r.start..r.end).map(|o| got[&o]).collect();
        assert_eq!(actual, expected, "range {r:?}");
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_unknown_patch_id_is_a_corrupt_error() -> Result<(), Box<dyn Error>> {
    let server = ChaosServer::builder(1, 100).start().await?;
    let fetcher = Fetcher::builder().build()?;
    let handle = tokio::runtime::Handle::current();
    let sources = vec![HttpSource {
        url: server.url("p0.patch"),
        expected_len: 100,
        policy: None,
    }];
    let mut src = HttpRangeSource::new(fetcher, handle, sources);

    let ranges: Vec<Range<u64>> = std::iter::once(0u64..10).collect();
    let err = tokio::task::spawn_blocking(move || {
        let mut out = |_off: u64, _bytes: &[u8]| -> apogee_zipatch::Result<()> { Ok(()) };
        src.read_ranges(PatchId(5), &ranges, &mut out)
    })
    .await?
    .expect_err("patch id out of range");
    assert!(matches!(err, apogee_zipatch::Error::Corrupt { .. }));
    Ok(())
}

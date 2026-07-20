//! `Fetcher::fetch_ranges` against the chaos server: the three response shapes (single `206`,
//! `multipart/byteranges`, and a range-ignoring `200`) and range packing under a strict request-
//! header-size limit.

use std::collections::BTreeMap;
use std::error::Error;
use std::ops::Range;

use apogee_fetch::{FetchError, Fetcher, HeaderPolicy, RangePacking};
use apogee_test_support::chaos::{ChaosServer, generated_vec};

/// Fetch `ranges` of `server`'s body and return every delivered byte keyed by its absolute offset.
/// Errors propagate with `?` so no `unwrap` lives in this free helper.
async fn collect(
    server: &ChaosServer,
    len: u64,
    ranges: &[Range<u64>],
    policy: Option<&HeaderPolicy>,
    packing: RangePacking,
) -> Result<BTreeMap<u64, u8>, Box<dyn Error>> {
    let fetcher = Fetcher::builder().build()?;
    let url = server.url("f.bin");
    let mut got: BTreeMap<u64, u8> = BTreeMap::new();
    fetcher
        .fetch_ranges(&url, len, ranges, policy, packing, |off, bytes| {
            for (i, b) in bytes.iter().enumerate() {
                got.insert(off + i as u64, *b);
            }
            Ok::<(), FetchError>(())
        })
        .await?;
    Ok(got)
}

/// Assert the delivered bytes tile `ranges` exactly and match the server's generated content.
fn assert_exact(seed: u64, got: &BTreeMap<u64, u8>, ranges: &[Range<u64>]) {
    let mut expected_total = 0u64;
    for r in ranges {
        let expected = generated_vec(seed, r.start, (r.end - r.start) as usize);
        let actual: Vec<u8> = (r.start..r.end).map(|o| got[&o]).collect();
        assert_eq!(actual, expected, "range {r:?}");
        expected_total += r.end - r.start;
    }
    // Nothing beyond the requested ranges was delivered.
    assert_eq!(got.len() as u64, expected_total, "extra bytes delivered");
}

#[tokio::test]
async fn a_single_range_is_a_206_and_slices_correctly() {
    let (seed, len) = (7, 5000);
    let server = ChaosServer::builder(seed, len).start().await.unwrap();
    let ranges: Vec<Range<u64>> = std::iter::once(1000..1100).collect();
    let got = collect(&server, len, &ranges, None, RangePacking::default())
        .await
        .unwrap();
    assert_exact(seed, &got, &ranges);
    assert_eq!(server.stats().requests(), 1);
}

#[tokio::test]
async fn multiple_ranges_are_one_multipart_response() {
    let (seed, len) = (11, 8000);
    let server = ChaosServer::builder(seed, len).start().await.unwrap();
    let ranges = vec![10..50, 2000..2100, 7900..8000];
    let got = collect(&server, len, &ranges, None, RangePacking::default())
        .await
        .unwrap();
    assert_exact(seed, &got, &ranges);
    // All three ranges pack into one request, answered as one multipart body.
    assert_eq!(server.stats().requests(), 1);
    assert_eq!(server.stats().served_ranges().len(), 3);
}

#[tokio::test]
async fn a_range_ignoring_200_is_streamed_and_sliced() {
    let (seed, len) = (13, 6000);
    // accept_ranges(false): the server returns the whole body with 200 and no Content-Range.
    let server = ChaosServer::builder(seed, len)
        .accept_ranges(false)
        .start()
        .await
        .unwrap();
    let ranges = vec![100..200, 5000..5500];
    let got = collect(&server, len, &ranges, None, RangePacking::default())
        .await
        .unwrap();
    // Only the requested bytes are delivered even though the whole file was streamed.
    assert_exact(seed, &got, &ranges);
    assert_eq!(
        server.stats().bytes_served(),
        len,
        "full body streamed once"
    );
}

#[tokio::test]
async fn packing_stays_under_a_strict_request_header_limit() {
    let (seed, len) = (17, 10_000);
    // A tight app-level header cap: a single packed request of every range would blow past it, so the
    // packer must split into many small requests. `request_header_bytes` counts method+path+headers.
    let server = ChaosServer::builder(seed, len)
        .max_request_header_bytes(150)
        .start()
        .await
        .unwrap();
    let ranges: Vec<Range<u64>> = (0..30).map(|i| (i * 300)..(i * 300 + 10)).collect();
    // A ~20-byte Range value budget forces roughly one range per request.
    let packing = RangePacking {
        max_ranges: 256,
        max_range_header_bytes: 20,
    };
    let got = collect(&server, len, &ranges, None, packing).await.unwrap();
    assert_exact(seed, &got, &ranges);
    // The transfer succeeded (no 431), and it took more than one request to stay under the limit.
    assert!(server.stats().requests() > 1, "expected split requests");
}

//! The fetch↔zipatch integration checkpoint: damage an installed tree, verify, and repair it over
//! HTTP through `HttpRangeSource`, confirming the tree is byte-identical again while only the broken
//! ranges were pulled. Patch bytes are served by the chaos server (one per source patch), and the
//! synthetic patches come from `apogee_zipatch::fixtures` so the format has one owner.

use std::error::Error;
use std::path::Path;

use apogee_fetch::{Fetcher, HttpRangeSource, HttpSource, RangePacking};
use apogee_test_support::chaos::ChaosServer;
use apogee_test_support::tree_manifest;
use apogee_zipatch::{VerifyOptions, fixtures};

/// Overwrite a byte range of a file with `fill` (whole-file read/modify/write; the fixtures are tiny).
fn overwrite(path: &Path, off: usize, fill: &[u8]) -> std::io::Result<()> {
    let mut data = std::fs::read(path)?;
    data[off..off + fill.len()].copy_from_slice(fill);
    std::fs::write(path, data)
}

/// Serve each patch of `chain` from its own chaos server; `sources[i]`/`servers[i]` back `PatchId(i)`.
async fn serve(chain: &[Vec<u8>]) -> Result<(Vec<ChaosServer>, Vec<HttpSource>), Box<dyn Error>> {
    let mut servers = Vec::new();
    let mut sources = Vec::new();
    for (i, patch) in chain.iter().enumerate() {
        let server = ChaosServer::serving(patch.clone()).start().await?;
        sources.push(HttpSource {
            url: server.url(&format!("p{i}.patch")),
            expected_len: patch.len() as u64,
            policy: None,
        });
        servers.push(server);
    }
    Ok((servers, sources))
}

/// A one-patch chain with two stored parts (`a.bin`, `b.bin`) separated by an 8 KiB filler, so their
/// source ranges sit far enough apart that the repair planner does not merge them: corrupting both
/// yields a single `read_ranges` call carrying two ranges.
fn far_apart_patch() -> Vec<u8> {
    let mut b = fixtures::PatchBuilder::new();
    b.fhdr(b"DIFF", 0).target_info(fixtures::WIN32);
    b.file_op(
        b'A',
        0,
        128,
        "a.bin",
        &fixtures::block_stored(&[0xA1u8; 128]),
    );
    b.file_op(
        b'A',
        0,
        8192,
        "filler.bin",
        &fixtures::block_stored(&[0xB2u8; 8192]),
    );
    b.file_op(
        b'A',
        0,
        128,
        "b.bin",
        &fixtures::block_stored(&[0xC3u8; 128]),
    );
    b.eof();
    b.bytes()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn repair_over_http_pulls_only_the_broken_ranges() -> Result<(), Box<dyn Error>> {
    let chain = fixtures::chain();
    let applied = tempfile::tempdir()?;
    fixtures::apply_chain(applied.path(), &chain)?;
    let index = fixtures::build_from(&chain)?;
    let baseline = tree_manifest::author(applied.path())?;

    // One broken part in each patch: ffxivboot.exe[0,100) (patch 0, 100 B) and the dat's [256,384)
    // write (patch 1, 128 B). Each becomes a single-range request answered with a single 206.
    overwrite(&applied.path().join("ffxivboot.exe"), 0, &[0xFF])?;
    overwrite(&applied.path().join(fixtures::DAT0_PATH), 256, &[0xFF])?;
    let report = index.verify(applied.path(), &VerifyOptions::default())?;
    assert!(!report.is_clean());

    let (servers, sources) = serve(&chain).await?;
    let fetcher = Fetcher::builder().build()?;
    let handle = tokio::runtime::Handle::current();
    let mut src = HttpRangeSource::new(fetcher, handle, sources);

    let root = applied.path().to_path_buf();
    let outcome =
        tokio::task::spawn_blocking(move || index.repair(&root, &report, &mut src)).await??;
    assert!(
        outcome.is_complete(),
        "still broken: {:?}",
        outcome.still_broken
    );

    // Byte-accounting: each server delivered only its broken part, far below its patch length.
    assert_eq!(servers[0].stats().bytes_served(), 100);
    assert_eq!(servers[1].stats().bytes_served(), 128);
    for (i, patch) in chain.iter().enumerate() {
        assert!(
            servers[i].stats().bytes_served() < patch.len() as u64,
            "server {i} served more than a broken part",
        );
    }
    assert_eq!(outcome.bytes_fetched, 100 + 128);

    let now = tree_manifest::author(applied.path())?;
    assert_eq!(
        now.files, baseline.files,
        "repaired tree must match baseline"
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn repair_over_http_exercises_the_multipart_path() -> Result<(), Box<dyn Error>> {
    let chain = vec![far_apart_patch()];
    let applied = tempfile::tempdir()?;
    fixtures::apply_chain(applied.path(), &chain)?;
    let index = fixtures::build_from(&chain)?;
    let baseline = tree_manifest::author(applied.path())?;

    // Two parts of the same patch, far enough apart not to merge: one read_ranges call with two
    // ranges packs into one multi-range request, which the server answers as multipart/byteranges.
    overwrite(&applied.path().join("a.bin"), 0, &[0xFF])?;
    overwrite(&applied.path().join("b.bin"), 0, &[0xFF])?;
    let report = index.verify(applied.path(), &VerifyOptions::default())?;
    assert_eq!(report.broken.len(), 2);

    let (servers, sources) = serve(&chain).await?;
    let fetcher = Fetcher::builder().build()?;
    let handle = tokio::runtime::Handle::current();
    let mut src = HttpRangeSource::new(fetcher, handle, sources);

    let root = applied.path().to_path_buf();
    let outcome =
        tokio::task::spawn_blocking(move || index.repair(&root, &report, &mut src)).await??;
    assert!(outcome.is_complete());

    // One request, answered as a multipart body serving both broken parts.
    assert_eq!(servers[0].stats().requests(), 1);
    assert_eq!(servers[0].stats().served_ranges().len(), 2);

    let now = tree_manifest::author(applied.path())?;
    assert_eq!(now.files, baseline.files);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn repair_over_http_packs_under_a_strict_header_limit() -> Result<(), Box<dyn Error>> {
    let chain = vec![far_apart_patch()];
    let applied = tempfile::tempdir()?;
    fixtures::apply_chain(applied.path(), &chain)?;
    let index = fixtures::build_from(&chain)?;
    let baseline = tree_manifest::author(applied.path())?;

    overwrite(&applied.path().join("a.bin"), 0, &[0xFF])?;
    overwrite(&applied.path().join("b.bin"), 0, &[0xFF])?;
    let report = index.verify(applied.path(), &VerifyOptions::default())?;

    // A strict app-level header cap plus a tiny Range-value budget: the two ranges must split into
    // separate requests rather than pack into one oversized header.
    let server = ChaosServer::serving(chain[0].clone())
        .max_request_header_bytes(150)
        .start()
        .await?;
    let sources = vec![HttpSource {
        url: server.url("p0.patch"),
        expected_len: chain[0].len() as u64,
        policy: None,
    }];
    let fetcher = Fetcher::builder().build()?;
    let handle = tokio::runtime::Handle::current();
    let mut src = HttpRangeSource::new(fetcher, handle, sources).with_packing(RangePacking {
        max_ranges: 256,
        max_range_header_bytes: 12,
    });

    let root = applied.path().to_path_buf();
    let outcome =
        tokio::task::spawn_blocking(move || index.repair(&root, &report, &mut src)).await??;
    assert!(
        outcome.is_complete(),
        "still broken: {:?}",
        outcome.still_broken
    );
    assert!(
        server.stats().requests() >= 2,
        "packing must split to stay under the header limit"
    );

    let now = tree_manifest::author(applied.path())?;
    assert_eq!(now.files, baseline.files);
    Ok(())
}

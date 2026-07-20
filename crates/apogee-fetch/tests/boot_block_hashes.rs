//! A real boot patch verified against its recorded per-block SHA1s.
//!
//! Boot patchlists carry no per-block hashes, so a recorded-fact fixture stands in for the
//! authenticated list: `fixtures/boot_block_hashes.json` records one public patch's URL, whole-file
//! SHA256, length, block size, and per-block SHA1 (the digests, never the bytes). The well-formedness
//! check runs everywhere; the live half downloads the patch and verifies it block by block, and is
//! `#[ignore]`d so the offline suite makes no network request.

use apogee_fetch::{DownloadSpec, Fetcher, HeaderPolicy, Validator};
use serde_json::Value;
use sha2::{Digest, Sha256};
use tokio_util::sync::CancellationToken;
use url::Url;

const FIXTURE: &str = include_str!("fixtures/boot_block_hashes.json");

struct BootFixture {
    url: String,
    sha256: [u8; 32],
    len: u64,
    block_size: u32,
    block_hashes: Vec<[u8; 20]>,
}

fn from_hex<const N: usize>(hex: &str) -> [u8; N] {
    assert_eq!(hex.len(), N * 2, "hex length mismatch: {hex}");
    let mut out = [0u8; N];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).expect("valid hex");
    }
    out
}

fn load_fixture() -> BootFixture {
    let v: Value = serde_json::from_str(FIXTURE).expect("fixture parses");
    BootFixture {
        url: v["url"].as_str().unwrap().to_owned(),
        sha256: from_hex(v["sha256"].as_str().unwrap()),
        len: v["len"].as_u64().unwrap(),
        block_size: v["block_size"].as_u64().unwrap() as u32,
        block_hashes: v["block_hashes"]
            .as_array()
            .unwrap()
            .iter()
            .map(|h| from_hex(h.as_str().unwrap()))
            .collect(),
    }
}

#[test]
fn the_recorded_boot_fixture_is_well_formed() {
    let f = load_fixture();
    assert!(f.block_size > 0);
    assert!(!f.block_hashes.is_empty());
    // The block count matches the length and block size, so the fixture describes a valid block map.
    assert_eq!(
        f.block_hashes.len() as u64,
        f.len.div_ceil(u64::from(f.block_size))
    );
    assert!(Url::parse(&f.url).is_ok());
}

// The live half of the block-verification gate: a real boot patch downloads over the CDN and verifies
// end to end against its recorded block hashes. `#[ignore]`d because it makes a network request; run
// on demand with `cargo test -p apogee-fetch --test boot_block_hashes -- --ignored`.
#[tokio::test]
#[ignore = "hits the live FFXIV boot CDN"]
async fn a_real_boot_patch_verifies_against_its_recorded_block_hashes() {
    let f = load_fixture();
    let dir = tempfile::tempdir().unwrap();
    let dest = dir.path().join("boot.patch");
    let spec = DownloadSpec::builder(
        Url::parse(&f.url).unwrap(),
        &dest,
        Validator::BlockSha1 {
            block_size: f.block_size,
            hashes: f.block_hashes.clone(),
        },
    )
    .expected_len(f.len)
    .header_policy(HeaderPolicy::SePatch { unique_id: None })
    .build()
    .unwrap();

    let verified = Fetcher::builder()
        .build()
        .unwrap()
        .download(&spec, None, CancellationToken::new())
        .await
        .expect("the real boot patch verifies against its recorded block hashes");

    // Cross-check the whole file against the recorded SHA256: every block passed *and* the assembled
    // file is the patch we recorded.
    let bytes = tokio::fs::read(verified.path()).await.unwrap();
    assert_eq!(bytes.len() as u64, f.len);
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    let got: [u8; 32] = hasher.finalize().into();
    assert_eq!(got, f.sha256);
}

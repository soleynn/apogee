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

fn from_hex<const N: usize>(hex: &str) -> Result<[u8; N], String> {
    if hex.len() != N * 2 {
        return Err(format!("hex length mismatch: {hex}"));
    }
    let mut out = [0u8; N];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16)
            .map_err(|e| format!("bad hex {hex}: {e}"))?;
    }
    Ok(out)
}

fn load_fixture() -> Result<BootFixture, String> {
    let v: Value = serde_json::from_str(FIXTURE).map_err(|e| e.to_string())?;
    let str_field = |k: &str| {
        v[k].as_str()
            .map(str::to_owned)
            .ok_or_else(|| format!("missing string field {k}"))
    };
    let block_hashes = v["block_hashes"]
        .as_array()
        .ok_or("block_hashes is not an array")?
        .iter()
        .map(|h| {
            h.as_str()
                .ok_or_else(|| "block hash is not a string".to_owned())
                .and_then(from_hex::<20>)
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(BootFixture {
        url: str_field("url")?,
        sha256: from_hex(&str_field("sha256")?)?,
        len: v["len"].as_u64().ok_or("missing len")?,
        block_size: u32::try_from(v["block_size"].as_u64().ok_or("missing block_size")?)
            .map_err(|e| e.to_string())?,
        block_hashes,
    })
}

#[test]
fn the_recorded_boot_fixture_is_well_formed() {
    let f = load_fixture().unwrap();
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
    let f = load_fixture().unwrap();
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

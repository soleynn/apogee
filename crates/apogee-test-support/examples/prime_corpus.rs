//! Prime the boot corpus cache: fetch every committed corpus entry (URL + SHA256) into the cache
//! directory, so the differential-apply gate has its inputs. Requires network access and is run in the
//! nightly tier, not on every push (the every-push corpus self-test is hermetic). A cache hit makes no
//! request; the SHA256 pin covers the on-wire bytes.

use std::error::Error;

use apogee_fetch::Fetcher;
use apogee_test_support::corpus::{self, CorpusManifest};

/// The committed corpus manifest (URLs + pins, never the bytes), shared with the apply/index gates.
const MANIFEST_JSON: &str = include_str!("../corpus/manifest.json");

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let manifest = CorpusManifest::from_json(MANIFEST_JSON)?;
    let cache = corpus::default_cache_dir();
    let fetcher = Fetcher::builder().build()?;
    let paths = corpus::fetch_all(&manifest, &cache, &fetcher).await?;
    for path in &paths {
        println!("primed {}", path.display());
    }
    eprintln!(
        "primed {} corpus entr{} into {}",
        paths.len(),
        if paths.len() == 1 { "y" } else { "ies" },
        cache.display()
    );
    Ok(())
}

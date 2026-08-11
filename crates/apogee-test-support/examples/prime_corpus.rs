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

    // Every entry is attempted rather than stopping at the first failure, so one report describes the
    // whole corpus. Which entries are gone for good and which merely failed is the difference between
    // "re-record the manifest" and "try again later", and stopping early hides the rest of that answer.
    let mut primed = 0usize;
    let mut retired: Vec<&str> = Vec::new();
    let mut failed: Vec<String> = Vec::new();
    for entry in &manifest.entries {
        match corpus::fetch_cached(entry, &cache, &fetcher).await {
            Ok(path) => {
                primed += 1;
                println!("primed {}", path.display());
            }
            Err(e) if corpus::is_retired(&e) => retired.push(&entry.name),
            Err(e) => failed.push(format!("{}: {e}", entry.name)),
        }
    }

    for name in &retired {
        eprintln!(
            "retired upstream: {name} is no longer served, so its pin and every fact recorded from \
             the chain it belongs to have to be re-recorded together",
        );
    }
    for failure in &failed {
        eprintln!("failed: {failure}");
    }
    eprintln!(
        "primed {primed} of {} corpus entries into {}",
        manifest.entries.len(),
        cache.display(),
    );

    // A short corpus is still a failure. The gates downstream apply a *chain*, so a missing link is
    // not reduced coverage but no coverage, and exiting 0 here would hand them a cache they would
    // rightly refuse. Failing with the reason beats each of them rediscovering an absent file.
    let short = manifest.entries.len() - primed;
    if short > 0 {
        return Err(format!(
            "{short} corpus entr{} unavailable ({} retired upstream, {} failed)",
            if short == 1 { "y" } else { "ies" },
            retired.len(),
            failed.len(),
        )
        .into());
    }
    Ok(())
}

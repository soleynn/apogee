//! The boot apply gate: applying the real boot patch chain reproduces the committed oracle tree
//! byte-for-byte (per-file path, length, SHA256). The reference applier authored `boot.tree.json`
//! out of process; CI only diffs against it, so no Square Enix bytes and no reference build enter the
//! repo. Skips when the corpus cache is absent, exactly like the parser gate.

use std::path::PathBuf;

use apogee_test_support::tree_manifest::{self, TreeManifest};
use apogee_zipatch::{ApplyOptions, DiskSink, PatchReader, apply};
use serde::Deserialize;

/// The committed corpus manifest (URLs + digests, never the bytes). Entries are in chain order.
const MANIFEST_JSON: &str = include_str!("../../apogee-test-support/corpus/manifest.json");
/// The committed oracle: the recorded facts of the boot tree the reference applier produced.
const ORACLE_JSON: &str = include_str!("../../apogee-test-support/fixtures/oracle/boot.tree.json");

#[derive(Deserialize)]
struct Manifest {
    entries: Vec<Entry>,
}

#[derive(Deserialize)]
struct Entry {
    sha256: String,
    name: String,
}

/// The content-addressed cache: `$APOGEE_CORPUS_CACHE`, else `<workspace>/.corpus-cache` (two levels
/// up from this crate).
fn cache_dir() -> PathBuf {
    if let Some(dir) = std::env::var_os("APOGEE_CORPUS_CACHE") {
        return PathBuf::from(dir);
    }
    let mut root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    root.pop();
    root.pop();
    root.push(".corpus-cache");
    root
}

#[test]
fn boot_chain_applies_to_the_oracle_tree() {
    let manifest: Manifest = serde_json::from_str(MANIFEST_JSON).expect("parse corpus manifest");
    let cache = cache_dir();

    let patches: Vec<PathBuf> = manifest
        .entries
        .iter()
        .map(|e| cache.join(&e.sha256))
        .collect();
    if patches.iter().any(|p| !p.exists()) {
        eprintln!(
            "skipping: boot corpus not primed under {} (no-network run)",
            cache.display()
        );
        return;
    }

    let out = tempfile::tempdir().expect("tempdir");

    // Apply the chain in manifest order; each patch is its own apply pass, as the patcher runs them.
    for (entry, path) in manifest.entries.iter().zip(&patches) {
        let file = std::fs::File::open(path).expect("open cached patch");
        // Boot patches carry no block-SHA1 list, so chunk CRC verification stays on.
        let mut reader = PatchReader::open(std::io::BufReader::new(file))
            .expect("valid magic")
            .verify_crc(true);
        let mut sink = DiskSink::new(out.path()).expect("sink");
        apply(&mut reader, &mut sink, &ApplyOptions::default())
            .unwrap_or_else(|e| panic!("applying {}: {e}", entry.name));
    }

    let oracle = TreeManifest::from_json(ORACLE_JSON).expect("parse oracle tree");
    tree_manifest::assert_tree_matches(out.path(), &oracle, None);
}

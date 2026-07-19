//! The block-index corpus gate: build an index over the real boot patch chain, verify the applied
//! install against it (zero broken/missing/size/strays), and reconstruct a byte-identical tree. Skips
//! when the corpus cache is absent, like the other corpus gates; uses only recorded facts (URLs +
//! digests), never Square Enix bytes.

use std::fs::File;
use std::io::BufReader;
use std::path::PathBuf;

use apogee_test_support::tree_manifest;
use apogee_zipatch::{
    ApplyOptions, DiskSink, PatchReader, Platform, VerifyOptions, apply, build_index,
};
use serde::Deserialize;

/// The committed corpus manifest (URLs + digests). Entries are in chain order.
const MANIFEST_JSON: &str = include_str!("../../apogee-test-support/corpus/manifest.json");

#[derive(Deserialize)]
struct Manifest {
    entries: Vec<Entry>,
}

#[derive(Deserialize)]
struct Entry {
    sha256: String,
    name: String,
}

/// The content-addressed cache: `$APOGEE_CORPUS_CACHE`, else `<workspace>/.corpus-cache`.
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
fn a_boot_index_verifies_clean_and_reconstructs_the_applied_tree() {
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

    // Apply the boot chain to get the reference install tree.
    let applied = tempfile::tempdir().expect("tempdir");
    for (entry, path) in manifest.entries.iter().zip(&patches) {
        let file = File::open(path).expect("open cached patch");
        let mut reader = PatchReader::open(BufReader::new(file))
            .expect("valid magic")
            .verify_crc(true);
        let mut sink = DiskSink::new(applied.path()).expect("sink");
        apply(&mut reader, &mut sink, &ApplyOptions::default())
            .unwrap_or_else(|e| panic!("applying {}: {e}", entry.name));
    }

    // Build the index over the same corpus (seekable files).
    let inputs: Vec<(String, File)> = manifest
        .entries
        .iter()
        .zip(&patches)
        .map(|(e, p)| (e.name.clone(), File::open(p).expect("open")))
        .collect();
    let index = build_index(inputs, Platform::Win32, "boot").expect("build index");

    // The healthy tree verifies with nothing to repair.
    let report = index
        .verify(applied.path(), &VerifyOptions::default())
        .expect("verify");
    assert!(
        report.is_clean(),
        "a healthy boot install must verify clean, got {report:?}"
    );

    // Reconstructing from the index reproduces the applied tree byte-for-byte.
    let mut sources: Vec<File> = patches
        .iter()
        .map(|p| File::open(p).expect("open"))
        .collect();
    let rebuilt = tempfile::tempdir().expect("tempdir");
    index
        .reconstruct(rebuilt.path(), &mut sources)
        .expect("reconstruct");

    let applied_tree = tree_manifest::author(applied.path()).expect("author applied");
    let rebuilt_tree = tree_manifest::author(rebuilt.path()).expect("author rebuilt");
    assert_eq!(
        applied_tree.files, rebuilt_tree.files,
        "reconstruct-from-index must equal apply on the boot corpus"
    );
}

//! The parser gate: every fixture boot patch parses and dumps clean, chunk by chunk, reaching its
//! `EOF_` without a single error. These are genuine Square Enix ZiPatch files (unauthenticated boot
//! patches), fetched by URL+SHA256 into a content-addressed cache that is never checked in.
//!
//! The test reads the cache directly, so it is hermetic given a primed cache and **skips** when the
//! cache is absent (the every-push no-network job) rather than failing. A dedicated corpus step (or
//! a developer, like the first authoring run) primes `.corpus-cache` first; then this dumps the real
//! bytes and proves the framing, CRC, and command decoders survive current SE output.

use std::path::PathBuf;

use apogee_zipatch::{Chunk, PatchReader};
use serde::Deserialize;

/// The committed corpus manifest (URLs + digests, never the bytes), shared with the download harness.
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

/// The content-addressed cache: `$APOGEE_CORPUS_CACHE`, else `<workspace>/.corpus-cache`. The crate
/// manifest dir is `crates/apogee-zipatch`, so the workspace root is two levels up.
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
fn dumps_every_fixture_boot_patch_without_error() {
    let manifest: Manifest = serde_json::from_str(MANIFEST_JSON).expect("parse corpus manifest");
    let cache = cache_dir();
    if !cache.is_dir() {
        eprintln!(
            "skipping: corpus cache {} absent (no-network run)",
            cache.display()
        );
        return;
    }

    let mut dumped = 0usize;
    for entry in &manifest.entries {
        let path = cache.join(&entry.sha256);
        if !path.exists() {
            eprintln!("skipping {}: {} not in cache", entry.name, entry.sha256);
            continue;
        }

        let file = std::fs::File::open(&path).expect("open cached patch");
        let mut patch = PatchReader::open(std::io::BufReader::new(file)).expect("valid magic");

        let mut chunk_count = 0usize;
        let mut saw_header = false;
        let mut saw_eof = false;
        loop {
            let next = match patch.next_chunk() {
                Ok(next) => next,
                Err(e) => panic!("parsing {} failed: {e}", entry.name),
            };
            let Some(chunk) = next else { break };
            chunk_count += 1;
            match chunk {
                Chunk::FileHeader(_) => saw_header = true,
                Chunk::EndOfFile => saw_eof = true,
                _ => {}
            }
        }

        assert!(saw_header, "{}: no FHDR chunk", entry.name);
        assert!(saw_eof, "{}: never reached EOF_", entry.name);
        assert!(chunk_count > 2, "{}: implausibly few chunks", entry.name);
        eprintln!("dumped {} ({chunk_count} chunks)", entry.name);
        dumped += 1;
    }

    if dumped == 0 {
        eprintln!(
            "skipping: no cached fixtures present under {}",
            cache.display()
        );
    }
}

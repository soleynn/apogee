#![no_main]

use libfuzzer_sys::fuzz_target;

// The `.apzi` block-index deserializer runs over a manifest a repair pulls from a host before its
// contents are trusted, so it must never panic or over-allocate on any byte sequence: the compressed
// body and every count/length are capped, and each field is a checked read. It only ever returns an
// index or a typed error.
fuzz_target!(|data: &[u8]| {
    let _ = apogee_zipatch::Index::read_apzi(data);
});

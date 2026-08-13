#![no_main]

use libfuzzer_sys::fuzz_target;

// The runner catalog parser runs over a downloaded manifest before its signature is trusted for the
// shape, so it must never panic or over-allocate on any byte sequence: it only ever returns a
// catalog or a typed parse error.
fuzz_target!(|data: &[u8]| {
    let _ = apogee_runtime::Catalog::from_json_bytes(data);

    // The detached signature is downloaded too, and it is walked against every compiled-in key in
    // turn, so one corpus entry drives both halves: its head as a signature of whatever length
    // arrived, its tail as the body that signature is checked over.
    let (signature, body) = data.split_at(data.len().min(64));
    let _ = apogee_runtime::Catalog::parse_and_verify(
        body,
        signature,
        apogee_runtime::CATALOG_PUBLIC_KEYS,
    );

    // The trusted list is a list so a key can be rotated without an outage, and every entry is
    // decompressed before any of it is used. That is parse surface of its own: a list of any length,
    // holding bytes that need not be points on the curve, at any position. The constant above is a
    // single valid key, which reaches none of it, so the same bytes are read as a key list too.
    let keys: Vec<[u8; 32]> = body
        .chunks_exact(32)
        // Bounded because the list is a rotation window rather than a keyring, and an unbounded one
        // would spend the run decompressing curve points instead of reaching the parser.
        .take(8)
        .map(|chunk| {
            let mut key = [0u8; 32];
            key.copy_from_slice(chunk);
            key
        })
        .collect();
    let _ = apogee_runtime::Catalog::parse_and_verify(body, signature, &keys);
});

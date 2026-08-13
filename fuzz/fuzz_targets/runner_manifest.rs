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
});

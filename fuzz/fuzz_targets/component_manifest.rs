#![no_main]

use libfuzzer_sys::fuzz_target;

// The component manifest parser runs over a downloaded manifest before its signature is trusted for the
// shape, so it must never panic or over-allocate on any byte sequence: it only ever returns a manifest
// or a typed parse error. It also validates the destinations and registry edits its rows describe, so
// this covers those too.
fuzz_target!(|data: &[u8]| {
    let _ = apogee_addons::ComponentManifest::from_json_bytes(data);
});

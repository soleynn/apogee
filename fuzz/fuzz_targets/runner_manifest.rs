#![no_main]

use libfuzzer_sys::fuzz_target;

// The runner catalog parser runs over a downloaded manifest before its signature is trusted for the
// shape, so it must never panic or over-allocate on any byte sequence: it only ever returns a
// catalog or a typed parse error.
fuzz_target!(|data: &[u8]| {
    let _ = apogee_runtime::Catalog::from_json_bytes(data);
});

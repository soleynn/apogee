#![no_main]

use libfuzzer_sys::fuzz_target;

// The fallback secret store's file header is read before any of it is trusted, so it must never panic
// or reserve out of a number it just read: it only ever returns a header or a typed refusal. It stops
// short of the key derivation on purpose, so the fuzzer spends its budget on the parser rather than
// on Argon2.
fuzz_target!(|data: &[u8]| {
    apogee_secrets::fuzz_parse_frame(data);
});

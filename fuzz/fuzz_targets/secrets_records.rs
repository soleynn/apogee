#![no_main]

use libfuzzer_sys::fuzz_target;

// The record table the fallback secret store seals. Authenticated before it is reached in production,
// so this covers the decoder's own totality rather than an attacker's reach: it walks records whose
// lengths come out of the buffer, and it must stay panic-free and allocation-bounded whatever those
// lengths say.
fuzz_target!(|data: &[u8]| {
    apogee_secrets::fuzz_parse_records(data);
});

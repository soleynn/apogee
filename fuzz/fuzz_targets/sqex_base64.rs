#![no_main]

use libfuzzer_sys::fuzz_target;

// The mangled-base64 decoder sees hostile input, so it must never panic on any byte sequence: it
// only ever returns bytes or `None`. Encoding is total, and every input round-trips back through it.
fuzz_target!(|data: &[u8]| {
    let _ = sqex_crypto::sqex_base64::decode(&String::from_utf8_lossy(data));
    let encoded = sqex_crypto::sqex_base64::encode(data);
    assert_eq!(sqex_crypto::sqex_base64::decode(&encoded).as_deref(), Some(data));
});

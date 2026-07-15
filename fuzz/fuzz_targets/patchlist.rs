#![no_main]

use libfuzzer_sys::fuzz_target;

// The patchlist parser sees hostile SE input, so it must never panic or over-allocate on any byte
// sequence: it only ever returns entries or a typed parse error.
fuzz_target!(|data: &[u8]| {
    let text = String::from_utf8_lossy(data);
    let _ = sqex_proto::parse_patch_list(&text);
});

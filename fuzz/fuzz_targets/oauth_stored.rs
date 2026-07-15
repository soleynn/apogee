#![no_main]

use libfuzzer_sys::fuzz_target;

// The `_STORED_` scraper sees hostile SE HTML, so it must never panic or over-allocate on any byte
// sequence: it only ever returns a borrowed slice or a typed error.
fuzz_target!(|data: &[u8]| {
    let text = String::from_utf8_lossy(data);
    let _ = sqex_proto::scrape_stored(&text);
});

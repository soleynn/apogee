#![no_main]

use libfuzzer_sys::fuzz_target;

// The `Date` reader sees whatever a login response stamps on itself, so it must answer cleanly for
// any byte sequence: an instant or nothing, never a panic and never an arithmetic overflow. The
// calendar arithmetic behind it multiplies a day count by 86400, which is exactly the shape that
// wraps when a field reaches it unchecked.
fuzz_target!(|data: &[u8]| {
    let text = String::from_utf8_lossy(data);
    let _ = sqex_proto::parse_http_date(&text);
});

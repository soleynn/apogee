#![no_main]

use libfuzzer_sys::fuzz_target;

// The launchParams parser sees hostile SE input, so it must never panic or over-allocate on any byte
// sequence: it only ever returns the parsed params or a field count.
fuzz_target!(|data: &[u8]| {
    let text = String::from_utf8_lossy(data);
    let _ = sqex_proto::parse_launch_params(&text);
});

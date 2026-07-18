#![no_main]

use libfuzzer_sys::fuzz_target;

// SqPack blocks arrive over a plain-HTTP patch path, so the codec must stay panic- and
// allocation-safe on any byte sequence: it only ever returns a block or a typed error. Decode blocks
// back to back the way the apply path streams them, stopping at the first error. Each successful
// decode consumes at least a full 128-byte padded block, so the loop always makes progress.
fuzz_target!(|data: &[u8]| {
    let limits = apogee_sqpack::codec::Limits::default();
    let mut src = data;
    while !src.is_empty() {
        let mut out = Vec::new();
        if apogee_sqpack::codec::read_block(&mut src, &mut out, &limits).is_err() {
            break;
        }
    }
});

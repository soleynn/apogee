#![no_main]

use libfuzzer_sys::fuzz_target;

// The `multipart/byteranges` parser reads a server's multi-range response, which is untrusted input
// over plain HTTP, so it must be total and bounded: any byte sequence resolves to a parse result or a
// typed error, never a panic or an over-allocation (header blocks are size-capped and no part body is
// buffered). This drives the parser over arbitrary bodies, varying the feed chunk size from a leading
// control byte to fuzz chunk-boundary handling.
fuzz_target!(|data: &[u8]| {
    apogee_fetch::fuzzing::fuzz_multipart(data);
});

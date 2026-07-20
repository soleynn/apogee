#![no_main]

use libfuzzer_sys::fuzz_target;

// The `.apdl` resume journal is an in-house CRC-framed binary format read from disk before a download
// resumes, so its decoder must be total and bounded on any byte sequence: a corrupt or crafted journal
// resolves to "start over", never a panic or an over-allocation. This drives the decoder over
// arbitrary input; the journal is size-capped and every record and length is a checked read.
fuzz_target!(|data: &[u8]| {
    apogee_fetch::fuzzing::fuzz_decode(data);
});

#![no_main]

use libfuzzer_sys::fuzz_target;

use apogee_zipatch::{Limits, PatchReader};

// A ZiPatch file arrives over a plain-HTTP patch path, so the whole reader must stay panic- and
// allocation-safe on any byte sequence: it only ever yields a chunk or a typed error. Drive magic,
// chunk framing, CRC verification, and command dispatch to EOF_ or the first error. The chunk-size
// cap is set small so a hostile length field is rejected before any large allocation.
fuzz_target!(|data: &[u8]| {
    let limits = Limits {
        max_chunk_size: 1 << 16,
    };
    if let Ok(reader) = PatchReader::open(data) {
        let mut reader = reader.with_limits(limits);
        while let Ok(Some(_chunk)) = reader.next_chunk() {}
    }
});

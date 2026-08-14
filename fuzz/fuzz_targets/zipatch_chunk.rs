#![no_main]

use libfuzzer_sys::fuzz_target;

use apogee_zipatch::{Limits, MAGIC, PatchReader};

// A ZiPatch file arrives over a plain-HTTP patch path, so the whole reader must stay panic- and
// allocation-safe on any byte sequence: it only ever yields a chunk or a typed error. Drive chunk
// framing and command dispatch to EOF_ or the first error. The chunk-size cap is set small so a
// hostile length field is rejected before any large allocation.
//
// The magic is prepended and CRC verification is off, as in the two sibling targets, because both
// are fixed-value gates a fuzzer cannot search past: raw bytes have to reproduce a 12-byte magic and
// then a CRC32 over each chunk before any of the parser is reached. Measured, the earlier shape
// spent 77 million executions to reach 25 edges and a one-input corpus, i.e. it fuzzed `read_exact`.
// Both gates are pinned by unit tests instead (`open_validates_the_magic`,
// `a_wrong_chunk_crc_is_rejected`, `crc_verification_can_be_disabled_for_the_hashed_apply_path`).
//
// This stays distinct from `zipatch_apply`, which walks the same stream: the interpreter stops at
// the first command it refuses (a console platform, an unknown file op, an escaping path), so it
// never sees what follows one. A sink-free walk keeps going, and reaches framings behind them.
fuzz_target!(|data: &[u8]| {
    let cap = 1usize << 16;
    if data.len() + MAGIC.len() > cap {
        return;
    }
    let mut patch = Vec::with_capacity(MAGIC.len() + data.len());
    patch.extend_from_slice(&MAGIC);
    patch.extend_from_slice(data);

    let limits = Limits {
        max_chunk_size: cap as u32,
    };
    if let Ok(reader) = PatchReader::open(patch.as_slice()) {
        let mut reader = reader.with_limits(limits).verify_crc(false);
        while let Ok(Some(_chunk)) = reader.next_chunk() {}
    }
});

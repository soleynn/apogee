#![no_main]

use libfuzzer_sys::fuzz_target;

use apogee_zipatch::{Limits, PatchReader, MAGIC};

// Focus coverage on the SQPK command decoders (T/X/A/D/E/H/F/I), the densest and most
// endianness-mixed parsing in the crate. The fuzz bytes are the command region (command byte +
// payload); wrap them in one minimal valid frame and parse with CRC disabled, so the bytes reach the
// command parsers instead of bouncing off the checksum. Must stay panic-free on any input.
fuzz_target!(|data: &[u8]| {
    // Keep the wrapped chunk under the parser's cap so no hostile length drives a large allocation.
    let cap = 1usize << 16;
    if data.len() + 4 > cap {
        return;
    }

    // SQPK chunk payload = innerSize (u32be, == payload length) + command region.
    let inner_size = (4 + data.len()) as u32;
    let mut patch = Vec::with_capacity(MAGIC.len() + 12 + data.len());
    patch.extend_from_slice(&MAGIC);
    patch.extend_from_slice(&inner_size.to_be_bytes()); // chunk size == inner size
    patch.extend_from_slice(b"SQPK");
    patch.extend_from_slice(&inner_size.to_be_bytes()); // the SQPK inner-size field
    patch.extend_from_slice(data);
    patch.extend_from_slice(&[0, 0, 0, 0]); // crc placeholder; verification is off below

    let limits = Limits {
        max_chunk_size: cap as u32,
    };
    if let Ok(reader) = PatchReader::open(patch.as_slice()) {
        let mut reader = reader.with_limits(limits).verify_crc(false);
        while let Ok(Some(_chunk)) = reader.next_chunk() {}
    }
});

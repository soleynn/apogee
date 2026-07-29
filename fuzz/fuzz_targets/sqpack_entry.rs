#![no_main]

use libfuzzer_sys::fuzz_target;

// A `.dat` arrives over a plain-HTTP patch path and is rewritten in place by every mod tool people
// run, so the entry reader must stay panic- and allocation-safe on any byte sequence: it only ever
// returns bytes or a typed error. A valid pair of headers is supplied here so the fuzzer spends its
// budget on the entries rather than on guessing the eight-byte magic and the data header. What the
// entries themselves declare is the interesting part: a header length, a block count, a mip's run of
// blocks and a model section's run are all free words that have to be held to the header they sit in
// and to the file the entry claims to be. Walk the container the way a sweep does, extracting each
// entry, and step by the slot the entry declares so a fabricated one cannot stall the loop.
fuzz_target!(|data: &[u8]| {
    let head = apogee_sqpack::COMMON_HEADER_LEN;
    let mut bytes = vec![0u8; head + apogee_sqpack::DATA_HEADER_LEN as usize];
    bytes[0..8].copy_from_slice(&apogee_sqpack::SQPACK_MAGIC);
    bytes[0x0C..0x10].copy_from_slice(&(head as u32).to_le_bytes());
    bytes[0x10..0x14].copy_from_slice(&1u32.to_le_bytes());
    bytes[0x14..0x18].copy_from_slice(&1u32.to_le_bytes()); // a dat container
    bytes[head..head + 4].copy_from_slice(&apogee_sqpack::DATA_HEADER_LEN.to_le_bytes());
    bytes.extend_from_slice(data);

    let Ok(dat) = apogee_sqpack::Dat::parse(&bytes) else {
        return;
    };
    let _ = dat.data_header().data_size();

    let mut offset =
        u64::from(apogee_sqpack::DATA_HEADER_OFFSET) + u64::from(apogee_sqpack::DATA_HEADER_LEN);
    while offset < dat.len() {
        let Ok(entry) = dat.entry_at(offset) else {
            break;
        };
        let _ = entry.stored_len();
        let _ = entry.block_count();
        let mut out = Vec::new();
        let _ = dat.read_into(&entry, &mut out);
        // An entry header is at least twenty bytes and its slot is a whole number of them, so the
        // walk always advances; the floor is belt and braces against a future zero-length slot.
        offset += entry
            .header()
            .slot_len()
            .max(u64::from(apogee_sqpack::DATA_UNIT));
    }
});

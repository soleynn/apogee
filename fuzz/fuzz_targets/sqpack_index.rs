#![no_main]

use libfuzzer_sys::fuzz_target;

// An archive's `.index` arrives over a plain-HTTP patch path and is rewritten in place by every mod
// tool people run, so the index reader must stay panic- and allocation-safe on any byte sequence: it
// only ever returns a container or a typed error. A valid common header is supplied here so the
// fuzzer spends its budget on the index header, the segment table and the segment bodies rather than
// on guessing the eight-byte magic. Every allocation the parser makes is bounded by the input's own
// length, since a segment that runs past the end is a truncation rather than a reservation. After a
// successful parse, walk what came back the way a lookup does: each entry is probed, each folder row
// is asked for its run, and a path is resolved, which is the arm that reads the collision table.
fuzz_target!(|data: &[u8]| {
    let mut bytes = vec![0u8; apogee_sqpack::COMMON_HEADER_LEN];
    bytes[0..8].copy_from_slice(&apogee_sqpack::SQPACK_MAGIC);
    bytes[0x0C..0x10].copy_from_slice(&(apogee_sqpack::COMMON_HEADER_LEN as u32).to_le_bytes());
    bytes[0x10..0x14].copy_from_slice(&1u32.to_le_bytes());
    bytes[0x14..0x18].copy_from_slice(&2u32.to_le_bytes()); // an index container
    bytes.extend_from_slice(data);

    let Ok(index) = apogee_sqpack::Index::parse(&bytes) else {
        return;
    };
    for entry in index.entries() {
        let _ = index.lookup(entry.key);
        let _ = entry.location();
    }
    for row in index.folders() {
        let _ = index.folder_entries(row);
    }
    for record in index.collisions() {
        let _ = index.resolve(&record.path);
    }
    let _ = index.resolve("exd/root.exl");
});

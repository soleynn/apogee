#![no_main]

use libfuzzer_sys::fuzz_target;

use apogee_sqpack::integrity::{
    ContainerId, ContainerRef, IndexFacts, Located, SweepOptions, inspect_dat_entries,
    inspect_dat_headers, inspect_data_region, inspect_index,
};
use apogee_sqpack::{ArchiveId, DatLimits, IndexKind, Repo, codec};

/// An index container out of an arbitrary body: a valid common header declaring an index, so the
/// fuzzer spends its budget on the index header, the segment table and the segment bodies rather than
/// on guessing the eight-byte magic.
fn index_container(body: &[u8]) -> Vec<u8> {
    let mut bytes = vec![0u8; apogee_sqpack::COMMON_HEADER_LEN];
    bytes[0..8].copy_from_slice(&apogee_sqpack::SQPACK_MAGIC);
    bytes[0x0C..0x10].copy_from_slice(&(apogee_sqpack::COMMON_HEADER_LEN as u32).to_le_bytes());
    bytes[0x10..0x14].copy_from_slice(&1u32.to_le_bytes());
    bytes[0x14..0x18].copy_from_slice(&2u32.to_le_bytes()); // an index container
    bytes.extend_from_slice(body);
    bytes
}

/// A dat container out of an arbitrary body: a valid pair of headers, plus a declared region length
/// that matches the body, so the slot walk has the body to walk and the region hash has the body to
/// read. The region is rounded up to a whole number of 128-byte units, since that is the only length
/// the header can spell. The declared region digest is a placeholder rather than the region's own: a
/// field of zeros claims nothing and is counted rather than compared, which would leave the hash pass
/// reading no bytes at all.
fn dat_container(body: &[u8]) -> Vec<u8> {
    let head = apogee_sqpack::COMMON_HEADER_LEN;
    let unit = apogee_sqpack::DATA_UNIT as usize;
    let region = body.len().next_multiple_of(unit);
    let mut bytes = vec![0u8; head + apogee_sqpack::DATA_HEADER_LEN as usize];
    bytes[0..8].copy_from_slice(&apogee_sqpack::SQPACK_MAGIC);
    bytes[0x0C..0x10].copy_from_slice(&(head as u32).to_le_bytes());
    bytes[0x10..0x14].copy_from_slice(&1u32.to_le_bytes());
    bytes[0x14..0x18].copy_from_slice(&1u32.to_le_bytes()); // a dat container
    bytes[head..head + 4].copy_from_slice(&apogee_sqpack::DATA_HEADER_LEN.to_le_bytes());
    // The data region's length in units, at 0x0C of the data header.
    bytes[head + 0x0C..head + 0x10].copy_from_slice(&((region / unit) as u32).to_le_bytes());
    // The region's declared SHA-1, at 0x20 of the data header.
    bytes[head + 0x20..head + 0x34].copy_from_slice(&[0xA5; 20]);
    bytes.extend_from_slice(body);
    bytes.resize(head + apogee_sqpack::DATA_HEADER_LEN as usize + region, 0);
    bytes
}

// The inspector is what somebody points at an install they suspect, so it is handed containers nobody
// wrote on purpose: a half-applied patch, a mod tool's rewrite, a download that stopped. It answers
// with a report on every input and never with a crash, so both halves of the pure layer have to stay
// panic- and allocation-safe on any bytes. One input becomes both containers of a one-archive install:
// the leading word says how much of it is the index, so a mutation inside either body leaves the other
// where it was. The locations the index half named then drive the slot walk over the data half,
// collapsed onto the one data file the target builds, which is how a hostile offset reaches the entry
// reader as well as hostile bytes. Asserted: every report stays inside the defect budget it was given,
// and inspecting the same bytes twice produces the same report, so a report that depends on anything
// but its input fails here rather than as a flake in somebody's whole-install sweep.
fuzz_target!(|data: &[u8]| {
    if data.len() < 2 {
        return;
    }
    let split = usize::from(u16::from_le_bytes([data[0], data[1]]));
    let (index_body, dat_body) = data[2..].split_at(split.min(data.len() - 2));

    let opts = SweepOptions {
        // The decode pass is inspector code, not the readers': it is the arm that turns a block a
        // hostile header promised into a finding.
        decode_entries: true,
        max_defects_per_container: 64,
        // Small bounds, so a size an entry merely declares cannot buy a reservation the container does
        // not back. That is what the malloc limit this target runs under is watching for.
        dat_limits: DatLimits {
            max_entry_header_bytes: 1 << 14,
            max_file_bytes: 1 << 20,
            block: codec::Limits {
                max_decompressed: 1 << 16,
            },
        },
        ..SweepOptions::default()
    };

    let archive = ContainerRef::new(
        Repo::Base,
        ArchiveId::new(0x0A, 0, 0),
        ContainerId::Index(IndexKind::Index1),
    );
    let facts = IndexFacts {
        container: archive,
        named: IndexKind::Index1,
        // One data file, which is the one the target builds below.
        dats: &[0],
    };

    let index_bytes = index_container(index_body);
    let indexed = inspect_index(&index_bytes, &facts, &opts);
    assert!(indexed.report.findings.len() <= opts.max_defects_per_container);
    assert_eq!(
        inspect_index(&index_bytes, &facts, &opts).report,
        indexed.report
    );

    let dat_bytes = dat_container(dat_body);
    let at = archive.with_file(ContainerId::Dat(0));
    let inspected = inspect_dat_headers(dat_bytes.as_slice(), at, &opts);
    assert!(inspected.report.findings.len() <= opts.max_defects_per_container);
    let Some(dat) = inspected.dat else {
        return;
    };
    let _ = inspect_data_region(&dat, at);

    // The one data file stands in for every data file of the archive, so every location the index half
    // named is an offset into it; the walk is handed them in the order it asks for.
    let mut named: Vec<Located> = indexed
        .locations
        .iter()
        .map(|located| Located { dat: 0, ..*located })
        .collect();
    named.sort_unstable();
    let walked = inspect_dat_entries(&dat, &named, at, &opts);
    assert!(walked.findings.len() <= opts.max_defects_per_container);
    assert_eq!(inspect_dat_entries(&dat, &named, at, &opts), walked);
});

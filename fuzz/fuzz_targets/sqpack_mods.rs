#![no_main]

use libfuzzer_sys::fuzz_target;

use apogee_sqpack::integrity::{
    ContainerId, ContainerRef, IndexFacts, Located, SweepOptions, inspect_dat_headers, inspect_index,
};
use apogee_sqpack::mods::{ModOptions, PristineMap, Standing, classify_entries};
use apogee_sqpack::{ArchiveId, DatLimits, IndexKind, Repo, codec};

/// An index container out of an arbitrary body, so the fuzzer spends its budget on the segment table
/// rather than on guessing the magic. Same shape the inspector's target builds.
fn index_container(body: &[u8]) -> Vec<u8> {
    let mut bytes = vec![0u8; apogee_sqpack::COMMON_HEADER_LEN];
    bytes[0..8].copy_from_slice(&apogee_sqpack::SQPACK_MAGIC);
    bytes[0x0C..0x10].copy_from_slice(&(apogee_sqpack::COMMON_HEADER_LEN as u32).to_le_bytes());
    bytes[0x10..0x14].copy_from_slice(&1u32.to_le_bytes());
    bytes[0x14..0x18].copy_from_slice(&2u32.to_le_bytes()); // an index container
    bytes.extend_from_slice(body);
    bytes
}

/// A dat container out of an arbitrary body, with a declared region matching what is there.
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
    bytes[head + 0x0C..head + 0x10].copy_from_slice(&((region / unit) as u32).to_le_bytes());
    bytes.extend_from_slice(body);
    bytes.resize(head + apogee_sqpack::DATA_HEADER_LEN as usize + region, 0);
    bytes
}

// Mod detection answers a question a user is about to act on: "repair will revert these files,
// proceed". Both of its inputs are outside this crate's control. The containers come from an install
// somebody suspects, which is why they are suspect; the map comes from a caller that may have built
// it from a different version of the tree, a partial patch chain, or nothing coherent at all. So the
// map is fuzzed alongside the bytes rather than held right while the bytes go wrong.
//
// Asserted, beyond not crashing:
//
// - every location the index named gets exactly one verdict, however the walk reached it. That is
//   what keeps a report's counts an accounting of the install rather than of whatever the walk
//   managed, and it has to hold when the budget drops verdicts from the list.
// - the report stays inside the budget it was given.
// - the same input twice gives the same report, so a verdict that depends on anything but its input
//   fails here rather than as a flake in somebody's pre-repair prompt.
// - a map that vouches for the container end to end never reads an entry header, which is the short
//   circuit a pristine install rests on.
fuzz_target!(|data: &[u8]| {
    if data.len() < 8 {
        return;
    }
    let split = usize::from(u16::from_le_bytes([data[0], data[1]]));
    // Two runs the map calls dirty, from bytes the fuzzer picks, so a run can land on an entry, on a
    // slot's slack, on a header, past the end, or nowhere at all.
    let first = u64::from(u16::from_le_bytes([data[2], data[3]]));
    let first_len = u64::from(u16::from_le_bytes([data[4], data[5]]));
    let second = u64::from(u16::from_le_bytes([data[6], data[7]]));
    let (index_body, dat_body) = data[8..].split_at(split.min(data.len() - 8));

    let sweep = SweepOptions {
        max_defects_per_container: 64,
        dat_limits: DatLimits {
            max_entry_header_bytes: 1 << 14,
            max_file_bytes: 1 << 20,
            block: codec::Limits {
                max_decompressed: 1 << 16,
            },
        },
        ..SweepOptions::default()
    };
    // The container this target hands to `classify_entries` is opened above under `sweep`'s bounds,
    // so the only field of this that bears on the walk is the budget.
    let opts = ModOptions {
        max_files_per_container: 32,
        ..ModOptions::default()
    };

    let archive = ContainerRef::new(
        Repo::Base,
        ArchiveId::new(0x0A, 0, 0),
        ContainerId::Index(IndexKind::Index1),
    );
    let facts = IndexFacts {
        container: archive,
        named: IndexKind::Index1,
        dats: &[0],
    };
    let indexed = inspect_index(&index_container(index_body), &facts, &sweep);
    let mut named: Vec<Located> = indexed
        .locations
        .iter()
        .map(|located| Located { dat: 0, ..*located })
        .collect();
    named.sort_unstable();

    let at = archive.with_file(ContainerId::Dat(0));
    let bytes = dat_container(dat_body);
    let Some(dat) = inspect_dat_headers(bytes.as_slice(), at, &sweep).dat else {
        return;
    };

    // Four maps over the same container: one that describes nothing, one that vouches for it whole,
    // and two that call runs of it dirty. Each reaches a different arm, and the invariants below hold
    // across all of them.
    let vouched = {
        let mut b = PristineMap::builder();
        b.accounts_for(Repo::Base).container(at, dat.len());
        b.build()
    };
    let dirty = {
        let mut b = PristineMap::builder();
        b.accounts_for(Repo::Base)
            .container(at, dat.len())
            .dirty(at, first, first_len)
            .dirty(at, second, first_len);
        b.build()
    };
    let short = {
        let mut b = PristineMap::builder();
        b.accounts_for(Repo::Base)
            .container(at, first)
            .dirty(at, second, first_len);
        b.build()
    };
    let empty = PristineMap::builder().build();

    for (map, accounted) in [
        (&vouched, true),
        (&dirty, true),
        (&short, true),
        (&empty, true),
        (&empty, false),
    ] {
        let out = classify_entries(&dat, &named, map.coverage(at), accounted, at, &opts);
        let counted = out.totals.pristine
            + out.totals.modified
            + out.totals.foreign
            + out.totals.broken
            + out.totals.unknown;
        assert_eq!(counted, named.len() as u64, "one verdict per location");
        assert!(out.files.len() <= opts.max_files_per_container);
        assert_eq!(out.truncated, out.totals.files_suppressed > 0);
        assert!(out.totals.shared <= out.totals.modified);
        // A carried verdict is never pristine: those are counted and dropped.
        assert!(out.files.iter().all(|f| f.standing != Standing::Pristine));
        assert_eq!(
            classify_entries(&dat, &named, map.coverage(at), accounted, at, &opts),
            out
        );
    }

    // The short circuit the pristine gate rests on: nothing is read when the map answers for the
    // whole container, and nothing is read when it describes none of it.
    let whole = classify_entries(&dat, &named, vouched.coverage(at), true, at, &opts);
    assert_eq!(whole.totals.entry_headers_read, 0);
    assert_eq!(whole.totals.pristine, named.len() as u64);
    let none = classify_entries(&dat, &named, None, true, at, &opts);
    assert_eq!(none.totals.entry_headers_read, 0);
    assert_eq!(none.totals.foreign, named.len() as u64);
});

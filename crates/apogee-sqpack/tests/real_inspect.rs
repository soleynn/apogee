//! Recorded-fact pins for a structural sweep of a whole SqPack install.
//!
//! The gate is one sentence: a pristine install produces no findings. Every check the sweep makes was
//! justified by a measurement over a full retail install, so a finding on a pristine tree is a bug in
//! the checks rather than a fault in the tree, and only a real install can say which it is.
//!
//! The recorded values were produced by a separate implementation of the format, out of process, so
//! what the gated tests prove is agreement between two readers rather than a program agreeing with
//! itself. The hermetic test checks the recording against what this crate declares about the format:
//! each index container's length against the records its segments tile it with, the two forms' entry
//! counts against the collision records that account for the difference, the claimed and unclaimed
//! bytes against the region they partition, and the hashed volume against the containers it covers. CI
//! carries no Square Enix bytes, only counts, lengths and file names.
//!
//! The gated tests re-sweep the tree at `$APOGEE_SQPACK_REAL_INSTALL` and are `#[ignore]` by default,
//! one per cost class so the cheap one can be run alone: the container census and the structure pass
//! read 55 MB, the entry walk adds two million positioned reads, the region-hash pass reads all
//! 118 GiB, and the decode pass inflates one archive.

use std::error::Error;
use std::path::Path;
use std::time::Instant;

use apogee_sqpack::integrity::{DEFECT_SLUGS, GapPolicy, Report, SweepOptions, Totals};
use apogee_sqpack::{
    ArchiveId, ArchiveInfo, COLLISION_RECORD_LEN, COMMON_HEADER_LEN, DATA_UNIT, Dat,
    FOLDER_ROW_LEN, GameData, INDEX_HEADER_LEN, INDEX1_ENTRY_LEN, INDEX2_ENTRY_LEN, Index,
    IndexKind, Repo,
};
use serde_json::Value;

type R<T> = Result<T, Box<dyn Error>>;

/// Where an index container's first segment starts: past both headers. Also how much of a container
/// neither a segment hash nor the segment table accounts for.
const HEADERS_LEN: u64 = COMMON_HEADER_LEN as u64 + INDEX_HEADER_LEN as u64;

/// A digest field of all zeros claims nothing, which two data files of a full install write over their
/// data region.
const UNCLAIMED_DIGEST: [u8; 20] = [0; 20];

fn doc() -> R<Value> {
    Ok(serde_json::from_str(include_str!(
        "fixtures/real_inspect.json"
    ))?)
}

fn rows<'a>(v: &'a Value, key: &str) -> R<&'a Vec<Value>> {
    v[key]
        .as_array()
        .ok_or_else(|| format!("{key} is not an array").into())
}

fn field_str<'a>(v: &'a Value, key: &str) -> R<&'a str> {
    v[key]
        .as_str()
        .ok_or_else(|| format!("missing string field {key}").into())
}

fn field_u64(v: &Value, key: &str) -> R<u64> {
    v[key]
        .as_u64()
        .ok_or_else(|| format!("missing integer field {key}").into())
}

fn field_u32(v: &Value, key: &str) -> R<u32> {
    Ok(u32::try_from(field_u64(v, key)?)?)
}

/// The list of names under `key`, sorted, so a recording and an enumeration compare regardless of the
/// order either walks the tree in.
fn name_list(v: &Value, key: &str) -> R<Vec<String>> {
    let mut out = Vec::new();
    for name in rows(v, key)? {
        out.push(
            name.as_str()
                .ok_or_else(|| format!("{key} holds something other than a name"))?
                .to_owned(),
        );
    }
    out.sort();
    Ok(out)
}

/// One block of the recording read as the accounting struct a sweep produces. Every field is required:
/// a block that omits one would otherwise compare a real count against a default of zero.
fn totals_of(v: &Value) -> R<Totals> {
    Ok(Totals {
        archives: field_u32(v, "archives")?,
        index_files: field_u32(v, "index_files")?,
        data_files: field_u32(v, "data_files")?,
        containers_unreadable: field_u32(v, "containers_unreadable")?,
        index_bytes: field_u64(v, "index_bytes")?,
        entries: field_u64(v, "entries")?,
        collision_records: field_u64(v, "collision_records")?,
        locations: field_u64(v, "locations")?,
        entry_headers_read: field_u64(v, "entry_headers_read")?,
        entries_decoded: field_u64(v, "entries_decoded")?,
        bytes_hashed: field_u64(v, "bytes_hashed")?,
        data_region_bytes: field_u64(v, "data_region_bytes")?,
        claimed_bytes: field_u64(v, "claimed_bytes")?,
        slack_bytes: field_u64(v, "slack_bytes")?,
        unclaimed_bytes: field_u64(v, "unclaimed_bytes")?,
        gaps: field_u64(v, "gaps")?,
        largest_gap: field_u64(v, "largest_gap")?,
        unclaimed_regions: field_u64(v, "unclaimed_regions")?,
        unclaimed_hash_fields: field_u32(v, "unclaimed_hash_fields")?,
        defects_suppressed: field_u64(v, "defects_suppressed")?,
    })
}

/// The twenty counters paired with the recording's, named, in the order the crate declares them.
fn pairs(found: &Totals, want: &Totals) -> Vec<(&'static str, u64, u64)> {
    vec![
        ("archives", found.archives.into(), want.archives.into()),
        (
            "index_files",
            found.index_files.into(),
            want.index_files.into(),
        ),
        (
            "data_files",
            found.data_files.into(),
            want.data_files.into(),
        ),
        (
            "containers_unreadable",
            found.containers_unreadable.into(),
            want.containers_unreadable.into(),
        ),
        ("index_bytes", found.index_bytes, want.index_bytes),
        ("entries", found.entries, want.entries),
        (
            "collision_records",
            found.collision_records,
            want.collision_records,
        ),
        ("locations", found.locations, want.locations),
        (
            "entry_headers_read",
            found.entry_headers_read,
            want.entry_headers_read,
        ),
        (
            "entries_decoded",
            found.entries_decoded,
            want.entries_decoded,
        ),
        ("bytes_hashed", found.bytes_hashed, want.bytes_hashed),
        (
            "data_region_bytes",
            found.data_region_bytes,
            want.data_region_bytes,
        ),
        ("claimed_bytes", found.claimed_bytes, want.claimed_bytes),
        ("slack_bytes", found.slack_bytes, want.slack_bytes),
        (
            "unclaimed_bytes",
            found.unclaimed_bytes,
            want.unclaimed_bytes,
        ),
        ("gaps", found.gaps, want.gaps),
        ("largest_gap", found.largest_gap, want.largest_gap),
        (
            "unclaimed_regions",
            found.unclaimed_regions,
            want.unclaimed_regions,
        ),
        (
            "unclaimed_hash_fields",
            found.unclaimed_hash_fields.into(),
            want.unclaimed_hash_fields.into(),
        ),
        (
            "defects_suppressed",
            found.defects_suppressed,
            want.defects_suppressed,
        ),
    ]
}

/// How many bytes of a container's own header each of its two self hashes covers, recovered from the
/// recording: everything hashed beyond the index segments is two header prefixes per container, and a
/// container is either index form or a data file. A recording whose hashed volume, index length or
/// container count is wrong does not divide.
fn header_prefix(totals: &Totals) -> R<u64> {
    let segments = totals
        .index_bytes
        .checked_sub(u64::from(totals.index_files) * HEADERS_LEN)
        .ok_or("the index containers are shorter than their own headers")?;
    let headers = totals
        .bytes_hashed
        .checked_sub(segments)
        .ok_or("less was hashed than the index segments hold")?;
    let containers = 2 * u64::from(totals.index_files + totals.data_files);
    if containers == 0 || !headers.is_multiple_of(containers) {
        return Err(format!("{headers} hashed header bytes over {containers} headers").into());
    }
    Ok(headers / containers)
}

/// Every counter against the recording's, exactly when the tree is the patch the recording came from.
/// Off that patch, each counter the recording found work in has to still find nine tenths of it, so a
/// patch day fails on a finding rather than on a count.
fn check_totals(found: &Totals, want: &Totals, exact: bool, where_: &str) {
    assert_eq!(
        found.containers_unreadable, 0,
        "{where_}: containers that would not open"
    );
    assert_eq!(
        found.defects_suppressed, 0,
        "{where_}: defects dropped at the per-container budget"
    );
    for (name, got, want) in pairs(found, want) {
        if exact {
            assert_eq!(got, want, "{where_}: {name}");
        } else if want != 0 {
            assert!(
                got * 10 >= want * 9,
                "{where_}: {name}: {got} is far below the recorded {want}"
            );
        }
    }
}

/// Fail with the findings themselves rather than with a count: a finding on a pristine install is the
/// interesting outcome, and its rendered line names the container, the offset and the key.
fn assert_clean(report: &Report, where_: &str) {
    let shown: Vec<String> = report
        .findings
        .iter()
        .take(20)
        .map(|f| format!("  [{}] {f}", f.slug()))
        .collect();
    assert!(
        report.is_clean(),
        "{where_}: {} findings, worst {:?}:\n{}",
        report.findings.len(),
        report.worst_severity(),
        shown.join("\n")
    );
    assert!(
        report.truncated.is_empty(),
        "{where_}: {} containers filled the defect budget: {:?}",
        report.truncated.len(),
        report.truncated
    );
}

/// The defects the recording says were measured absent over the whole install, checked by name so the
/// failure says which measurement the sweep contradicted.
fn assert_none_of(report: &Report, forbidden: &[String], where_: &str) {
    for slug in forbidden {
        let found: Vec<String> = report
            .findings
            .iter()
            .filter(|f| f.slug() == slug)
            .take(8)
            .map(|f| format!("  {f}"))
            .collect();
        assert!(
            found.is_empty(),
            "{where_}: {slug} was measured absent over a pristine install:\n{}",
            found.join("\n")
        );
    }
}

fn repo_of(v: &Value) -> R<Repo> {
    match field_str(v, "repo")? {
        "ffxiv" => Ok(Repo::Base),
        other => other
            .strip_prefix("ex")
            .and_then(|n| n.parse::<u8>().ok())
            .map(Repo::Ex)
            .ok_or_else(|| format!("unknown repository {other}").into()),
    }
}

/// The archive a recorded row names, as the install enumerated it.
fn archive_of<'a>(game: &'a GameData, row: &Value) -> R<&'a ArchiveInfo> {
    let stem = field_str(row, "archive")?;
    let id = ArchiveId::parse_stem(stem)
        .ok_or_else(|| format!("{stem}: archive stem does not parse"))?;
    game.archive(repo_of(row)?, id)
        .ok_or_else(|| format!("{stem} was not enumerated").into())
}

/// Whether the tree is the patch the recording was taken from, read from the base repository's version
/// file.
fn is_recorded_version(game: &GameData, doc: &Value) -> R<bool> {
    let want = field_str(doc, "version")?;
    Ok(game
        .repos()
        .iter()
        .any(|r| r.repo == Repo::Base && r.version.as_deref() == Some(want)))
}

fn open_install() -> R<GameData> {
    let root = std::env::var("APOGEE_SQPACK_REAL_INSTALL")?;
    Ok(GameData::open(Path::new(&root))?)
}

/// The key of the last record in a container's collision table: the terminator, which the reader stops
/// at and so never hands back. Segment two is the collision table and a record's key is its first
/// eight bytes, which is the whole of what this needs to know about the raw bytes.
fn terminator_key(bytes: &[u8], index: &Index) -> R<u64> {
    let table = index.header().segments[1];
    let end = usize::try_from(u64::from(table.offset) + u64::from(table.size))?;
    let start = end
        .checked_sub(COLLISION_RECORD_LEN)
        .ok_or("the collision table holds no record")?;
    let raw = bytes
        .get(start..start + 8)
        .and_then(|w| <[u8; 8]>::try_from(w).ok())
        .ok_or("the collision table runs past the container")?;
    Ok(u64::from_le_bytes(raw))
}

#[test]
fn the_recording_is_consistent_with_the_formats_this_crate_declares() -> R<()> {
    let doc = doc()?;
    let install = &doc["install"];
    let structure = totals_of(&install["structure"])?;
    let walk = totals_of(&install["walk"])?;
    let hash = totals_of(&install["hash"])?;

    // Both index forms sit beside every archive, so the container count is fixed by the archive count.
    assert_eq!(structure.index_files, 2 * structure.archives);
    assert!(structure.data_files >= structure.archives, "one dat apiece");

    // The three passes differ only in what they read. Their agreement on the container shape is what
    // says the recording is one install measured three ways rather than three recordings.
    for (name, found, want) in pairs(&hash, &structure) {
        let shared = !matches!(name, "bytes_hashed" | "unclaimed_hash_fields");
        assert_eq!(shared, found == want, "the hash pass differs in {name}");
    }
    assert_eq!(
        hash.bytes_hashed,
        structure.bytes_hashed + walk.data_region_bytes,
        "the hash pass adds exactly the data regions"
    );
    assert_eq!(
        u64::from(hash.unclaimed_hash_fields),
        name_list(install, "unclaimed_data_hash")?.len() as u64,
        "a data file declaring nothing over its region is a hash field the pass skipped"
    );
    for (name, found, want) in pairs(&walk, &structure) {
        // The walk is the structure pass plus the positioned reads, so it adds counters and changes
        // none of the ones the structure pass already filled.
        let reads = matches!(
            name,
            "entry_headers_read"
                | "data_region_bytes"
                | "claimed_bytes"
                | "slack_bytes"
                | "unclaimed_bytes"
                | "gaps"
                | "largest_gap"
                | "unclaimed_regions"
        );
        if reads {
            assert_eq!(want, 0, "the structure pass reads no entry: {name}");
            assert!(found > 0, "the walk found no {name}");
        } else {
            assert_eq!(found, want, "the walk differs in {name}");
        }
    }

    // Every location the primary form named had its entry header read, and nothing else was read.
    assert_eq!(walk.locations, walk.entry_headers_read);
    // The other form's entries are the rest, and it holds one placeholder where the primary holds a
    // whole colliding set, so it can never carry more.
    let second = walk.entries - walk.locations;
    assert!(second <= walk.locations, "the second form is not larger");

    // The slots and the space between them partition the declared region exactly, which is the whole
    // point of the accounting: a sweep that lost bytes would still report zero findings.
    assert_eq!(
        walk.claimed_bytes + walk.unclaimed_bytes,
        walk.data_region_bytes
    );
    // A slot, a region and a wiped run are all counted in allocation units, so every total the walk
    // divides the region into is a whole number of them.
    let unit = u64::from(DATA_UNIT);
    for (name, value) in [
        ("data_region_bytes", walk.data_region_bytes),
        ("claimed_bytes", walk.claimed_bytes),
        ("slack_bytes", walk.slack_bytes),
        ("unclaimed_bytes", walk.unclaimed_bytes),
        ("largest_gap", walk.largest_gap),
    ] {
        assert!(
            value.is_multiple_of(unit),
            "{name} is not a whole number of units"
        );
    }
    assert!(walk.largest_gap <= walk.unclaimed_bytes);
    assert!(
        walk.slack_bytes <= walk.claimed_bytes,
        "slack sits in slots"
    );
    // A run of unclaimed space is tiled by wiped regions, each at least one unit long, and there is at
    // least one region per run.
    assert!(walk.unclaimed_regions >= walk.gaps);
    assert!(walk.unclaimed_bytes >= walk.unclaimed_regions * unit);
    assert_eq!(
        walk.unclaimed_bytes * 1000 / walk.data_region_bytes,
        field_u64(install, "unclaimed_share_per_mille")?,
        "the wiped share of the install"
    );

    // The hashed volume names how much of each header a self hash covers. It has to be the same prefix
    // for the install and for every archive of it, a whole number of words, and inside the header.
    let prefix = header_prefix(&structure)?;
    assert!(
        prefix.is_multiple_of(4) && prefix < HEADERS_LEN / 2,
        "{prefix}"
    );

    // Every defect the recording says was measured absent is one this crate can actually report.
    let forbidden = name_list(install, "must_not_appear")?;
    assert!(forbidden.len() >= 8, "the gate names what it rules out");
    for (n, slug) in forbidden.iter().enumerate() {
        assert!(
            DEFECT_SLUGS.contains(&slug.as_str()),
            "unknown defect {slug}"
        );
        assert!(n == 0 || forbidden[n - 1] != *slug, "{slug} is named twice");
    }

    // The odd shapes a sweep is most likely to report on a pristine install.
    let empty = name_list(install, "empty_archives")?;
    assert_eq!(empty.len(), 8, "the archives holding nothing");
    for name in name_list(install, "unclaimed_data_hash")? {
        assert!(empty.contains(&name), "{name} holds no entries either");
    }
    assert!(field_u64(install, "dats_without_magic")? > 0);
    assert!(
        field_u64(install, "dats_without_magic")? < u64::from(structure.data_files),
        "not every data file lacks the magic"
    );

    let mut sum = Totals::default();
    let mut narrow = 0;
    let mut with_records = 0;
    let mut without_magic = 0;
    for row in rows(&doc, "archives")? {
        let name = format!("{}/{}", field_str(row, "repo")?, field_str(row, "archive")?);
        let totals = totals_of(&row["totals"])?;
        let dats = rows(row, "dats")?.len() as u64;
        let entries1 = field_u64(row, "entries_index1")?;
        let entries2 = field_u64(row, "entries_index2")?;
        let records = field_u64(row, "collision_records")?;
        let flagged = field_u64(row, "flagged_entries")?;
        let index1 = field_u64(row, "index1_bytes")?;
        let index2 = field_u64(row, "index2_bytes")?;

        // Each container's length is its two headers plus its segments, and each segment is a whole
        // number of the records the crate declares. The collision table always carries its terminator,
        // so an empty one is still one record long, and only the `.index` carries the other two
        // segments.
        assert_eq!(
            index1,
            HEADERS_LEN
                + entries1 * INDEX1_ENTRY_LEN as u64
                + COLLISION_RECORD_LEN as u64
                + field_u64(row, "unclassified_bytes")?
                + field_u64(row, "folder_rows")? * FOLDER_ROW_LEN as u64,
            "{name}: the .index does not tile"
        );
        assert_eq!(
            index2,
            HEADERS_LEN
                + entries2 * INDEX2_ENTRY_LEN as u64
                + (records + 1) * COLLISION_RECORD_LEN as u64,
            "{name}: the .index2 does not tile"
        );
        assert_eq!(totals.index_bytes, index1 + index2, "{name}");
        assert_eq!(totals.entries, entries1 + entries2, "{name}");
        assert_eq!(
            totals.locations, entries1,
            "{name}: the primary form's places"
        );
        assert_eq!(totals.entry_headers_read, entries1, "{name}");
        assert_eq!(totals.collision_records, records, "{name}");

        // The `.index2` keys the whole path, so a set of paths whose keys collide costs it one
        // placeholder entry where the `.index` holds one entry apiece: that difference and nothing else
        // is why the two forms count differently.
        assert_eq!(
            entries1 - entries2,
            records - flagged,
            "{name}: the forms differ by what the second one folded"
        );
        // Measured, not derived: every colliding key of a full install is shared by exactly two paths.
        assert_eq!(records, 2 * flagged, "{name}: two paths per colliding key");

        assert_eq!(u64::from(totals.data_files), dats, "{name}");
        assert_eq!(field_u64(row, "declared_data_files")?, dats, "{name}");
        assert_eq!(u64::from(totals.index_files), 2, "{name}");
        assert_eq!(totals.archives, 1, "{name}");
        for (n, dat) in rows(row, "dats")?.iter().enumerate() {
            assert_eq!(dat.as_u64(), Some(n as u64), "{name}: dats are 0 upwards");
        }
        assert!(field_u64(row, "dats_without_magic")? <= dats, "{name}");
        assert_eq!(
            header_prefix(&totals)?,
            prefix,
            "{name}: hashed a different header prefix than the install"
        );
        assert_eq!(
            totals.claimed_bytes + totals.unclaimed_bytes,
            totals.data_region_bytes,
            "{name}"
        );
        assert!(totals.unclaimed_regions >= totals.gaps, "{name}");
        assert!(
            totals.unclaimed_bytes >= totals.unclaimed_regions * unit,
            "{name}"
        );

        match field_str(row, "terminator")? {
            "narrow" => {
                narrow += 1;
                assert!(empty.contains(&name), "{name} spells a short terminator");
                assert_eq!(totals.entries, 0, "{name}");
                assert_eq!(totals.data_region_bytes, 0, "{name}");
            }
            "wide" => assert!(!empty.contains(&name), "{name}"),
            other => return Err(format!("{name}: unknown terminator {other}").into()),
        }
        if records > 0 {
            with_records += 1;
        }
        without_magic += field_u64(row, "dats_without_magic")?;
        sum.merge(&totals);
    }

    // The rows are a subset of one install, so they add up to no more than it does.
    for (name, part, whole) in pairs(&sum, &walk) {
        assert!(part <= whole, "the rows hold more {name} than the install");
    }
    assert!(
        sum.largest_gap <= walk.largest_gap && sum.gaps <= walk.gaps,
        "the rows' unclaimed space is the install's"
    );

    // One row per shape the sweep has to pass, or the representative set has stopped representing.
    assert!(narrow >= 2, "an archive spelling a short terminator");
    assert!(with_records >= 2, "an archive with collision records");
    assert!(without_magic >= 5, "data files carrying no magic");
    assert!(
        rows(&doc, "archives")?
            .iter()
            .any(|r| field_u64(r, "declared_data_files").is_ok_and(|n| n >= 4)),
        "an archive spanning several data files"
    );
    assert!(
        rows(&doc, "archives")?.iter().any(|r| {
            let t = totals_of(&r["totals"]);
            t.is_ok_and(|t| t.unclaimed_bytes * 3 > t.data_region_bytes)
        }),
        "an archive where wiped space is a third of the region"
    );

    // The archive the decode pass extracts is one of the rows, and it extracts everything it names.
    let decode = &install["decode"];
    let named = rows(&doc, "archives")?
        .iter()
        .find(|r| r["repo"] == decode["repo"] && r["archive"] == decode["archive"])
        .ok_or("the decode pass names an archive with no recorded row")?;
    assert_eq!(
        field_u64(decode, "entries_decoded")?,
        totals_of(&named["totals"])?.locations,
        "the decode pass extracts every location the archive names"
    );
    Ok(())
}

/// The containers a pristine install carries, counted directly rather than through the sweep: the odd
/// shapes have to be present, or a sweep reporting nothing has proved nothing. A fifth of the data
/// files carry something other than the SqPack magic, eight archives hold no entries at all and spell
/// their collision terminator in half the field, and two of those declare nothing over their data
/// region.
#[test]
#[ignore = "set APOGEE_SQPACK_REAL_INSTALL to a real game subtree to run"]
fn a_pristine_install_carries_the_containers_the_recording_names() -> R<()> {
    let game = open_install()?;
    let doc = doc()?;
    let install = &doc["install"];
    let exact = is_recorded_version(&game, &doc)?;

    let present: Vec<String> = game.repos().iter().map(|r| r.repo.dir_name()).collect();
    for name in name_list(install, "repos")? {
        assert!(present.contains(&name), "{name} was not enumerated");
    }

    let mut index_files = 0u32;
    let mut data_files = 0u32;
    let mut without_magic = Vec::new();
    let mut unclaimed_hash = Vec::new();
    let mut narrow = Vec::new();
    let mut empty = Vec::new();
    for info in game.archives() {
        let name = format!("{}/{}", info.repo.dir_name(), info.id.stem());
        for kind in [IndexKind::Index1, IndexKind::Index2] {
            assert!(info.has_index(kind), "{name}: both forms are present");
            index_files += 1;
            let bytes = std::fs::read(info.index_path(kind))?;
            let index = Index::parse(&bytes)?;

            // The terminator is all ones in the container's own key width, which for an `.index2` is
            // half the field. A reader that only knows the wide spelling hands back the terminator as a
            // record keyed 0xFFFFFFFF pointing at the data file's own header, so no real record may
            // carry either spelling.
            let key = terminator_key(&bytes, &index)?;
            if kind == IndexKind::Index2 && key == u64::from(u32::MAX) {
                narrow.push(name.clone());
            } else {
                assert_eq!(key, u64::MAX, "{name}: {kind:?} terminator");
            }
            for record in index.collisions() {
                assert!(
                    record.key != u64::MAX && record.key != u64::from(u32::MAX),
                    "{name}: a terminator was handed back as a record"
                );
            }
            if kind == IndexKind::Index1 && index.entries().is_empty() {
                empty.push(name.clone());
            }
        }
        for number in &info.dats {
            data_files += 1;
            let dat = Dat::open(info.dat_path(*number))?;
            if dat.common_header().is_none() {
                without_magic.push(format!("{name}.dat{number}"));
            }
            if dat.data_header().data_sha1 == UNCLAIMED_DIGEST {
                unclaimed_hash.push(name.clone());
            }
        }
    }
    without_magic.sort();
    unclaimed_hash.sort();
    narrow.sort();
    empty.sort();

    // Whichever spelling an archive uses, it uses it in the form that holds no entries: the two sets
    // being the same is what makes the eight of them one shape rather than two coincidences.
    assert_eq!(narrow, empty, "the short terminator and the empty archives");
    if exact {
        assert_eq!(
            u64::from(index_files),
            field_u64(&install["structure"], "index_files")?
        );
        assert_eq!(
            u64::from(data_files),
            field_u64(&install["structure"], "data_files")?
        );
        assert_eq!(
            without_magic.len() as u64,
            field_u64(install, "dats_without_magic")?,
            "data files carrying no magic: {without_magic:?}"
        );
        assert_eq!(empty, name_list(install, "empty_archives")?);
        assert_eq!(unclaimed_hash, name_list(install, "unclaimed_data_hash")?);
    } else {
        assert!(index_files >= 2 && data_files >= index_files / 2);
        assert!(!without_magic.is_empty(), "no data file lacks the magic");
    }
    Ok(())
}

/// The structure pass over a whole install: every container's headers, its segment hashes, its entries
/// and its collision table, plus the two forms of each archive naming the same places. Reads 55 MB and
/// nothing of a data file past its headers, so this is the tier to run on its own.
#[test]
#[ignore = "set APOGEE_SQPACK_REAL_INSTALL to a real game subtree to run"]
fn the_structure_of_a_pristine_install_is_clean() -> R<()> {
    let game = open_install()?;
    let doc = doc()?;
    let install = &doc["install"];
    let exact = is_recorded_version(&game, &doc)?;
    let opts = SweepOptions {
        walk_entries: false,
        gaps: GapPolicy::Skip,
        ..SweepOptions::default()
    };

    let started = Instant::now();
    let report = game.inspect(&opts);
    eprintln!(
        "structure: {:.2?}, {} index bytes, {} entries, {} places",
        started.elapsed(),
        report.totals.index_bytes,
        report.totals.entries,
        report.totals.locations
    );
    assert_clean(&report, "the structure pass");
    assert_none_of(
        &report,
        &name_list(install, "must_not_appear")?,
        "structure",
    );
    check_totals(
        &report.totals,
        &totals_of(&install["structure"])?,
        exact,
        "the structure pass",
    );

    // A report is a pure function of the tree and the options, so the thread count cannot change it.
    // Worth pinning here rather than in a costlier tier: this is the pass a caller runs interactively.
    let single = game.inspect(&SweepOptions {
        parallelism: Some(1),
        ..opts.clone()
    });
    assert_eq!(single, report, "one worker and the default pool disagree");
    Ok(())
}

/// The entry walk over a whole install: one positioned read at every location an index names, the slot
/// accounting that follows from it, and the chain of wiped regions across everything the slots do not
/// cover. Two million small reads.
#[test]
#[ignore = "set APOGEE_SQPACK_REAL_INSTALL to a real game subtree to run"]
fn the_entries_and_unclaimed_space_of_a_pristine_install_are_clean() -> R<()> {
    let game = open_install()?;
    let doc = doc()?;
    let install = &doc["install"];
    let exact = is_recorded_version(&game, &doc)?;
    let forbidden = name_list(install, "must_not_appear")?;
    let opts = SweepOptions::default();

    let started = Instant::now();
    let report = game.inspect(&opts);
    let totals = report.totals;
    eprintln!(
        "walk: {:.2?}, {} headers read, {} claimed + {} unclaimed in {} runs of {} regions",
        started.elapsed(),
        totals.entry_headers_read,
        totals.claimed_bytes,
        totals.unclaimed_bytes,
        totals.gaps,
        totals.unclaimed_regions
    );
    assert_clean(&report, "the entry walk");
    assert_none_of(&report, &forbidden, "the entry walk");
    check_totals(
        &totals,
        &totals_of(&install["walk"])?,
        exact,
        "the entry walk",
    );

    // The same pass over one archive at a time, against the recorded rows: an install-wide total can
    // be right while two archives are wrong in opposite directions.
    for row in rows(&doc, "archives")? {
        let info = archive_of(&game, row)?;
        let name = format!("{}/{}", info.repo.dir_name(), info.id.stem());
        let recorded: Vec<u8> = rows(row, "dats")?
            .iter()
            .filter_map(|n| n.as_u64().and_then(|n| u8::try_from(n).ok()))
            .collect();
        if exact {
            assert_eq!(info.dats, recorded, "{name}: data files present");
        }
        let one = game.inspect_archive(info, &opts);
        assert_clean(&one, &name);
        check_totals(&one.totals, &totals_of(&row["totals"])?, exact, &name);
    }
    Ok(())
}

/// Every data file's declared digest over its own data region, which is the only check that reads all
/// 118 GiB. Disk-bound and minutes long, so the entry walk is left off: what this adds to the
/// structure pass is exactly the region bytes. Nothing is asserted about wall time, since a slow disk
/// is not a fault in the code.
#[test]
#[ignore = "set APOGEE_SQPACK_REAL_INSTALL to a real game subtree to run"]
fn every_declared_data_region_hash_of_a_pristine_install_matches() -> R<()> {
    let game = open_install()?;
    let doc = doc()?;
    let install = &doc["install"];
    let exact = is_recorded_version(&game, &doc)?;
    let opts = SweepOptions {
        walk_entries: false,
        gaps: GapPolicy::Skip,
        hash_data_regions: true,
        ..SweepOptions::default()
    };

    let started = Instant::now();
    let report = game.inspect(&opts);
    let elapsed = started.elapsed();
    let rate = report.totals.bytes_hashed as f64 / elapsed.as_secs_f64() / 1e6;
    eprintln!(
        "region hashes: {:.2?}, {} bytes hashed at {rate:.0} MB/s, {} fields claimed nothing",
        elapsed, report.totals.bytes_hashed, report.totals.unclaimed_hash_fields
    );
    assert_clean(&report, "the region hashes");
    assert_none_of(
        &report,
        &name_list(install, "must_not_appear")?,
        "the region hashes",
    );
    check_totals(
        &report.totals,
        &totals_of(&install["hash"])?,
        exact,
        "the region hashes",
    );
    Ok(())
}

/// One archive extracted entirely through the sweep, because inflating 118 GiB is hours. The pure
/// per-container layer is what makes a single archive addressable, and this is the tier that says an
/// entry the index names not only has a header where it should but decodes to what it declares.
#[test]
#[ignore = "set APOGEE_SQPACK_REAL_INSTALL to a real game subtree to run"]
fn every_entry_of_one_archive_of_a_pristine_install_decodes() -> R<()> {
    let game = open_install()?;
    let doc = doc()?;
    let decode = &doc["install"]["decode"];
    let exact = is_recorded_version(&game, &doc)?;
    let row = rows(&doc, "archives")?
        .iter()
        .find(|r| r["repo"] == decode["repo"] && r["archive"] == decode["archive"])
        .ok_or("the decode pass names an archive with no recorded row")?;
    let info = archive_of(&game, row)?;
    let name = format!("{}/{}", info.repo.dir_name(), info.id.stem());

    let started = Instant::now();
    let report = game.inspect_archive(
        info,
        &SweepOptions {
            decode_entries: true,
            ..SweepOptions::default()
        },
    );
    eprintln!(
        "decode of {name}: {:.2?}, {} entries extracted",
        started.elapsed(),
        report.totals.entries_decoded
    );
    assert_clean(&report, &name);
    let want = Totals {
        entries_decoded: field_u64(decode, "entries_decoded")?,
        ..totals_of(&row["totals"])?
    };
    check_totals(&report.totals, &want, exact, &name);
    Ok(())
}

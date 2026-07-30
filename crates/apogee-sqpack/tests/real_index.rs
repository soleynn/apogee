//! Recorded-fact pins for SqPack index containers, captured from a real FFXIV install.
//!
//! The recorded values were produced by a separate implementation of the format, out of process, so
//! what the gated test proves is agreement between two readers rather than a program agreeing with
//! itself. The hermetic test checks the recording against the crate's own definitions: every
//! recorded key is what [`hash_path`] computes for the path beside it, every count is its segment's
//! size over the record length the crate declares, the non-empty segments tile the file from
//! `0x800`, and every recorded location fits the packing an entry word uses. CI carries no Square
//! Enix bytes.
//!
//! The install-gated test re-reads the real containers named in the fixture from
//! `$APOGEE_SQPACK_REAL_INSTALL` and asserts the parser reproduces all of it; it is `#[ignore]` by
//! default. A patch rewrites every extent, count and location, so only the patch the fixture was
//! recorded on is held to those. What is checked on any version is what a patch cannot move: the
//! fields the format fixes, each segment's declared SHA-1 against the bytes the parser framed, the
//! dat count against the dat files present, a path's key against what the crate hashes it to, each
//! collision record against its own path, each folder row against the run it names, and a floor
//! under every count. A patch day fails on a regression rather than on a count.

use std::error::Error;
use std::fmt::Write as _;
use std::path::Path;

use apogee_sqpack::{
    ArchiveId, COLLISION_RECORD_LEN, COMMON_HEADER_LEN, FOLDER_ROW_LEN, GameData, INDEX_HEADER_LEN,
    Index, IndexKind, Repo, SQPACK_MAGIC, hash_path,
};
use serde_json::Value;

type R<T> = Result<T, Box<dyn Error>>;

/// Where the first segment starts in every index container: past both headers.
const FIRST_SEGMENT: u64 = COMMON_HEADER_LEN as u64 + INDEX_HEADER_LEN as u64;

fn doc() -> R<Value> {
    Ok(serde_json::from_str(include_str!(
        "fixtures/real_index.json"
    ))?)
}

fn records(doc: &Value) -> R<&Vec<Value>> {
    doc["records"]
        .as_array()
        .ok_or_else(|| "records is not an array".into())
}

/// Whether the tree is the patch the recording was taken from, read from the base repository's
/// version file.
fn is_recorded_version(game: &GameData, doc: &Value) -> R<bool> {
    let want = field_str(doc, "version")?;
    Ok(game
        .repos()
        .iter()
        .any(|r| r.repo == Repo::Base && r.version.as_deref() == Some(want)))
}

/// A count the recording found work in, off the patch it was recorded on: still within a tenth of
/// what was measured, which is what makes a patch day fail on a finding rather than on a count.
fn assert_floor(found: u64, want: u64, where_: &str) {
    if want != 0 {
        assert!(
            found * 10 >= want * 9,
            "{where_}: {found} is far below the recorded {want}"
        );
    }
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

fn field_array<'a>(v: &'a Value, key: &str) -> R<&'a Vec<Value>> {
    v[key]
        .as_array()
        .ok_or_else(|| format!("{key} is not an array").into())
}

fn hex_u32(v: &Value, key: &str) -> R<u32> {
    Ok(u32::from_str_radix(field_str(v, key)?, 16)?)
}

fn hex_u64(v: &Value, key: &str) -> R<u64> {
    Ok(u64::from_str_radix(field_str(v, key)?, 16)?)
}

fn kind_of(record: &Value) -> R<IndexKind> {
    match field_str(record, "kind")? {
        "index1" => Ok(IndexKind::Index1),
        "index2" => Ok(IndexKind::Index2),
        other => Err(format!("unknown index kind {other}").into()),
    }
}

/// The key the crate computes for `path` under `kind`.
fn key_for(path: &str, kind: IndexKind) -> u64 {
    let hash = hash_path(path);
    match kind {
        IndexKind::Index2 => u64::from(hash.full),
        _ => hash.key(),
    }
}

fn segments(record: &Value) -> R<Vec<(u64, u64, String)>> {
    let mut out = Vec::new();
    for seg in field_array(record, "segments")? {
        out.push((
            field_u64(seg, "offset")?,
            field_u64(seg, "size")?,
            field_str(seg, "sha1")?.to_owned(),
        ));
    }
    if out.len() != 4 {
        return Err(format!("{} segments recorded, expected 4", out.len()).into());
    }
    Ok(out)
}

#[test]
fn the_recording_is_consistent_with_the_formats_this_crate_declares() -> R<()> {
    let doc = doc()?;
    let records = records(&doc)?;
    assert!(!records.is_empty(), "fixture has records");
    assert!(
        !field_str(&doc, "version")?.is_empty(),
        "fixture is versioned"
    );
    for record in records {
        let path = field_str(record, "path")?;
        let kind = kind_of(record)?;
        let segments = segments(record)?;

        // The header fields the format fixes, observed to hold on a real install.
        assert_eq!(
            field_u64(record, "header_size")?,
            u64::from(INDEX_HEADER_LEN),
            "{path}"
        );
        assert_eq!(field_u64(record, "version")?, 1, "{path}");
        assert_eq!(
            field_u64(record, "kind_word")?,
            u64::from(kind.word()),
            "{path}"
        );

        // Each count is its segment's size over the record length the crate declares. The collision
        // table always carries its terminating record, so an empty one is still 256 bytes.
        let entry_len = kind.entry_len() as u64;
        assert_eq!(
            field_u64(record, "entry_count")? * entry_len,
            segments[0].1,
            "{path}: entry segment"
        );
        assert_eq!(
            (field_u64(record, "collision_count")? + 1) * COLLISION_RECORD_LEN as u64,
            segments[1].1,
            "{path}: collision segment"
        );
        assert_eq!(
            field_u64(record, "folder_count")? * FOLDER_ROW_LEN as u64,
            segments[3].1,
            "{path}: folder segment"
        );
        if kind == IndexKind::Index2 {
            assert_eq!(
                segments[2].1, 0,
                "{path}: an index2 carries no third segment"
            );
            assert_eq!(
                segments[3].1, 0,
                "{path}: an index2 carries no folder table"
            );
        }

        // The non-empty segments tile the file, back to back, from the end of the two headers.
        let mut extents: Vec<(u64, u64)> = segments
            .iter()
            .filter(|(_, size, _)| *size != 0)
            .map(|(offset, size, _)| (*offset, *size))
            .collect();
        extents.sort_unstable();
        let mut cursor = FIRST_SEGMENT;
        for (offset, size) in &extents {
            assert_eq!(*offset, cursor, "{path}: segment at {offset} leaves a gap");
            cursor += size;
        }
        assert_eq!(
            cursor,
            field_u64(record, "file_len")?,
            "{path}: file length"
        );

        // The archive's own file name is what the id spells.
        let archive = ArchiveId::parse_stem(field_str(record, "archive")?)
            .ok_or_else(|| format!("{path}: archive stem does not parse"))?;
        assert!(path.ends_with(&archive.index_file_name(kind)), "{path}");
        assert_eq!(archive.expansion, repo_of(record)?.expansion(), "{path}");

        // Every recorded key is what the crate hashes its path to, and every recorded location fits
        // the packing an entry word uses.
        for row in field_array(record, "resolved")? {
            let file = field_str(row, "path")?;
            assert_eq!(key_for(file, kind), hex_u64(row, "key")?, "{path}: {file}");
            let dat = field_u64(row, "dat")?;
            assert!(
                dat < field_u64(record, "data_file_count")?,
                "{path}: {file} dat"
            );
            let offset = field_u64(row, "offset")?;
            assert_eq!(offset % 128, 0, "{path}: {file} is not 128-aligned");
            assert!(offset / 8 <= u64::from(u32::MAX), "{path}: {file} offset");
        }

        // A collision record's key is what its own path hashes to, and the sharers are numbered.
        let collisions = field_array(record, "collisions")?;
        for (n, row) in collisions.iter().enumerate() {
            let file = field_str(row, "path")?;
            assert_eq!(key_for(file, kind), hex_u64(row, "key")?, "{path}: {file}");
            assert_eq!(
                field_u64(row, "conflict_index")?,
                (n % 2) as u64,
                "{path}: {file} conflict index"
            );
        }
        for pair in collisions.chunks(2) {
            if let [a, b] = pair {
                assert_eq!(
                    hex_u64(a, "key")?,
                    hex_u64(b, "key")?,
                    "{path}: a pair shares a key"
                );
                assert_ne!(field_str(a, "path")?, field_str(b, "path")?, "{path}");
            }
        }

        // A sample entry's key sits inside the container's own key space, and its location word names
        // a dat file the archive has.
        for sample in field_array(record, "sample_entries")? {
            let packed = hex_u32(sample, "packed")?;
            let dat = u64::from((packed >> 1) & 0b111);
            assert!(
                dat < field_u64(record, "data_file_count")?,
                "{path}: sample dat"
            );
            if kind == IndexKind::Index2 {
                assert_eq!(
                    hex_u64(sample, "key")? >> 32,
                    0,
                    "{path}: index2 key is 32 bits"
                );
            }
        }
    }
    Ok(())
}

/// Rebuild an index container from the recording: its two headers written where a real container
/// writes them, the recorded collision records followed by a terminator, and zeros everywhere else.
/// Every field the parser reads lives in the first `0x800` bytes, so what this proves is that the
/// parser finds each one at the offset a real install put it at.
fn rebuild(record: &Value) -> R<Vec<u8>> {
    let mut out = vec![0u8; usize::try_from(field_u64(record, "file_len")?)?];
    let kind = kind_of(record)?;

    out.get_mut(0..8)
        .ok_or("container is shorter than its magic")?
        .copy_from_slice(&SQPACK_MAGIC);
    write_u32(&mut out, 0x0C, u32::try_from(COMMON_HEADER_LEN)?);
    write_u32(&mut out, 0x10, 1);
    write_u32(&mut out, 0x14, 2); // an index container

    let head = COMMON_HEADER_LEN;
    write_u32(
        &mut out,
        head,
        u32::try_from(field_u64(record, "header_size")?)?,
    );
    write_u32(
        &mut out,
        head + 0x04,
        u32::try_from(field_u64(record, "version")?)?,
    );
    write_u32(
        &mut out,
        head + 0x50,
        u32::try_from(field_u64(record, "data_file_count")?)?,
    );
    write_u32(&mut out, head + 0x12C, kind.word());
    for ((offset, size, sha1), at) in segments(record)?
        .into_iter()
        .zip([0x08usize, 0x54, 0x9C, 0xE4])
    {
        write_u32(&mut out, head + at, u32::try_from(offset)?);
        write_u32(&mut out, head + at + 4, u32::try_from(size)?);
        let raw = unhex(&sha1)?;
        out.get_mut(head + at + 8..head + at + 28)
            .ok_or("segment descriptor does not fit")?
            .copy_from_slice(&raw);
    }

    // The collision table the recording carries, then the terminator that ends it.
    let base = usize::try_from(segments(record)?[1].0)?;
    let mut at = base;
    for row in field_array(record, "collisions")? {
        write_u64(&mut out, at, hex_u64(row, "key")?);
        write_u32(&mut out, at + 8, hex_u32(row, "packed")?);
        write_u32(
            &mut out,
            at + 12,
            u32::try_from(field_u64(row, "conflict_index")?)?,
        );
        let path = field_str(row, "path")?.as_bytes();
        out.get_mut(at + 16..at + 16 + path.len())
            .ok_or("collision path does not fit")?
            .copy_from_slice(path);
        at += COLLISION_RECORD_LEN;
    }
    write_u64(&mut out, at, u64::MAX);
    Ok(out)
}

fn write_u32(buf: &mut [u8], at: usize, value: u32) {
    if let Some(slot) = buf.get_mut(at..at + 4) {
        slot.copy_from_slice(&value.to_le_bytes());
    }
}

fn write_u64(buf: &mut [u8], at: usize, value: u64) {
    if let Some(slot) = buf.get_mut(at..at + 8) {
        slot.copy_from_slice(&value.to_le_bytes());
    }
}

fn unhex(text: &str) -> R<Vec<u8>> {
    let mut out = Vec::with_capacity(text.len() / 2);
    for pair in text.as_bytes().chunks(2) {
        out.push(u8::from_str_radix(std::str::from_utf8(pair)?, 16)?);
    }
    Ok(out)
}

#[test]
fn the_parser_reads_a_container_rebuilt_from_the_recording() -> R<()> {
    let doc = doc()?;
    for record in records(&doc)? {
        let path = field_str(record, "path")?;
        let index = Index::parse(&rebuild(record)?)?;
        let header = index.header();
        let kind = kind_of(record)?;

        assert_eq!(index.kind(), kind, "{path}");
        assert_eq!(
            u64::from(header.header_size),
            field_u64(record, "header_size")?,
            "{path}"
        );
        assert_eq!(
            u64::from(header.version),
            field_u64(record, "version")?,
            "{path}"
        );
        assert_eq!(
            u64::from(header.data_file_count),
            field_u64(record, "data_file_count")?,
            "{path}"
        );
        for (n, (offset, size, sha1)) in segments(record)?.iter().enumerate() {
            let declared = header.segments[n];
            assert_eq!(
                u64::from(declared.offset),
                *offset,
                "{path} segment {n} offset"
            );
            assert_eq!(u64::from(declared.size), *size, "{path} segment {n} size");
            assert_eq!(hex(&declared.sha1), *sha1, "{path} segment {n} sha1");
        }
        // The counts follow from the extents and the record lengths this crate declares.
        assert_eq!(
            index.entries().len() as u64,
            field_u64(record, "entry_count")?,
            "{path}"
        );
        assert_eq!(
            index.folders().len() as u64,
            field_u64(record, "folder_count")?,
            "{path}"
        );

        // Each recorded collision record reads back, and the terminator ends the table.
        let recorded = field_array(record, "collisions")?;
        assert_eq!(
            index.collisions().len(),
            recorded.len(),
            "{path} collisions"
        );
        for (found, row) in index.collisions().iter().zip(recorded) {
            assert_eq!(found.key, hex_u64(row, "key")?, "{path}");
            assert_eq!(found.packed, hex_u32(row, "packed")?, "{path}");
            assert_eq!(found.path, field_str(row, "path")?, "{path}");
        }
    }
    Ok(())
}

fn repo_of(record: &Value) -> R<Repo> {
    match field_str(record, "repo")? {
        "ffxiv" => Ok(Repo::Base),
        other => other
            .strip_prefix("ex")
            .and_then(|n| n.parse::<u8>().ok())
            .map(Repo::Ex)
            .ok_or_else(|| format!("unknown repository {other}").into()),
    }
}

/// Re-read the real containers named in the fixture and confirm the parser still reproduces every
/// recorded fact. Gated on `APOGEE_SQPACK_REAL_INSTALL` (the game subtree holding `sqpack/` and
/// `ffxivgame.ver`); `#[ignore]` so the hermetic suite stays install-free.
///
/// Every extent, count and location is the patch's, so only that patch is held to them. What holds
/// on any version is checked either way, and is most of what the recording is for: a segment's
/// declared SHA-1 against the bytes the parser framed is what says the extents are the right ones,
/// whatever they happen to be.
#[test]
#[ignore = "set APOGEE_SQPACK_REAL_INSTALL to a real game subtree to run"]
fn the_parser_reproduces_the_recording_on_a_live_install() -> R<()> {
    let root = std::env::var("APOGEE_SQPACK_REAL_INSTALL")?;
    let root = Path::new(&root);
    let game = GameData::open(root)?;
    let doc = doc()?;
    let exact = is_recorded_version(&game, &doc)?;

    for record in records(&doc)? {
        let name = field_str(record, "path")?;
        let file = root.join("sqpack").join(name);
        let bytes = std::fs::read(&file)?;
        let index = Index::parse(&bytes)?;
        let header = index.header();
        let kind = kind_of(record)?;

        // The fields the format fixes, which no patch moves.
        assert_eq!(index.kind(), kind, "{name}");
        assert_eq!(
            u64::from(header.header_size),
            field_u64(record, "header_size")?,
            "{name}"
        );
        assert_eq!(
            u64::from(header.version),
            field_u64(record, "version")?,
            "{name}"
        );
        assert!(index.is_sorted(), "{name}: entries are in key order");

        // The header's dat count is the number of dat files the archive really has.
        let archive = ArchiveId::parse_stem(field_str(record, "archive")?)
            .ok_or("archive stem does not parse")?;
        let dir = file.parent().ok_or("archive has no directory")?;
        let present = (0..u8::MAX)
            .take_while(|n| dir.join(archive.dat_file_name(*n)).is_file())
            .count();
        assert_eq!(
            present as u64,
            u64::from(header.data_file_count),
            "{name} dat files"
        );

        // Each segment's declared SHA-1 against the bytes the parser framed: whatever the extents
        // are on this patch, they are the ones the container's own header vouches for.
        for (n, declared) in header.segments.iter().enumerate() {
            let start = declared.offset as usize;
            let end = start + declared.size as usize;
            let framed = bytes
                .get(start..end)
                .ok_or_else(|| format!("{name} segment {n} runs past the file"))?;
            assert_eq!(
                sha1_hex(framed),
                hex(&declared.sha1),
                "{name} segment {n} contents"
            );
        }

        // Every collision record's key is what its own path hashes to, and the entry it names is a
        // placeholder whose location lives in the record rather than in the entry.
        for row in index.collisions() {
            assert_eq!(
                key_for(&row.path, kind),
                row.key,
                "{name}: {} key",
                row.path
            );
            let entry = index.lookup(row.key).ok_or("collision key has no entry")?;
            assert!(
                entry.is_collision(),
                "{name}: {} entry is a placeholder",
                row.path
            );
            assert_eq!(entry.location(), None, "{name}: {}", row.path);
        }

        // Every folder row names a run of entries that all carry its hash.
        for (n, row) in index.folders().iter().enumerate() {
            let run = index.folder_entries(row).ok_or("folder row names no run")?;
            assert!(
                run.iter().all(|e| e.folder_hash() == row.hash),
                "{name} folder {n}: every entry in the run carries the folder's hash"
            );
        }

        // Every recorded path still hashes to its recorded key and still resolves, through this
        // container and through the whole install, to one and the same place.
        for row in field_array(record, "resolved")? {
            let file = field_str(row, "path")?;
            assert_eq!(key_for(file, kind), hex_u64(row, "key")?, "{name}: {file}");
            let direct = index
                .resolve(file)?
                .ok_or_else(|| format!("{name}: {file} no longer resolves"))?;
            let found = game
                .lookup(file)?
                .ok_or_else(|| format!("{file} does not resolve through the install"))?;
            assert_eq!(
                found.archive.stem(),
                field_str(record, "archive")?,
                "{file} archive"
            );
            assert_eq!(found.repo, repo_of(record)?, "{file} repo");
            assert_eq!(found.dat, direct.dat, "{file} dat");
            assert_eq!(found.offset, direct.offset, "{file} offset");
            assert!(
                found.dat_path.is_file(),
                "{file}: {:?} exists",
                found.dat_path
            );
            if exact {
                assert_eq!(u64::from(direct.dat), field_u64(row, "dat")?, "{file} dat");
                assert_eq!(direct.offset, field_u64(row, "offset")?, "{file} offset");
            }
        }

        if exact {
            assert_recorded_extents(&index, &bytes, record, name)?;
        } else {
            assert_floor(
                index.entries().len() as u64,
                field_u64(record, "entry_count")?,
                &format!("{name} entries"),
            );
            assert_floor(
                index.folders().len() as u64,
                field_u64(record, "folder_count")?,
                &format!("{name} folders"),
            );
            assert_floor(
                index.collisions().len() as u64,
                field_u64(record, "collision_count")?,
                &format!("{name} collisions"),
            );
        }
    }

    // The install's archives are discovered from the index files present, and each recorded container
    // is one of them.
    for record in records(&doc)? {
        let archive = ArchiveId::parse_stem(field_str(record, "archive")?)
            .ok_or("archive stem does not parse")?;
        let info = game
            .archive(repo_of(record)?, archive)
            .ok_or_else(|| format!("{} was not enumerated", archive.stem()))?;
        assert_eq!(info.repo, repo_of(record)?);
        assert!(
            info.has_index1 && info.has_index2,
            "{} has both index forms",
            archive.stem()
        );
    }
    Ok(())
}

/// Everything a patch moves, on the one patch the recording was taken from: the container's length,
/// its counts, every segment's extent and declared digest, and the entries, folders and collision
/// records the recording sampled.
fn assert_recorded_extents(index: &Index, bytes: &[u8], record: &Value, name: &str) -> R<()> {
    let header = index.header();
    assert_eq!(
        bytes.len() as u64,
        field_u64(record, "file_len")?,
        "{name} length"
    );
    assert_eq!(
        u64::from(header.data_file_count),
        field_u64(record, "data_file_count")?,
        "{name}"
    );
    assert_eq!(
        index.entries().len() as u64,
        field_u64(record, "entry_count")?,
        "{name}"
    );
    assert_eq!(
        index.folders().len() as u64,
        field_u64(record, "folder_count")?,
        "{name}"
    );
    assert_eq!(
        index.collisions().len() as u64,
        field_u64(record, "collision_count")?,
        "{name}"
    );

    for (n, (offset, size, sha1)) in segments(record)?.iter().enumerate() {
        let declared = header.segments[n];
        assert_eq!(
            u64::from(declared.offset),
            *offset,
            "{name} segment {n} offset"
        );
        assert_eq!(u64::from(declared.size), *size, "{name} segment {n} size");
        assert_eq!(
            hex(&declared.sha1),
            *sha1,
            "{name} segment {n} declared sha1"
        );
    }

    for sample in field_array(record, "sample_entries")? {
        let at = field_u64(sample, "at")? as usize;
        let entry = index
            .entries()
            .get(at)
            .ok_or("sample entry is out of range")?;
        assert_eq!(entry.key, hex_u64(sample, "key")?, "{name} entry {at} key");
        assert_eq!(
            entry.packed,
            hex_u32(sample, "packed")?,
            "{name} entry {at} packed"
        );
    }

    for (n, sample) in field_array(record, "sample_folders")?.iter().enumerate() {
        let row = index
            .folders()
            .get(n)
            .ok_or("sample folder is out of range")?;
        assert_eq!(row.hash, hex_u32(sample, "hash")?, "{name} folder {n}");
        assert_eq!(
            u64::from(row.entries_offset),
            field_u64(sample, "entries_offset")?,
            "{name} folder {n} offset"
        );
        assert_eq!(
            u64::from(row.entries_size),
            field_u64(sample, "entries_size")?,
            "{name} folder {n} size"
        );
    }

    for row in field_array(record, "collisions")? {
        let file = field_str(row, "path")?;
        let found = index
            .collisions()
            .iter()
            .find(|c| c.path == file)
            .ok_or_else(|| format!("{name}: no collision record for {file}"))?;
        assert_eq!(found.key, hex_u64(row, "key")?, "{name}: {file} key");
        assert_eq!(
            found.packed,
            hex_u32(row, "packed")?,
            "{name}: {file} packed"
        );
        assert_eq!(
            u64::from(found.conflict_index),
            field_u64(row, "conflict_index")?,
            "{name}: {file} conflict index"
        );
    }
    Ok(())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

fn sha1_hex(bytes: &[u8]) -> String {
    use sha1::{Digest, Sha1};
    hex(&Sha1::digest(bytes))
}

//! Recorded-fact pins for SqPack dat entries, captured from a real FFXIV install.
//!
//! The recorded values were produced by a separate implementation of the format, out of process, so
//! what the install-gated test proves is agreement between two readers rather than a program
//! agreeing with itself. The hermetic test checks the recording against the crate's own definitions:
//! every length against the unit the entry header counts in, every table against the header that has
//! to hold it, every extracted length against what the entry declares. CI carries no Square Enix
//! bytes, only field values and digests.
//!
//! The install-gated test re-reads the real containers from `$APOGEE_SQPACK_REAL_INSTALL`, extracts
//! every recorded entry, and asserts the crate reproduces all of it down to the sha256 of the file's
//! bytes; it is `#[ignore]` by default.

use std::error::Error;
use std::fmt::Write as _;
use std::path::Path;

use apogee_sqpack::{
    ArchiveId, ContentType, DATA_HEADER_LEN, DATA_HEADER_OFFSET, DATA_UNIT, Dat, ENTRY_HEADER_LEN,
    Entry, EntryBody, GameData, IndexKind, MIP_LEVEL_LEN, MODEL_FILE_HEADER_LEN,
    MODEL_TABLE_OFFSET, ModelTable, Repo, STANDARD_BLOCK_LEN,
};
use serde_json::Value;

type R<T> = Result<T, Box<dyn Error>>;

/// The sha256 of nothing, which is what an empty entry extracts to.
const EMPTY_SHA256: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

fn doc() -> R<Value> {
    Ok(serde_json::from_str(include_str!(
        "fixtures/real_entries.json"
    ))?)
}

fn rows<'a>(doc: &'a Value, key: &str) -> R<&'a Vec<Value>> {
    doc[key]
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

fn opt_u64(v: &Value, key: &str) -> Option<u64> {
    v[key].as_u64()
}

fn content_type(record: &Value) -> R<ContentType> {
    match field_str(record, "content_type")? {
        "empty" => Ok(ContentType::Empty),
        "standard" => Ok(ContentType::Standard),
        "model" => Ok(ContentType::Model),
        "texture" => Ok(ContentType::Texture),
        other => Err(format!("unknown content type {other}").into()),
    }
}

/// How long a header has to be to hold the record's table, and so what the crate expects the
/// container to have written: the shared words, the table, and the padding up to a whole unit.
fn header_needs(record: &Value) -> R<u64> {
    let head = ENTRY_HEADER_LEN as u64 + 4;
    let blocks = opt_u64(record, "blocks").unwrap_or(0);
    Ok(match content_type(record)? {
        ContentType::Standard => head + blocks * STANDARD_BLOCK_LEN as u64,
        ContentType::Texture => {
            head + field_u64(record, "mips")? * MIP_LEVEL_LEN as u64 + blocks * 2
        }
        ContentType::Model => MODEL_TABLE_OFFSET as u64 + blocks * 2,
        _ => ENTRY_HEADER_LEN as u64,
    })
}

#[test]
fn the_recording_is_consistent_with_the_formats_this_crate_declares() -> R<()> {
    let doc = doc()?;
    let entries = rows(&doc, "entries")?;
    assert!(entries.len() >= 4, "fixture has records");

    let mut seen = Vec::new();
    for record in entries {
        let kind = content_type(record)?;
        seen.push(kind);
        let where_ = format!(
            "{}/{} dat{} @{}",
            field_str(record, "repo")?,
            field_str(record, "archive")?,
            field_u64(record, "dat")?,
            field_u64(record, "offset")?
        );

        // Every entry starts on a 128-byte boundary, which is what leaves an index's location word
        // its four low bits.
        assert_eq!(
            field_u64(record, "offset")? % u64::from(DATA_UNIT),
            0,
            "{where_}"
        );

        // The header is padded to a whole number of units and is long enough for its own table.
        let header_size = field_u64(record, "header_size")?;
        assert_eq!(
            header_size % u64::from(DATA_UNIT),
            0,
            "{where_}: header size"
        );
        let needs = header_needs(record)?;
        assert!(
            header_size >= needs,
            "{where_}: header {header_size} < {needs}"
        );
        assert!(
            header_size < needs + u64::from(DATA_UNIT),
            "{where_}: header {header_size} is more than one unit of padding over {needs}"
        );

        // The allocation is never smaller than what is stored, and the occupancy is the stored bytes
        // rounded up to the unit it counts in.
        let allocated = field_u64(record, "allocated_units")?;
        let occupied = field_u64(record, "occupied_units")?;
        assert!(allocated >= occupied, "{where_}: allocation");
        if let Some(on_disk) = opt_u64(record, "on_disk_len") {
            assert_eq!(
                occupied * u64::from(DATA_UNIT),
                on_disk.div_ceil(u64::from(DATA_UNIT)) * u64::from(DATA_UNIT),
                "{where_}: occupancy"
            );
        }

        // An extraction never produces more than the entry declares. It produces exactly that for
        // every type but a volume texture, whose declared length counts padding between mip surfaces
        // the archive does not store.
        let raw = field_u64(record, "raw_size")?;
        let extracted = field_u64(record, "extracted_len")?;
        assert!(extracted <= raw, "{where_}: extracted {extracted} > {raw}");
        if kind != ContentType::Texture {
            assert_eq!(extracted, raw, "{where_}: extracted length");
        }

        let sha = field_str(record, "sha256")?;
        assert_eq!(sha.len(), 64, "{where_}: digest");
        assert!(sha.bytes().all(|b| b.is_ascii_hexdigit()), "{where_}");

        match kind {
            ContentType::Empty => {
                // An empty entry holds nothing, whatever its leftover words say.
                assert_eq!(extracted, 0, "{where_}");
                assert_eq!(sha, EMPTY_SHA256, "{where_}");
            }
            ContentType::Texture => {
                let head = field_u64(record, "texture_header_len")?;
                assert!(extracted >= head, "{where_}: texture header");
                assert!(field_u64(record, "mips")? > 0, "{where_}: mips");
                assert!(
                    field_u64(record, "blocks")? >= field_u64(record, "mips")?,
                    "{where_}: a mip has at least one block"
                );
            }
            ContentType::Model => {
                // The file is the header the packer folded away plus the sections, in order.
                let lengths = rows(record, "section_lengths")?;
                assert_eq!(lengths.len(), 11, "{where_}: sections");
                let sum: u64 = lengths.iter().filter_map(Value::as_u64).sum();
                assert_eq!(
                    sum + MODEL_FILE_HEADER_LEN as u64,
                    raw,
                    "{where_}: sections and header make the file"
                );
                assert!(field_u64(record, "lod_count")? <= 3, "{where_}: levels");
            }
            _ => {}
        }
    }

    // Every content type this crate reads is pinned by at least one record, which is what the gate
    // for this rung asks for.
    for kind in [
        ContentType::Empty,
        ContentType::Standard,
        ContentType::Model,
        ContentType::Texture,
    ] {
        assert!(seen.contains(&kind), "no record for {kind:?}");
    }
    // And at least one of each of the two shapes a texture takes.
    assert!(
        entries.iter().any(|r| {
            content_type(r).is_ok_and(|k| k == ContentType::Texture)
                && field_u64(r, "extracted_len")
                    .is_ok_and(|e| field_u64(r, "raw_size").is_ok_and(|raw| e < raw))
        }),
        "no record for a texture whose declared length counts padding it does not store"
    );
    Ok(())
}

#[test]
fn the_recorded_dat_headers_describe_the_files_they_came_from() -> R<()> {
    let doc = doc()?;
    for record in rows(&doc, "dats")? {
        let path = field_str(record, "path")?;
        assert_eq!(
            field_u64(record, "header_size")?,
            u64::from(DATA_HEADER_LEN),
            "{path}"
        );
        // Both headers plus the data region is the whole file.
        let region = field_u64(record, "data_units")? * u64::from(DATA_UNIT);
        assert_eq!(
            DATA_HEADER_OFFSET + u64::from(DATA_HEADER_LEN) + region,
            field_u64(record, "file_len")?,
            "{path}"
        );
        assert_eq!(field_str(record, "data_sha1")?.len(), 40, "{path}");
    }
    // A real install carries dat files with no SqPack magic at all, and the recording has one, since
    // refusing them would make a fifth of an install unreadable.
    assert!(
        rows(&doc, "dats")?
            .iter()
            .any(|r| r["has_magic"] == Value::Bool(false)),
        "no record for a dat file without a common header"
    );
    Ok(())
}

/// Re-read the real containers named in the fixture and confirm the crate reproduces every recorded
/// fact, the extracted bytes included. Gated on `APOGEE_SQPACK_REAL_INSTALL` (the game subtree
/// holding `sqpack/` and `ffxivgame.ver`); `#[ignore]` so the hermetic suite stays install-free.
#[test]
#[ignore = "set APOGEE_SQPACK_REAL_INSTALL to a real game subtree to run"]
fn the_crate_reproduces_the_recording_on_a_live_install() -> R<()> {
    let root = std::env::var("APOGEE_SQPACK_REAL_INSTALL")?;
    let root = Path::new(&root);
    let game = GameData::open(root)?;
    let doc = doc()?;

    for record in rows(&doc, "dats")? {
        let name = field_str(record, "path")?;
        let dat = Dat::open(root.join("sqpack").join(name))?;
        let _ = &game;
        let header = dat.data_header();
        assert_eq!(dat.len(), field_u64(record, "file_len")?, "{name} length");
        assert_eq!(
            dat.common_header().is_some(),
            record["has_magic"] == Value::Bool(true),
            "{name} common header"
        );
        assert_eq!(
            u64::from(header.header_size),
            field_u64(record, "header_size")?,
            "{name}"
        );
        assert_eq!(
            u64::from(header.unclassified),
            field_u64(record, "unclassified")?,
            "{name}"
        );
        assert_eq!(
            u64::from(header.data_units),
            field_u64(record, "data_units")?,
            "{name}"
        );
        assert_eq!(
            u64::from(header.span_index),
            field_u64(record, "span_index")?,
            "{name}"
        );
        assert_eq!(
            u64::from(header.max_file_size),
            field_u64(record, "max_file_size")?,
            "{name}"
        );
        assert_eq!(
            hex(&header.data_sha1),
            field_str(record, "data_sha1")?,
            "{name}"
        );
        assert_eq!(
            header.declared_file_len(),
            dat.len(),
            "{name} declared length"
        );
    }

    for record in rows(&doc, "entries")? {
        let stem = field_str(record, "archive")?;
        let archive = ArchiveId::parse_stem(stem).ok_or_else(|| format!("{stem}: archive stem"))?;
        let repo = repo_of(record)?;
        let info = game
            .archive(repo, archive)
            .ok_or_else(|| format!("{} was not enumerated", archive.stem()))?;
        let dat_number = u8::try_from(field_u64(record, "dat")?)?;
        let where_ = format!("{}/{}", repo.dir_name(), archive.stem());
        let dat = game.dat_of(info, dat_number)?;
        let offset = field_u64(record, "offset")?;
        let entry = dat.entry_at(offset)?;

        assert_eq!(
            entry.content_type(),
            content_type(record)?,
            "{where_} @{offset}"
        );
        assert_eq!(
            u64::from(entry.header().header_size),
            field_u64(record, "header_size")?,
            "{where_} @{offset} header size"
        );
        assert_eq!(
            entry.declared_len(),
            field_u64(record, "raw_size")?,
            "{where_} @{offset} declared length"
        );
        assert_eq!(
            u64::from(entry.header().allocated_units),
            field_u64(record, "allocated_units")?,
            "{where_} @{offset} allocation"
        );
        assert_eq!(
            u64::from(entry.header().occupied_units),
            field_u64(record, "occupied_units")?,
            "{where_} @{offset} occupancy"
        );
        if let Some(blocks) = opt_u64(record, "blocks") {
            assert_eq!(
                entry.block_count() as u64,
                blocks,
                "{where_} @{offset} blocks"
            );
        }
        check_body(&entry, record, &where_)?;

        let bytes = dat.read(&entry)?;
        assert_eq!(
            bytes.len() as u64,
            field_u64(record, "extracted_len")?,
            "{where_} @{offset} extracted length"
        );
        assert_eq!(
            sha256_hex(&bytes),
            field_str(record, "sha256")?,
            "{where_} @{offset} extracted bytes"
        );

        if entry.content_type() == ContentType::Model {
            check_model_file(&bytes, record, &where_)?;
        }

        // A record that names a path must reach the same bytes through the install, which is the
        // whole path from a game path to a file: hash, index, dat, entry, blocks, codec.
        if let Some(path) = record["path"].as_str() {
            let found = game
                .lookup(path)?
                .ok_or_else(|| format!("{path} does not resolve"))?;
            assert_eq!(found.offset, offset, "{path} offset");
            assert_eq!(
                found.archive.stem(),
                field_str(record, "archive")?,
                "{path} archive"
            );
            let read = game
                .read(path)?
                .ok_or_else(|| format!("{path} does not read"))?;
            assert_eq!(read, bytes, "{path} bytes");
        }
    }
    Ok(())
}

/// Every word the fixed table carries, against the recording. The reader and the synthetic builder
/// share their idea of where these sit, so only a real container can say whether that idea is right:
/// a group moved in the struct would tile just as well and mean something else entirely.
fn check_model_table(table: &ModelTable, record: &Value, where_: &str) -> R<()> {
    let words = &record["table_words"];
    let word = |key: &str| field_u64(words, key);
    let triple = |key: &str| -> R<[u64; 3]> {
        let row = words[key]
            .as_array()
            .ok_or_else(|| format!("{where_}: {key} is not an array"))?;
        let mut out = [0u64; 3];
        for (slot, value) in out.iter_mut().zip(row) {
            *slot = value.as_u64().ok_or_else(|| format!("{where_}: {key}"))?;
        }
        Ok(out)
    };
    let spread = |values: [u32; 3]| values.map(u64::from);

    assert_eq!(u64::from(table.stack_size), word("stack_size")?, "{where_}");
    assert_eq!(
        u64::from(table.runtime_size),
        word("runtime_size")?,
        "{where_}"
    );
    assert_eq!(
        spread(table.vertex_size),
        triple("vertex_size")?,
        "{where_}"
    );
    assert_eq!(spread(table.edge_size), triple("edge_size")?, "{where_}");
    assert_eq!(spread(table.index_size), triple("index_size")?, "{where_}");
    assert_eq!(
        u64::from(table.compressed_stack_size),
        word("compressed_stack_size")?,
        "{where_}"
    );
    assert_eq!(
        u64::from(table.compressed_runtime_size),
        word("compressed_runtime_size")?,
        "{where_}"
    );
    assert_eq!(
        spread(table.compressed_vertex_size),
        triple("compressed_vertex_size")?,
        "{where_}"
    );
    assert_eq!(
        spread(table.compressed_edge_size),
        triple("compressed_edge_size")?,
        "{where_}"
    );
    assert_eq!(
        spread(table.compressed_index_size),
        triple("compressed_index_size")?,
        "{where_}"
    );
    assert_eq!(
        u64::from(table.stack_offset),
        word("stack_offset")?,
        "{where_}"
    );
    assert_eq!(
        u64::from(table.runtime_offset),
        word("runtime_offset")?,
        "{where_}"
    );
    assert_eq!(
        spread(table.vertex_offset),
        triple("vertex_offset")?,
        "{where_}"
    );
    assert_eq!(
        spread(table.edge_offset),
        triple("edge_offset")?,
        "{where_}"
    );
    assert_eq!(
        spread(table.index_offset),
        triple("index_offset")?,
        "{where_}"
    );

    // The runs in the order an extraction walks them, which is not the order the table writes them.
    let recorded = rows(record, "section_runs")?;
    let walked = table.sections();
    assert_eq!(walked.len(), recorded.len(), "{where_}: sections");
    for (n, ((_, run), row)) in walked.iter().zip(recorded).enumerate() {
        let pair = row.as_array().ok_or_else(|| format!("{where_}: run {n}"))?;
        assert_eq!(
            [u64::from(run.first), u64::from(run.count)],
            [
                pair[0].as_u64().unwrap_or_default(),
                pair[1].as_u64().unwrap_or_default()
            ],
            "{where_}: section {n}"
        );
    }
    Ok(())
}

/// The header a model extraction writes back has to describe the bytes beside it, and the crate is
/// the only thing that wrote it, so it is checked against the format's own arithmetic rather than
/// against itself: the vertex-declaration stack is exactly seventeen eight-byte elements per
/// declaration, each section starts where the one before it ended, and the last one ends at the file.
fn check_model_file(bytes: &[u8], record: &Value, where_: &str) -> R<()> {
    let word = |at: usize| -> R<u64> {
        let raw = bytes
            .get(at..at + 4)
            .and_then(|w| <[u8; 4]>::try_from(w).ok())
            .ok_or_else(|| format!("{where_}: model file is shorter than its header"))?;
        Ok(u64::from(u32::from_le_bytes(raw)))
    };
    let short = |at: usize| -> R<u64> {
        let raw = bytes
            .get(at..at + 2)
            .and_then(|w| <[u8; 2]>::try_from(w).ok())
            .ok_or_else(|| format!("{where_}: model file is shorter than its header"))?;
        Ok(u64::from(u16::from_le_bytes(raw)))
    };

    assert_eq!(word(0x00)?, field_u64(record, "model_version")?, "{where_}");
    let declarations = short(0x0C)?;
    assert_eq!(
        declarations,
        field_u64(record, "vertex_declarations")?,
        "{where_}"
    );
    assert_eq!(short(0x0E)?, field_u64(record, "materials")?, "{where_}");
    assert_eq!(
        u64::from(bytes[0x40]),
        field_u64(record, "lod_count")?,
        "{where_}"
    );

    // One vertex declaration is seventeen elements of eight bytes; the stack section is nothing but
    // those, so a stack of any other length would mean the sections were cut in the wrong places.
    let stack = word(0x04)?;
    assert_eq!(
        stack,
        declarations * 17 * 8,
        "{where_}: vertex declarations"
    );

    let runtime = word(0x08)?;
    let mut at = MODEL_FILE_HEADER_LEN as u64 + stack + runtime;
    for lod in 0..3 {
        for (offset_at, size_at) in [
            (0x10 + lod * 4, 0x28 + lod * 4),
            (0x1C + lod * 4, 0x34 + lod * 4),
        ] {
            let size = word(size_at)?;
            if size == 0 {
                assert_eq!(
                    word(offset_at)?,
                    0,
                    "{where_}: an empty section has no offset"
                );
                continue;
            }
            assert_eq!(word(offset_at)?, at, "{where_}: section at {offset_at:#x}");
            at += size;
        }
    }
    assert_eq!(
        at,
        bytes.len() as u64,
        "{where_}: the sections fill the file"
    );
    Ok(())
}

/// What the entry's own table says, checked against the recording.
fn check_body(entry: &Entry, record: &Value, where_: &str) -> R<()> {
    match entry.body() {
        EntryBody::Texture(table) => {
            assert_eq!(
                u64::from(table.raw_header_len()),
                field_u64(record, "texture_header_len")?,
                "{where_}: texture header"
            );
            assert_eq!(
                table.mips.len() as u64,
                field_u64(record, "mips")?,
                "{where_}: mips"
            );
            assert_eq!(
                entry.stored_len(),
                Some(field_u64(record, "extracted_len")?),
                "{where_}: a texture's table says what it extracts to"
            );
        }
        EntryBody::Model(table) => {
            check_model_table(table, record, where_)?;
            assert_eq!(
                u64::from(table.version),
                field_u64(record, "model_version")?,
                "{where_}: model version"
            );
            assert_eq!(
                u64::from(table.lod_count),
                field_u64(record, "lod_count")?,
                "{where_}: levels of detail"
            );
            assert_eq!(
                u64::from(table.vertex_declaration_count),
                field_u64(record, "vertex_declarations")?,
                "{where_}: vertex declarations"
            );
            assert_eq!(
                u64::from(table.material_count),
                field_u64(record, "materials")?,
                "{where_}: materials"
            );
            // A model's length is known only after decoding, so its table says nothing about it.
            assert_eq!(entry.stored_len(), None, "{where_}");
        }
        EntryBody::Standard(_) | EntryBody::Empty => {
            assert_eq!(
                entry.stored_len(),
                Some(field_u64(record, "extracted_len")?),
                "{where_}: the table says what it extracts to"
            );
        }
        other => return Err(format!("{where_}: unread content type {other:?}").into()),
    }
    Ok(())
}

/// Extract every entry of four archives, which is what says the recorded handful is not a lucky
/// sample: each entry has to decode, and the length it produces has to be the one it declares.
///
/// One archive of each shape, because the four content types share almost no code below the header:
/// `exd` is all standard entries, `ui` is mostly textures, `chara` carries the models, and
/// `bgcommon` holds every volume texture in the game, which is the one shape allowed to come out
/// shorter than it declares.
#[test]
#[ignore = "set APOGEE_SQPACK_REAL_INSTALL to a real game subtree to run"]
fn every_entry_of_an_archive_extracts_to_the_length_it_declares() -> R<()> {
    let root = std::env::var("APOGEE_SQPACK_REAL_INSTALL")?;
    let game = GameData::open(Path::new(&root))?;

    let mut seen = std::collections::BTreeMap::new();
    for category in [0x0a, 0x06, 0x04, 0x01] {
        let id = ArchiveId::new(category, 0, 0);
        let info = game
            .archive(Repo::Base, id)
            .ok_or_else(|| format!("the install has no {} archive", id.stem()))?;
        let index = game
            .index_of(info, IndexKind::Index1)?
            .ok_or_else(|| format!("{} has no index", id.stem()))?;

        let mut read = 0usize;
        for location in index.entries().iter().filter_map(|e| e.location()) {
            let dat = game.dat_of(info, location.dat)?;
            let entry = dat.entry_at(location.offset)?;
            let out = dat.read(&entry)?;
            let where_ = format!("{} dat{} @{}", id.stem(), location.dat, location.offset);
            match entry.content_type() {
                // A volume texture declares padding between mip surfaces that is not stored, so the
                // bound is what its own table says, never more than the declared size.
                ContentType::Texture => {
                    assert!(out.len() as u64 <= entry.declared_len(), "{where_}");
                    assert_eq!(Some(out.len() as u64), entry.stored_len(), "{where_}");
                }
                // An empty entry holds nothing however large a file its leftover word names; the
                // `chara` archive has one declaring nearly three megabytes.
                ContentType::Empty => assert!(out.is_empty(), "{where_}"),
                _ => assert_eq!(out.len() as u64, entry.declared_len(), "{where_}"),
            }
            *seen
                .entry(format!("{:?}", entry.content_type()))
                .or_insert(0usize) += 1;
            read += 1;
        }
        assert!(read > 1_000, "{} has entries to read: {read}", id.stem());
    }

    // Every content type this crate reads was met in bulk, not just in the recorded handful.
    for kind in ["Empty", "Standard", "Model", "Texture"] {
        assert!(
            seen.get(kind).is_some_and(|n| *n > 0),
            "no {kind} entry in the sweep: {seen:?}"
        );
    }
    Ok(())
}

/// The repository a record was captured from.
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

fn hex(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    hex(&Sha256::digest(bytes))
}

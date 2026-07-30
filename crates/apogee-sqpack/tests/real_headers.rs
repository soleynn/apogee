//! Recorded-fact pins for the SqPack common header, captured from a real FFXIV install.
//!
//! The recorded values were produced by a separate implementation of the format, out of process, so
//! what the gated test proves is agreement between two readers rather than a program agreeing with
//! itself. The hermetic test reconstructs each recorded header's identifying prefix and asserts the
//! parser reproduces the recorded fields (and that a real install was observed to carry the spec's
//! expected `0x400`/`1`/win32 values, which is what retires the `[pin]` markers). CI carries no SE
//! bytes.
//!
//! The install-gated test re-reads the real files named in the fixture from
//! `$APOGEE_SQPACK_REAL_INSTALL` and confirms the parser output and the header sha256 still match;
//! it is `#[ignore]` by default. Only the patch the fixture was recorded on is held to the digests
//! and lengths: a patch rewrites containers, so on any other version the test checks the fields the
//! format fixes, a floor under each length, and the digest every index header shares, and a patch
//! day fails on a regression rather than on a length.

use std::error::Error;
use std::path::Path;

use apogee_sqpack::{
    COMMON_HEADER_LEN, CommonHeader, GameData, Platform, Repo, SQPACK_MAGIC, SqPackKind,
    parse_common_header,
};
use serde_json::Value;

type R<T> = Result<T, Box<dyn Error>>;

/// The recorded facts for one real archive header.
struct Record {
    path: String,
    file_len: u64,
    header_size: u32,
    version: u32,
    kind: SqPackKind,
    sha256_first_1024: String,
}

fn doc() -> R<Value> {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/real_headers.json"
    );
    Ok(serde_json::from_str(&std::fs::read_to_string(path)?)?)
}

fn load_records(doc: &Value) -> R<Vec<Record>> {
    let raw = doc["records"].as_array().ok_or("records is not an array")?;
    let mut out = Vec::with_capacity(raw.len());
    for r in raw {
        // Every recorded platform is win32; a real install has never been observed otherwise.
        if r["platform"].as_str() != Some("win32") {
            return Err(format!("unexpected platform in {}", r["path"]).into());
        }
        out.push(Record {
            path: field_str(r, "path")?.to_owned(),
            file_len: field_u64(r, "file_len")?,
            header_size: u32::try_from(field_u64(r, "header_size")?)?,
            version: u32::try_from(field_u64(r, "version")?)?,
            kind: kind_from_str(field_str(r, "kind")?)?,
            sha256_first_1024: field_str(r, "sha256_first_1024")?.to_owned(),
        });
    }
    Ok(out)
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

fn kind_from_str(s: &str) -> R<SqPackKind> {
    match s {
        "sqdb" => Ok(SqPackKind::Sqdb),
        "data" => Ok(SqPackKind::Data),
        "index" => Ok(SqPackKind::Index),
        other => Err(format!("unknown kind {other}").into()),
    }
}

/// The `type` byte a `SqPackKind` is stored as, for reconstructing a header prefix.
fn kind_byte(kind: SqPackKind) -> u32 {
    match kind {
        SqPackKind::Sqdb => 0,
        SqPackKind::Data => 1,
        SqPackKind::Index => 2,
        SqPackKind::Unknown(v) => v,
        // `SqPackKind` is non_exhaustive; the fixture only ever carries the known kinds above.
        _ => u32::MAX,
    }
}

/// Rebuild a header's identifying prefix (through `0x18`) from recorded fields, padded to a full
/// common header of zeros.
fn build_prefix(header_size: u32, version: u32, kind: SqPackKind) -> Vec<u8> {
    let mut buf = vec![0u8; COMMON_HEADER_LEN];
    buf[0..8].copy_from_slice(&SQPACK_MAGIC);
    buf[8] = 0; // win32
    buf[0x0C..0x10].copy_from_slice(&header_size.to_le_bytes());
    buf[0x10..0x14].copy_from_slice(&version.to_le_bytes());
    buf[0x14..0x18].copy_from_slice(&kind_byte(kind).to_le_bytes());
    buf
}

fn assert_matches_record(header: &CommonHeader, rec: &Record) {
    assert_eq!(header.platform, Platform::Win32, "{}", rec.path);
    assert_eq!(header.header_size, rec.header_size, "{}", rec.path);
    assert_eq!(header.version, rec.version, "{}", rec.path);
    assert_eq!(header.kind, rec.kind, "{}", rec.path);
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

#[test]
fn parser_reproduces_recorded_real_header_facts() -> R<()> {
    let doc = doc()?;
    let records = load_records(&doc)?;
    assert!(!records.is_empty(), "fixture has records");
    assert!(
        !field_str(&doc, "version")?.is_empty(),
        "fixture is versioned"
    );
    for rec in &records {
        // The pin: a real install was observed to carry exactly the spec's expected values.
        assert_eq!(rec.header_size, 0x400, "{}", rec.path);
        assert_eq!(rec.version, 1, "{}", rec.path);
        assert!(
            matches!(rec.kind, SqPackKind::Index | SqPackKind::Data),
            "{} kind {:?}",
            rec.path,
            rec.kind
        );
        // The parser reproduces those fields from a faithful reconstruction of the header prefix.
        let header = parse_common_header(&build_prefix(rec.header_size, rec.version, rec.kind))?;
        assert_matches_record(&header, rec);
    }

    // Every recorded index header hashes to the same digest, which is the fixture's claim that the
    // bytes the self-hash covers carry nothing that tells one index container from another.
    let mut digests = index_digests(&records);
    digests.dedup();
    assert_eq!(
        digests.len(),
        1,
        "index headers share one digest: {digests:?}"
    );
    Ok(())
}

/// The header digest of every index container in the recording, in fixture order.
fn index_digests(records: &[Record]) -> Vec<&str> {
    records
        .iter()
        .filter(|rec| rec.kind == SqPackKind::Index)
        .map(|rec| rec.sha256_first_1024.as_str())
        .collect()
}

/// Re-read the real archives named in the fixture and confirm the parser and each header's sha256
/// still match. Gated on `APOGEE_SQPACK_REAL_INSTALL` (the game subtree holding `sqpack/` and
/// `ffxivgame.ver`); `#[ignore]` so the hermetic suite stays install-free.
///
/// The digests and lengths are the patch's, so only that patch is held to them. On any other the
/// fields the format fixes still have to hold exactly, each container still has to be within a
/// tenth of the length it was recorded at, and every index header still has to share one digest.
#[test]
#[ignore = "set APOGEE_SQPACK_REAL_INSTALL to a real game subtree to run"]
fn parser_matches_a_live_install() -> R<()> {
    let root = std::env::var("APOGEE_SQPACK_REAL_INSTALL")?;
    let root = Path::new(&root);
    let doc = doc()?;
    let records = load_records(&doc)?;
    let game = GameData::open(root)?;
    let exact = is_recorded_version(&game, &doc)?;

    let mut live_index_digests = Vec::new();
    for rec in &records {
        let path = root.join("sqpack").join(&rec.path);
        let (len, head) = read_header(&path)?;
        let header = parse_common_header(&head)?;
        assert_matches_record(&header, rec);
        let digest = sha256_hex(&head);
        if header.kind == SqPackKind::Index {
            live_index_digests.push(digest.clone());
        }
        if exact {
            assert_eq!(len, rec.file_len, "{} length", rec.path);
            assert_eq!(digest, rec.sha256_first_1024, "{} header sha256", rec.path);
        } else {
            // A patch rewrites a container; it does not shrink one to a fraction of itself.
            assert!(
                len * 10 >= rec.file_len * 9,
                "{}: {len} is far below the recorded {}",
                rec.path,
                rec.file_len
            );
        }
    }
    live_index_digests.dedup();
    assert_eq!(
        live_index_digests.len(),
        1,
        "index headers share one digest: {live_index_digests:?}"
    );

    // GameData enumerates every repository the install carries, each with a non-empty version.
    let repos: Vec<Repo> = game.repos().iter().map(|ri| ri.repo).collect();
    assert!(repos.contains(&Repo::Base), "base repo enumerated");
    for n in 1..=5 {
        assert!(repos.contains(&Repo::Ex(n)), "ex{n} enumerated");
    }
    for ri in game.repos() {
        assert!(
            ri.version.as_deref().is_some_and(|v| !v.is_empty()),
            "{:?} has a version",
            ri.repo
        );
    }
    Ok(())
}

/// Read a file's length and its first common-header block, without loading a multi-gigabyte dat.
fn read_header(path: &Path) -> R<(u64, Vec<u8>)> {
    use std::io::Read;
    let mut file = std::fs::File::open(path)?;
    let len = file.metadata()?.len();
    let mut head = vec![0u8; COMMON_HEADER_LEN];
    file.read_exact(&mut head)?;
    Ok((len, head))
}

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    use std::fmt::Write as _;
    Sha256::digest(bytes)
        .iter()
        .fold(String::new(), |mut s, b| {
            let _ = write!(s, "{b:02x}");
            s
        })
}

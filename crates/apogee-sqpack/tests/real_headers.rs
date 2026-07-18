//! Recorded-fact pins for the SqPack common header, captured from a real FFXIV install.
//!
//! The hermetic test reconstructs each recorded header's identifying prefix and asserts the parser
//! reproduces the recorded fields (and that a real install was observed to carry the spec's expected
//! `0x400`/`1`/win32 values, which is what retires the `[pin]` markers). CI carries no SE bytes. The
//! install-gated test re-reads the real files named in the fixture from `$APOGEE_SQPACK_REAL_INSTALL`
//! and confirms the parser output and the header sha256 still match; it is `#[ignore]` by default.

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

fn load_records() -> R<Vec<Record>> {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/real_headers.json"
    );
    let doc: Value = serde_json::from_str(&std::fs::read_to_string(path)?)?;
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

#[test]
fn parser_reproduces_recorded_real_header_facts() -> R<()> {
    let records = load_records()?;
    assert!(!records.is_empty(), "fixture has records");
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
    Ok(())
}

/// Re-read the real archives named in the fixture and confirm the parser and each header's sha256
/// still match. Gated on `APOGEE_SQPACK_REAL_INSTALL` (the game subtree holding `sqpack/` and
/// `ffxivgame.ver`); `#[ignore]` so the hermetic suite stays install-free.
#[test]
#[ignore = "set APOGEE_SQPACK_REAL_INSTALL to a real game subtree to run"]
fn parser_matches_a_live_install() -> R<()> {
    let root = std::env::var("APOGEE_SQPACK_REAL_INSTALL")?;
    let root = Path::new(&root);
    let records = load_records()?;

    for rec in &records {
        let path = root.join("sqpack").join(&rec.path);
        let (len, head) = read_header(&path)?;
        assert_eq!(len, rec.file_len, "{} length", rec.path);
        assert_eq!(
            sha256_hex(&head),
            rec.sha256_first_1024,
            "{} header sha256",
            rec.path
        );
        assert_matches_record(&parse_common_header(&head)?, rec);
    }

    // GameData enumerates every repository the install carries, each with a non-empty version.
    let game = GameData::open(root)?;
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

//! Archive writing: reproducibility, the self-describing record, and what a reader gets back.

mod common;

use std::io::Read;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use apogee_addons::backup::{
    BACKUP_FORMAT, BACKUP_FORMAT_VERSION, BackupError, BackupSpec, GameConfigOpts, MANIFEST_ENTRY,
    Selection, SelectionRoot, create, inspect,
};

#[cfg(unix)]
use common::CHARACTER_FILES;
use common::{CHARACTER_DIR, game_tree, game_tree_reversed, hex, write};
use tokio_util::sync::CancellationToken;

/// A fixed instant, so an archive is a function of its contents alone.
const AT: u64 = 1_785_000_000;

fn spec(source: &Path, dest: &Path, at: u64) -> Result<BackupSpec, BackupError> {
    Ok(BackupSpec {
        selection: Selection::new().with_root(SelectionRoot::game_config(
            source,
            GameConfigOpts::default(),
        ))?,
        dest_dir: dest.to_path_buf(),
        created_at: UNIX_EPOCH + Duration::from_secs(at),
        note: None,
    })
}

/// Anything a test here can fail with.
type Fallible = Box<dyn std::error::Error>;

/// One entry as stored: name, unix mode, uncompressed size, content.
type Stored = (String, u32, u64, Vec<u8>);

/// Every entry in archive order.
fn listing(archive: &Path) -> Result<Vec<Stored>, Fallible> {
    let mut zip = zip::ZipArchive::new(std::fs::File::open(archive)?)?;
    let mut out = Vec::new();
    for i in 0..zip.len() {
        let mut entry = zip.by_index(i)?;
        let name = entry.name().to_owned();
        let mode = entry.unix_mode().unwrap_or(0);
        let size = entry.size();
        let mut body = Vec::new();
        entry.read_to_end(&mut body)?;
        out.push((name, mode, size, body));
    }
    Ok(out)
}

/// The product requirement. The same tree rebuilt in the opposite order, with its timestamp skewed
/// (and, on Unix, every file's mode skewed), must produce the same bytes: creation order and source
/// metadata are incidental and none may reach the archive. The source path is held fixed because it
/// is provenance the archive records on purpose, not an incidental difference.
#[test]
fn rebuilding_a_tree_differently_does_not_change_the_archive() -> Result<(), BackupError> {
    let source = tempfile::tempdir().unwrap();
    let out = tempfile::tempdir().unwrap();

    game_tree(source.path()).unwrap();
    let a = create(
        &spec(source.path(), out.path(), AT)?,
        &CancellationToken::new(),
    )?;
    let bytes_a = std::fs::read(&a.archive).unwrap();

    // Same content at the same path, written in the opposite order so the filesystem enumerates it
    // differently, then skewed in every way the archive could otherwise inherit.
    for entry in std::fs::read_dir(source.path()).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            std::fs::remove_dir_all(&path).unwrap();
        } else {
            std::fs::remove_file(&path).unwrap();
        }
    }
    game_tree_reversed(source.path()).unwrap();
    #[cfg(unix)]
    for name in CHARACTER_FILES {
        let path = source.path().join(CHARACTER_DIR).join(name);
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o777)).unwrap();
    }
    let long_ago = SystemTime::now() - Duration::from_secs(60 * 60 * 24 * 365);
    std::fs::File::options()
        .write(true)
        .open(source.path().join("FFXIV.cfg"))
        .unwrap()
        .set_modified(long_ago)
        .unwrap();

    let b = create(
        &spec(source.path(), out.path(), AT)?,
        &CancellationToken::new(),
    )?;
    let bytes_b = std::fs::read(&b.archive).unwrap();

    assert_ne!(a.archive, b.archive, "two archives, not one overwritten");
    assert_eq!(
        bytes_a, bytes_b,
        "creation order, mode, and mtime must not reach the archive"
    );
    assert_eq!(a.archive_bytes, b.archive_bytes);
    Ok(())
}

/// The creation instant is a real fact about the backup, so it is the one input that does change the
/// bytes. This pins that the reproducibility above is not just two identical no-ops.
#[test]
fn a_different_instant_gives_a_different_archive() -> Result<(), BackupError> {
    let source = tempfile::tempdir().unwrap();
    game_tree(source.path()).unwrap();
    let out = tempfile::tempdir().unwrap();

    let a = create(
        &spec(source.path(), out.path(), AT)?,
        &CancellationToken::new(),
    )?;
    let b = create(
        &spec(source.path(), out.path(), AT + 1)?,
        &CancellationToken::new(),
    )?;
    assert_ne!(
        std::fs::read(&a.archive).unwrap(),
        std::fs::read(&b.archive).unwrap()
    );
    Ok(())
}

/// No entry may carry metadata copied from its source. The real tree mixes 0664 and 0777 depending
/// on how the game last wrote the file, which is exactly the kind of incidental difference that
/// would otherwise leak into the archive.
#[test]
fn entries_carry_fixed_metadata_not_the_sources() -> Result<(), BackupError> {
    let source = tempfile::tempdir().unwrap();
    game_tree(source.path()).unwrap();
    #[cfg(unix)]
    std::fs::set_permissions(
        source.path().join("FFXIV.cfg"),
        std::fs::Permissions::from_mode(0o777),
    )
    .unwrap();
    let out = tempfile::tempdir().unwrap();

    let report = create(
        &spec(source.path(), out.path(), AT)?,
        &CancellationToken::new(),
    )?;
    let file = std::fs::File::open(&report.archive).unwrap();
    let mut zip = zip::ZipArchive::new(file).unwrap();
    for i in 0..zip.len() {
        let entry = zip.by_index(i).unwrap();
        let want = if entry.is_dir() { 0o755 } else { 0o644 };
        // Masked to the permission bits: the stored mode also carries the file-type bits.
        assert_eq!(
            entry.unix_mode().map(|m| m & 0o777),
            Some(want),
            "{} carries a source mode",
            entry.name()
        );
        assert_eq!(
            entry.last_modified(),
            Some(zip::DateTime::default()),
            "{} carries a source timestamp",
            entry.name()
        );
    }
    Ok(())
}

/// A directory is stored as a directory and lands ahead of everything inside it, so a reader that
/// creates entries in order never meets a file before its parent.
#[test]
fn a_directory_entry_precedes_its_contents() -> Result<(), Fallible> {
    let source = tempfile::tempdir().unwrap();
    game_tree(source.path()).unwrap();
    let out = tempfile::tempdir().unwrap();

    let report = create(
        &spec(source.path(), out.path(), AT)?,
        &CancellationToken::new(),
    )?;
    let names: Vec<String> = listing(&report.archive)?
        .into_iter()
        .map(|(n, ..)| n)
        .collect();

    let dir = format!("user/{CHARACTER_DIR}/");
    let dir_at = names
        .iter()
        .position(|n| *n == dir)
        .expect("directory entry");
    let first_child = names
        .iter()
        .position(|n| n.starts_with(&dir) && n.len() > dir.len())
        .expect("a child");
    assert!(dir_at < first_child);
    Ok(())
}

/// Every file comes back with the bytes that went in, and the record's hash describes them.
#[test]
fn contents_round_trip_and_match_their_recorded_hash() -> Result<(), Fallible> {
    let source = tempfile::tempdir().unwrap();
    game_tree(source.path()).unwrap();
    let out = tempfile::tempdir().unwrap();

    let report = create(
        &spec(source.path(), out.path(), AT)?,
        &CancellationToken::new(),
    )?;
    let manifest = inspect(&report.archive)?;
    let stored = listing(&report.archive)?;

    for (name, _, _, body) in &stored {
        if name == MANIFEST_ENTRY {
            continue;
        }
        let record = manifest
            .entries
            .iter()
            .find(|e| e.name == *name)
            .unwrap_or_else(|| panic!("{name} is in the archive but not the record"));
        assert_eq!(record.size, body.len() as u64, "{name} size");
        if !body.is_empty() {
            let digest = <sha2::Sha256 as sha2::Digest>::digest(body);
            let hex = hex(&digest);
            assert_eq!(record.sha256, hex, "{name} hash");
        }
    }
    // The record covers the payload exactly: nothing described that is not stored.
    assert_eq!(manifest.entries.len(), stored.len() - 1);

    let hotbar = stored
        .iter()
        .find(|(n, ..)| n.ends_with("HOTBAR.DAT"))
        .expect("a character file");
    assert_eq!(hotbar.3, b"HOTBAR.DAT");
    Ok(())
}

/// The record is what makes an archive self-describing, and it carries the rule counts forward so a
/// rule that matched nothing stays visible after the fact.
#[test]
fn the_record_describes_the_selection_that_produced_it() -> Result<(), BackupError> {
    let source = tempfile::tempdir().unwrap();
    game_tree(source.path()).unwrap();
    std::fs::remove_dir_all(source.path().join(CHARACTER_DIR).join("log")).unwrap();
    let out = tempfile::tempdir().unwrap();

    let mut s = spec(source.path(), out.path(), AT)?;
    s.note = Some("before a patch".into());
    let report = create(&s, &CancellationToken::new())?;
    let manifest = inspect(&report.archive)?;

    assert_eq!(manifest.format, BACKUP_FORMAT);
    assert_eq!(manifest.format_version, BACKUP_FORMAT_VERSION);
    assert_eq!(manifest.created_at, AT);
    assert_eq!(manifest.note.as_deref(), Some("before a patch"));
    assert!(manifest.producer.starts_with("apogee-addons/"));

    let root = &manifest.roots[0];
    assert_eq!(root.files, 16);
    let logs = root
        .rules
        .iter()
        .find(|r| r.rule == "dir log")
        .expect("the prune rule is recorded even though it matched nothing");
    assert_eq!(logs.matched, 0);
    assert!(root.rules.iter().any(|r| r.matched > 0));
    Ok(())
}

/// Two backups at the same instant must not land on one another.
#[test]
fn a_second_backup_in_the_same_second_gets_its_own_name() -> Result<(), BackupError> {
    let source = tempfile::tempdir().unwrap();
    game_tree(source.path()).unwrap();
    let out = tempfile::tempdir().unwrap();

    let a = create(
        &spec(source.path(), out.path(), AT)?,
        &CancellationToken::new(),
    )?;
    let b = create(
        &spec(source.path(), out.path(), AT)?,
        &CancellationToken::new(),
    )?;
    assert_ne!(a.archive, b.archive);
    assert!(a.archive.exists() && b.archive.exists());
    // The name states the instant, so a directory listing sorts chronologically. A known, fixed,
    // lowercase extension this crate generates, not an arbitrary file from a real filesystem:
    // `Path::extension()`'s case-insensitivity buys nothing worth the indirection here.
    #[allow(clippy::case_sensitive_file_extension_comparisons)]
    let named_right = a
        .archive
        .file_name()
        .and_then(|n| n.to_str())
        .is_some_and(|n| n.starts_with("apogee-config-20260725T") && n.ends_with(".apbk"));
    assert!(named_right, "unexpected name {:?}", a.archive);
    Ok(())
}

/// Reading is by name out of the central directory, and anything that is not ours is refused rather
/// than guessed at.
#[test]
fn inspect_refuses_what_is_not_one_of_our_archives() {
    let dir = tempfile::tempdir().unwrap();

    let not_zip = dir.path().join("random.apbk");
    write(&not_zip, "just some bytes").unwrap();
    assert!(matches!(
        inspect(&not_zip),
        Err(BackupError::NotAnArchive { .. })
    ));

    // A perfectly valid zip that simply is not ours.
    let foreign = dir.path().join("foreign.apbk");
    let mut w = zip::ZipWriter::new(std::fs::File::create(&foreign).unwrap());
    w.start_file("hello.txt", zip::write::SimpleFileOptions::default())
        .unwrap();
    std::io::Write::write_all(&mut w, b"hi").unwrap();
    w.finish().unwrap();
    assert!(matches!(
        inspect(&foreign),
        Err(BackupError::NotAnArchive { .. })
    ));

    assert!(matches!(
        inspect(&dir.path().join("absent.apbk")),
        Err(BackupError::Io { .. })
    ));
}

/// An archive from a newer build is reported as such rather than misread. Retention leans on this:
/// deleting an archive it cannot understand is the one unrecoverable mistake available to it.
#[test]
fn inspect_refuses_a_newer_format_version() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("future.apbk");
    let body = serde_json::json!({
        "format": BACKUP_FORMAT,
        "format_version": BACKUP_FORMAT_VERSION + 1,
        "producer": "apogee-addons/9.9.9",
        "created_at": AT,
        "roots": [],
        "entries": [],
    });
    let mut w = zip::ZipWriter::new(std::fs::File::create(&path).unwrap());
    w.start_file(MANIFEST_ENTRY, zip::write::SimpleFileOptions::default())
        .unwrap();
    std::io::Write::write_all(&mut w, body.to_string().as_bytes()).unwrap();
    w.finish().unwrap();

    match inspect(&path) {
        Err(BackupError::UnsupportedFormat {
            found, supported, ..
        }) => {
            assert_eq!(found, BACKUP_FORMAT_VERSION + 1);
            assert_eq!(supported, BACKUP_FORMAT_VERSION);
        }
        other => panic!("expected a version refusal, got {other:?}"),
    }
}

/// A selection that yields nothing never reaches the writer, so no file is left behind.
#[test]
fn a_backup_that_selects_nothing_writes_no_file() -> Result<(), BackupError> {
    let source = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(source.path().join("screenshots")).unwrap();
    let out = tempfile::tempdir().unwrap();

    let err = create(
        &spec(source.path(), out.path(), AT)?,
        &CancellationToken::new(),
    );
    assert!(matches!(err, Err(BackupError::NothingSelected)));
    assert_eq!(std::fs::read_dir(out.path()).unwrap().count(), 0);
    Ok(())
}

/// A capture is a blocking copy of a tree of unbounded size, so it has to be stoppable, and stopping it
/// must leave nothing half-written where a reader looks for archives. The archive is assembled in a
/// temporary file and only named once it is complete, which is what makes the refusal clean.
#[test]
fn a_cancelled_capture_writes_no_archive() -> Result<(), Fallible> {
    let source = tempfile::tempdir()?;
    let out = tempfile::tempdir()?;
    game_tree(source.path())?;
    let cancel = CancellationToken::new();
    cancel.cancel();

    let refused = create(&spec(source.path(), out.path(), AT)?, &cancel);

    assert!(
        matches!(refused, Err(BackupError::Cancelled)),
        "a stopped capture is not a failed one: {refused:?}"
    );
    let left: Vec<_> = std::fs::read_dir(out.path())?.collect::<Result<_, _>>()?;
    assert!(
        left.is_empty(),
        "a stopped capture left something behind: {:?}",
        left.iter().map(std::fs::DirEntry::path).collect::<Vec<_>>()
    );
    Ok(())
}

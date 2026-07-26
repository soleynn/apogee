//! Restore: the round trip, and what a hostile archive is not allowed to do.

mod common;

use std::collections::BTreeMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{Duration, UNIX_EPOCH};

use apogee_addons::backup::{
    BACKUP_FORMAT, BACKUP_FORMAT_VERSION, BackupError, BackupSpec, GameConfigOpts, MANIFEST_ENTRY,
    RejectReason, RestorePlan, RootLabel, Selection, SelectionRoot, create, restore,
};

use common::{CHARACTER_DIR, game_tree, write};

type Fallible = Box<dyn std::error::Error>;

const AT: u64 = 1_785_000_000;

/// Back up `source` and return the archive path.
fn back_up(source: &Path, dest: &Path) -> Result<PathBuf, Fallible> {
    let spec = BackupSpec {
        selection: Selection::new().with_root(SelectionRoot::game_config(
            source,
            GameConfigOpts::default(),
        ))?,
        dest_dir: dest.to_path_buf(),
        created_at: UNIX_EPOCH + Duration::from_secs(AT),
        note: None,
    };
    Ok(create(&spec)?.archive)
}

fn plan(archive: &Path, target: &Path) -> RestorePlan {
    let mut targets = BTreeMap::new();
    targets.insert(RootLabel::User, target.to_path_buf());
    RestorePlan {
        archive: archive.to_path_buf(),
        targets,
    }
}

/// Every file under `root`, relative path to contents, so two trees can be compared whole.
fn snapshot(root: &Path) -> Result<BTreeMap<String, Vec<u8>>, Fallible> {
    fn walk(dir: &Path, base: &Path, out: &mut BTreeMap<String, Vec<u8>>) -> Result<(), Fallible> {
        for entry in std::fs::read_dir(dir)? {
            let path = entry?.path();
            let rel = path.strip_prefix(base)?.to_string_lossy().into_owned();
            if path.is_dir() {
                out.insert(format!("{rel}/"), Vec::new());
                walk(&path, base, out)?;
            } else {
                out.insert(rel, std::fs::read(&path)?);
            }
        }
        Ok(())
    }
    let mut out = BTreeMap::new();
    walk(root, root, &mut out)?;
    Ok(out)
}

/// Build an archive by hand, so a restore can be handed shapes the writer would never produce.
/// `entries` is (name, body, is_dir); every one is also listed in the record so a rejection can only
/// come from the name checks rather than from the entry being unlisted.
fn hostile_archive(
    path: &Path,
    entries: &[(&str, &[u8], bool)],
    symlinks: &[(&str, &str)],
) -> Result<(), Fallible> {
    let opts = zip::write::SimpleFileOptions::default();
    let mut w = zip::ZipWriter::new(std::fs::File::create(path)?);
    let mut records = Vec::new();
    for (name, body, is_dir) in entries {
        if *is_dir {
            w.add_directory(*name, opts)?;
            records.push(serde_json::json!({
                "name": name, "kind": "dir", "size": 0,
            }));
        } else {
            w.start_file(*name, opts)?;
            w.write_all(body)?;
            let digest = <sha2::Sha256 as sha2::Digest>::digest(body);
            let hex: String = digest.iter().map(|b| format!("{b:02x}")).collect();
            records.push(serde_json::json!({
                "name": name, "kind": "file", "size": body.len(), "sha256": hex,
            }));
        }
    }
    for (name, target) in symlinks {
        w.add_symlink(*name, *target, opts)?;
        records.push(serde_json::json!({ "name": name, "kind": "file", "size": 0 }));
    }
    let manifest = serde_json::json!({
        "format": BACKUP_FORMAT,
        "format_version": BACKUP_FORMAT_VERSION,
        "producer": "hand-built/0",
        "created_at": AT,
        "roots": [],
        "entries": records,
    });
    w.start_file(MANIFEST_ENTRY, opts)?;
    w.write_all(manifest.to_string().as_bytes())?;
    w.finish()?;
    Ok(())
}

/// The round trip: what comes back is what went in, byte for byte.
#[test]
fn a_restored_tree_matches_what_was_backed_up() -> Result<(), Fallible> {
    let source = tempfile::tempdir()?;
    let dest = tempfile::tempdir()?;
    game_tree(source.path())?;
    let archive = back_up(source.path(), dest.path())?;

    let live = tempfile::tempdir()?;
    let target = live.path().join("config");
    let report = restore(&plan(&archive, &target))?;

    assert_eq!(report.restored.len(), 1);
    assert_eq!(report.restored[0].label, RootLabel::User);
    assert_eq!(report.restored[0].displaced_to, None, "nothing was there");
    assert_eq!(report.restored[0].files, 16);

    let restored = snapshot(&target)?;
    assert_eq!(
        restored.get("FFXIV.cfg").map(Vec::as_slice),
        Some(&b"cfg"[..])
    );
    assert_eq!(
        restored
            .get(&format!("{CHARACTER_DIR}/HOTBAR.DAT"))
            .map(Vec::as_slice),
        Some(&b"HOTBAR.DAT"[..])
    );
    // What the selection dropped stays dropped on the way back.
    assert!(!restored.keys().any(|k| k.contains("log")));
    assert!(!restored.keys().any(|k| k.ends_with(".old")));
    Ok(())
}

/// Restoring over a live tree replaces it, and the tree that was there is set aside rather than
/// deleted, so the restore can be undone with one rename.
#[test]
fn the_previous_tree_is_set_aside_not_deleted() -> Result<(), Fallible> {
    let source = tempfile::tempdir()?;
    let dest = tempfile::tempdir()?;
    game_tree(source.path())?;
    let archive = back_up(source.path(), dest.path())?;

    let live = tempfile::tempdir()?;
    let target = live.path().join("config");
    write(&target.join("FFXIV.cfg"), "a different config")?;
    write(&target.join("something-else.txt"), "only in the live tree")?;

    let report = restore(&plan(&archive, &target))?;
    let displaced = report.restored[0]
        .displaced_to
        .clone()
        .expect("the previous tree is reported");

    // The restored tree replaced rather than merged: the stale file is gone from the live path.
    assert!(!target.join("something-else.txt").exists());
    assert_eq!(std::fs::read(target.join("FFXIV.cfg"))?, b"cfg");
    // And it is recoverable in full.
    assert_eq!(
        std::fs::read(displaced.join("something-else.txt"))?,
        b"only in the live tree"
    );
    assert_eq!(
        std::fs::read(displaced.join("FFXIV.cfg"))?,
        b"a different config"
    );
    Ok(())
}

/// A root the plan does not name is left where it is.
#[test]
fn a_root_the_plan_does_not_name_is_untouched() -> Result<(), Fallible> {
    let source = tempfile::tempdir()?;
    let dest = tempfile::tempdir()?;
    game_tree(source.path())?;
    let archive = back_up(source.path(), dest.path())?;

    let live = tempfile::tempdir()?;
    let empty = RestorePlan {
        archive: archive.clone(),
        targets: BTreeMap::new(),
    };
    let report = restore(&empty)?;
    assert!(report.restored.is_empty());
    assert_eq!(report.skipped, vec![RootLabel::User]);
    assert_eq!(std::fs::read_dir(live.path())?.count(), 0);
    Ok(())
}

/// The escape attempts, each of which must abort the whole restore rather than skip the entry.
#[test]
fn an_entry_that_would_escape_aborts_the_restore() -> Result<(), Fallible> {
    let dir = tempfile::tempdir()?;
    let live = tempfile::tempdir()?;
    let target = live.path().join("config");
    let outside = live.path().join("outside.txt");
    std::fs::write(&outside, b"untouched")?;

    let cases: &[(&str, RejectReason)] = &[
        ("user/../../outside.txt", RejectReason::Traversal),
        (r"user\..\..\outside.txt", RejectReason::Traversal),
        ("/etc/passwd", RejectReason::Absolute),
        (r"C:\windows\evil.dll", RejectReason::DriveLetter),
        ("elsewhere/thing.txt", RejectReason::UnknownRoot),
        ("user/CON", RejectReason::WindowsHostile),
        ("user/trailing.", RejectReason::WindowsHostile),
    ];

    for (name, want) in cases {
        let archive = dir.path().join("hostile.apbk");
        hostile_archive(&archive, &[(name, b"pwned", false)], &[])?;
        match restore(&plan(&archive, &target)) {
            Err(BackupError::RejectedEntry { reason, .. }) => assert_eq!(&reason, want, "{name}"),
            other => panic!("{name} should have been refused, got {other:?}"),
        }
        assert!(!target.exists(), "{name} created the target");
        assert_eq!(
            std::fs::read(&outside)?,
            b"untouched",
            "{name} wrote outside"
        );
        std::fs::remove_file(&archive)?;
    }
    Ok(())
}

/// A symlink entry is refused outright. A real config tree contains none, so allowing them would buy
/// nothing and admit aliasing into a directory the game writes to afterwards.
#[test]
fn a_symlink_entry_is_refused() -> Result<(), Fallible> {
    let dir = tempfile::tempdir()?;
    let live = tempfile::tempdir()?;
    let archive = dir.path().join("linky.apbk");
    hostile_archive(
        &archive,
        &[("user/FFXIV.cfg", b"fine", false)],
        &[("user/escape", "/etc")],
    )?;

    match restore(&plan(&archive, &live.path().join("config"))) {
        Err(BackupError::RejectedEntry { reason, .. }) => {
            assert_eq!(reason, RejectReason::NotAFileOrDir);
        }
        other => panic!("expected a refusal, got {other:?}"),
    }
    Ok(())
}

/// Two entries differing only in case land on one file where the destination folds case, so the pair
/// is refused rather than silently collapsed.
#[test]
fn two_entries_that_differ_only_in_case_are_refused() -> Result<(), Fallible> {
    let dir = tempfile::tempdir()?;
    let live = tempfile::tempdir()?;
    let archive = dir.path().join("collide.apbk");
    hostile_archive(
        &archive,
        &[
            ("user/FFXIV.cfg", b"one", false),
            ("user/ffxiv.CFG", b"two", false),
        ],
        &[],
    )?;

    match restore(&plan(&archive, &live.path().join("config"))) {
        Err(BackupError::RejectedEntry { reason, .. }) => {
            assert_eq!(reason, RejectReason::Collision);
        }
        other => panic!("expected a refusal, got {other:?}"),
    }
    Ok(())
}

/// Content is checked against the archive's own record as it is written, so a file altered after the
/// backup was taken cannot be restored as if it were genuine.
#[test]
fn a_tampered_entry_is_caught_by_its_recorded_hash() -> Result<(), Fallible> {
    let dir = tempfile::tempdir()?;
    let live = tempfile::tempdir()?;
    let archive = dir.path().join("tampered.apbk");

    // Build normally, then rewrite one entry's bytes while leaving the record alone.
    let opts = zip::write::SimpleFileOptions::default();
    let mut w = zip::ZipWriter::new(std::fs::File::create(&archive)?);
    w.start_file("user/FFXIV.cfg", opts)?;
    w.write_all(b"tampered")?;
    let honest = <sha2::Sha256 as sha2::Digest>::digest(b"original");
    let hex: String = honest.iter().map(|b| format!("{b:02x}")).collect();
    let manifest = serde_json::json!({
        "format": BACKUP_FORMAT,
        "format_version": BACKUP_FORMAT_VERSION,
        "producer": "hand-built/0",
        "created_at": AT,
        "roots": [],
        "entries": [{ "name": "user/FFXIV.cfg", "kind": "file", "size": 8, "sha256": hex }],
    });
    w.start_file(MANIFEST_ENTRY, opts)?;
    w.write_all(manifest.to_string().as_bytes())?;
    w.finish()?;

    let target = live.path().join("config");
    match restore(&plan(&archive, &target)) {
        Err(BackupError::ContentMismatch { entry }) => assert_eq!(entry, "user/FFXIV.cfg"),
        other => panic!("expected a hash mismatch, got {other:?}"),
    }
    assert!(!target.exists());
    Ok(())
}

/// An entry present in the container but absent from the record is refused, so an archive cannot be
/// grown after the fact by appending to it.
#[test]
fn an_entry_missing_from_the_record_is_refused() -> Result<(), Fallible> {
    let dir = tempfile::tempdir()?;
    let live = tempfile::tempdir()?;
    let archive = dir.path().join("extra.apbk");

    let opts = zip::write::SimpleFileOptions::default();
    let mut w = zip::ZipWriter::new(std::fs::File::create(&archive)?);
    w.start_file("user/smuggled.dat", opts)?;
    w.write_all(b"extra")?;
    let manifest = serde_json::json!({
        "format": BACKUP_FORMAT,
        "format_version": BACKUP_FORMAT_VERSION,
        "producer": "hand-built/0",
        "created_at": AT,
        "roots": [],
        "entries": [],
    });
    w.start_file(MANIFEST_ENTRY, opts)?;
    w.write_all(manifest.to_string().as_bytes())?;
    w.finish()?;

    match restore(&plan(&archive, &live.path().join("config"))) {
        Err(BackupError::RejectedEntry { reason, .. }) => {
            assert_eq!(reason, RejectReason::NotInRecord);
        }
        other => panic!("expected a refusal, got {other:?}"),
    }
    Ok(())
}

/// A refused restore leaves nothing behind, so a second attempt starts clean.
#[test]
fn a_refused_restore_leaves_no_staging_directory() -> Result<(), Fallible> {
    let dir = tempfile::tempdir()?;
    let live = tempfile::tempdir()?;
    let archive = dir.path().join("bad.apbk");
    hostile_archive(
        &archive,
        &[
            ("user/FFXIV.cfg", b"fine", false),
            ("user/../../escape", b"no", false),
        ],
        &[],
    )?;

    assert!(restore(&plan(&archive, &live.path().join("config"))).is_err());
    let leftovers: Vec<_> = std::fs::read_dir(live.path())?
        .filter_map(Result::ok)
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    assert!(leftovers.is_empty(), "left behind {leftovers:?}");
    Ok(())
}

/// A restore can be run twice; the second sets the first aside under its own name.
#[test]
fn restoring_twice_keeps_both_previous_trees() -> Result<(), Fallible> {
    let source = tempfile::tempdir()?;
    let dest = tempfile::tempdir()?;
    game_tree(source.path())?;
    let archive = back_up(source.path(), dest.path())?;

    let live = tempfile::tempdir()?;
    let target = live.path().join("config");
    write(&target.join("original.txt"), "first")?;

    let one = restore(&plan(&archive, &target))?;
    let two = restore(&plan(&archive, &target))?;

    let a = one.restored[0].displaced_to.clone().expect("first");
    let b = two.restored[0].displaced_to.clone().expect("second");
    assert_ne!(a, b, "the second must not land on the first");
    assert!(a.exists() && b.exists());
    assert_eq!(std::fs::read(a.join("original.txt"))?, b"first");
    Ok(())
}

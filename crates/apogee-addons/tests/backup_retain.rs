//! Retention: what gets deleted, and everything that must not be.

mod common;

use std::io::Write;
use std::num::NonZeroUsize;
use std::path::{Path, PathBuf};
use std::time::{Duration, UNIX_EPOCH};

use apogee_addons::backup::{
    BACKUP_FORMAT, BACKUP_FORMAT_VERSION, BackupSpec, ForeignReason, GameConfigOpts,
    MANIFEST_ENTRY, Retain, Selection, SelectionRoot, create, plan_prune, prune,
};

use common::{game_tree, write};
use tokio_util::sync::CancellationToken;

type Fallible = Box<dyn std::error::Error>;

fn keep(n: usize) -> Retain {
    Retain::keep(NonZeroUsize::new(n).unwrap_or(NonZeroUsize::MIN))
}

/// Write a real archive stamped at `at`.
fn archive_at(source: &Path, dest: &Path, at: u64) -> Result<PathBuf, Fallible> {
    let spec = BackupSpec {
        selection: Selection::new().with_root(SelectionRoot::game_config(
            source,
            GameConfigOpts::default(),
        ))?,
        dest_dir: dest.to_path_buf(),
        created_at: UNIX_EPOCH + Duration::from_secs(at),
        note: None,
    };
    Ok(create(&spec, &CancellationToken::new())?.archive)
}

/// A zip carrying an arbitrary record, for the cases a real backup cannot produce.
fn archive_with_record(path: &Path, record: Option<&str>) -> Result<(), Fallible> {
    let opts = zip::write::SimpleFileOptions::default();
    let mut w = zip::ZipWriter::new(std::fs::File::create(path)?);
    w.start_file("user/FFXIV.cfg", opts)?;
    w.write_all(b"cfg")?;
    if let Some(body) = record {
        w.start_file(MANIFEST_ENTRY, opts)?;
        w.write_all(body.as_bytes())?;
    }
    w.finish()?;
    Ok(())
}

fn names(paths: &[PathBuf]) -> Vec<String> {
    paths
        .iter()
        .filter_map(|p| p.file_name().map(|n| n.to_string_lossy().into_owned()))
        .collect()
}

/// The newest survive and the rest go, ordered by what the record says rather than by the name.
#[test]
fn the_newest_are_kept_and_the_oldest_are_removed() -> Result<(), Fallible> {
    let source = tempfile::tempdir()?;
    let dest = tempfile::tempdir()?;
    game_tree(source.path())?;

    let mut made = Vec::new();
    for offset in [0, 100, 200, 300, 400] {
        made.push(archive_at(
            source.path(),
            dest.path(),
            1_785_000_000 + offset,
        )?);
    }

    let plan = plan_prune(dest.path(), keep(2))?;
    assert_eq!(plan.ours.len(), 5);
    assert_eq!(plan.keep.len(), 2);
    assert_eq!(plan.delete.len(), 3);
    assert!(plan.foreign.is_empty());
    // Newest first, so the two kept are the last two written.
    assert_eq!(plan.ours[0].created_at, 1_785_000_400);
    assert_eq!(plan.keep, vec![made[4].clone(), made[3].clone()]);

    let report = prune(dest.path(), keep(2))?;
    assert_eq!(report.deleted, plan.delete);
    assert_eq!(report.kept, 2);
    for path in &report.deleted {
        assert!(!path.exists());
    }
    for path in &plan.keep {
        assert!(path.exists());
    }
    Ok(())
}

/// Ordering comes from the record, so an archive whose filename says otherwise is still placed
/// correctly. A name is a rendering; the data is the fact.
#[test]
fn ordering_follows_the_record_not_the_filename() -> Result<(), Fallible> {
    let source = tempfile::tempdir()?;
    let dest = tempfile::tempdir()?;
    game_tree(source.path())?;

    let old = archive_at(source.path(), dest.path(), 1_700_000_000)?;
    let new = archive_at(source.path(), dest.path(), 1_785_000_000)?;
    // Swap the names so anything sorting on them picks the wrong survivor.
    let a = dest.path().join("zzz-actually-old.apbk");
    let b = dest.path().join("aaa-actually-new.apbk");
    std::fs::rename(&old, &a)?;
    std::fs::rename(&new, &b)?;

    let plan = plan_prune(dest.path(), keep(1))?;
    assert_eq!(plan.keep, vec![b], "the newer record must survive");
    assert_eq!(plan.delete, vec![a]);
    Ok(())
}

/// Nothing that fails to prove it is ours is ever deleted, and each rejection says which check
/// stopped it.
#[test]
fn only_our_archives_are_candidates() -> Result<(), Fallible> {
    let source = tempfile::tempdir()?;
    let dest = tempfile::tempdir()?;
    game_tree(source.path())?;
    let ours = archive_at(source.path(), dest.path(), 1_785_000_000)?;

    // Right extension, wrong everything else.
    write(&dest.path().join("truncated.apbk"), "")?;
    write(&dest.path().join("garbage.apbk"), "not a zip at all")?;
    archive_with_record(&dest.path().join("norecord.apbk"), None)?;
    archive_with_record(&dest.path().join("unparsable.apbk"), Some("{not json"))?;
    archive_with_record(
        &dest.path().join("othertool.apbk"),
        Some(
            &serde_json::json!({
                "format": "some-other-tool", "format_version": 1, "producer": "x/0",
                "created_at": 1, "roots": [], "entries": [],
            })
            .to_string(),
        ),
    )?;
    archive_with_record(
        &dest.path().join("newer.apbk"),
        Some(
            &serde_json::json!({
                "format": BACKUP_FORMAT, "format_version": BACKUP_FORMAT_VERSION + 1,
                "producer": "apogee-addons/9.9.9", "created_at": 1, "roots": [], "entries": [],
            })
            .to_string(),
        ),
    )?;
    // Wrong extension, and a directory that merely looks like one.
    write(&dest.path().join("notes.txt"), "unrelated")?;
    std::fs::create_dir(dest.path().join("adirectory.apbk"))?;
    // A symlink named like an archive, pointing at a real one.
    std::os::unix::fs::symlink(&ours, dest.path().join("alink.apbk"))?;

    let plan = plan_prune(dest.path(), keep(1))?;
    assert_eq!(plan.ours.len(), 1, "only the real archive is ours");
    assert_eq!(plan.delete, Vec::<PathBuf>::new(), "nothing to delete");

    let by_name: std::collections::HashMap<String, ForeignReason> = plan
        .foreign
        .iter()
        .filter_map(|(p, r)| {
            p.file_name()
                .map(|n| (n.to_string_lossy().into_owned(), *r))
        })
        .collect();
    assert_eq!(by_name["truncated.apbk"], ForeignReason::NotAnArchive);
    assert_eq!(by_name["garbage.apbk"], ForeignReason::NotAnArchive);
    assert_eq!(by_name["norecord.apbk"], ForeignReason::NoRecord);
    assert_eq!(by_name["unparsable.apbk"], ForeignReason::UnreadableRecord);
    assert_eq!(by_name["othertool.apbk"], ForeignReason::UnreadableRecord);
    assert_eq!(
        by_name["newer.apbk"],
        ForeignReason::UnsupportedFormatVersion(BACKUP_FORMAT_VERSION + 1)
    );
    assert_eq!(by_name["notes.txt"], ForeignReason::WrongExtension);
    assert_eq!(by_name["adirectory.apbk"], ForeignReason::NotARegularFile);
    assert_eq!(by_name["alink.apbk"], ForeignReason::NotARegularFile);

    // And a real prune leaves every one of them in place.
    let before: Vec<String> = names(
        &std::fs::read_dir(dest.path())?
            .filter_map(Result::ok)
            .map(|e| e.path())
            .collect::<Vec<_>>(),
    );
    let report = prune(dest.path(), keep(1))?;
    // Reporting what it left alone, with the check that rejected each one. A prune that answered with
    // a count would leave the user counting files they can already see, which is the question rather
    // than the answer: these nine are here for nine different reasons.
    // By path, because both come from their own directory listing and the order of one is not the
    // order of the other.
    let mut reported = report.foreign.clone();
    let mut planned = plan.foreign.clone();
    reported.sort_by(|a, b| a.0.cmp(&b.0));
    planned.sort_by(|a, b| a.0.cmp(&b.0));
    assert_eq!(
        reported, planned,
        "the prune reported something other than the plan it ran"
    );
    let after: Vec<String> = names(
        &std::fs::read_dir(dest.path())?
            .filter_map(Result::ok)
            .map(|e| e.path())
            .collect::<Vec<_>>(),
    );
    let mut before = before;
    let mut after = after;
    before.sort();
    after.sort();
    assert_eq!(before, after, "a prune removed something that was not ours");
    Ok(())
}

/// An archive from a newer build is never deleted, because removing something this build cannot read
/// is the one mistake here that cannot be undone.
#[test]
fn an_archive_from_a_newer_build_is_left_alone_even_when_over_the_limit() -> Result<(), Fallible> {
    let source = tempfile::tempdir()?;
    let dest = tempfile::tempdir()?;
    game_tree(source.path())?;
    for offset in [0, 100, 200] {
        archive_at(source.path(), dest.path(), 1_785_000_000 + offset)?;
    }
    let future = dest.path().join("future.apbk");
    archive_with_record(
        &future,
        Some(
            &serde_json::json!({
                "format": BACKUP_FORMAT, "format_version": BACKUP_FORMAT_VERSION + 1,
                "producer": "apogee-addons/9.9.9", "created_at": 1, "roots": [], "entries": [],
            })
            .to_string(),
        ),
    )?;

    prune(dest.path(), keep(1))?;
    assert!(future.exists(), "a format we cannot read was deleted");
    Ok(())
}

/// Fewer archives than the policy keeps means nothing to do.
#[test]
fn a_directory_under_the_limit_loses_nothing() -> Result<(), Fallible> {
    let source = tempfile::tempdir()?;
    let dest = tempfile::tempdir()?;
    game_tree(source.path())?;
    archive_at(source.path(), dest.path(), 1_785_000_000)?;

    let report = prune(dest.path(), keep(5))?;
    assert!(report.deleted.is_empty());
    assert_eq!(report.kept, 1);
    Ok(())
}

/// The plan is a dry run: producing one changes nothing on disk.
#[test]
fn planning_a_prune_deletes_nothing() -> Result<(), Fallible> {
    let source = tempfile::tempdir()?;
    let dest = tempfile::tempdir()?;
    game_tree(source.path())?;
    for offset in [0, 100, 200] {
        archive_at(source.path(), dest.path(), 1_785_000_000 + offset)?;
    }

    let plan = plan_prune(dest.path(), keep(1))?;
    assert_eq!(plan.delete.len(), 2);
    for path in &plan.delete {
        assert!(path.exists(), "planning removed {path:?}");
    }
    // And it is stable: a second plan over an unchanged directory says the same thing.
    let again = plan_prune(dest.path(), keep(1))?;
    assert_eq!(plan.delete, again.delete);
    assert_eq!(plan.keep, again.keep);
    Ok(())
}

/// Two archives sharing an instant still order deterministically, so a plan does not vary run to run.
#[test]
fn archives_sharing_an_instant_order_deterministically() -> Result<(), Fallible> {
    let source = tempfile::tempdir()?;
    let dest = tempfile::tempdir()?;
    game_tree(source.path())?;
    archive_at(source.path(), dest.path(), 1_785_000_000)?;
    archive_at(source.path(), dest.path(), 1_785_000_000)?;

    let a = plan_prune(dest.path(), keep(1))?;
    let b = plan_prune(dest.path(), keep(1))?;
    assert_eq!(a.keep, b.keep);
    assert_eq!(a.delete, b.delete);
    assert_eq!(a.delete.len(), 1);
    Ok(())
}

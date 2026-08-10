//! Selection over a tree shaped like the one the game really writes.
//!
//! The casings, the doubled extensions, and the fact that character settings live in directories
//! rather than in files are all copied from a live install, because those are exactly the details a
//! selection can get wrong while still appearing to work.

use std::io;
use std::path::Path;

use apogee_addons::backup::{
    BackupError, GameConfigOpts, Presence, RuleRole, Selected, Selection, SelectionRoot,
};

/// The fourteen settings files a character directory holds, uppercase as the game writes them.
const CHARACTER_FILES: &[&str] = &[
    "ACQ.DAT",
    "ADDON.DAT",
    "COMMON.DAT",
    "CONTROL0.DAT",
    "CONTROL1.DAT",
    "GEARSET.DAT",
    "GS.DAT",
    "HOTBAR.DAT",
    "ITEMFDR.DAT",
    "ITEMODR.DAT",
    "KEYBIND.DAT",
    "LOGFLTR.DAT",
    "MACRO.DAT",
    "UISAVE.DAT",
];

const CHARACTER_DIR: &str = "FFXIV_CHR004000174C116E58";

fn write(path: &Path, body: &str) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, body)
}

/// A game config tree: the root config, one character directory with its settings, its chat logs and
/// rotation shadows, the config-copy directory, the game's restore blob, and screenshots.
fn game_tree(root: &Path) -> io::Result<()> {
    write(&root.join("FFXIV.cfg"), "cfg")?;
    // Rotation shadows carry an uppercase extension and a lowercase suffix at once.
    write(&root.join("FFXIV.cfg.old"), "stale")?;
    for name in CHARACTER_FILES {
        write(&root.join(CHARACTER_DIR).join(name), name)?;
    }
    write(&root.join(CHARACTER_DIR).join("ADDON.DAT.old"), "stale")?;
    for n in 0..3 {
        write(
            &root
                .join(CHARACTER_DIR)
                .join("log")
                .join(format!("{n:08x}.log")),
            "chat",
        )?;
    }
    // The config-copy payload is lowercase where the character payloads are uppercase.
    write(
        &root
            .join("cfgcopy")
            .join("FFXIV_CFGCPYB4E9C66C1760C0EE.dat"),
        "copy",
    )?;
    write(
        &root
            .join("backup")
            .join("FFXIV_BKCHR004000174C116E58_00.dat"),
        "blob",
    )?;
    std::fs::create_dir_all(root.join("screenshots"))?;
    Ok(())
}

fn resolve_game(root: &Path, opts: GameConfigOpts) -> Result<Selected, BackupError> {
    Selection::new()
        .with_root(SelectionRoot::game_config(root, opts))?
        .resolve()
}

fn names(selected: &Selected) -> Vec<String> {
    selected
        .entries()
        .iter()
        .map(|e| e.name().to_owned())
        .collect()
}

fn has(names: &[String], want: &str) -> bool {
    names.iter().any(|n| n == want)
}

/// The character settings are the whole point of the backup, and they live in a directory whose name
/// carries an id. A selection that reaches them only through a files-only pattern, or that matches
/// their extension with the wrong case, produces an archive that looks fine and holds none of them.
#[test]
fn every_character_settings_file_is_captured() -> Result<(), BackupError> {
    let tmp = tempfile::tempdir().unwrap();
    game_tree(tmp.path()).unwrap();

    let selected = resolve_game(tmp.path(), GameConfigOpts::default())?;
    let names = names(&selected);

    for file in CHARACTER_FILES {
        let want = format!("user/{CHARACTER_DIR}/{file}");
        assert!(has(&names, &want), "{want} missing from {names:?}");
    }
    assert!(has(&names, &format!("user/{CHARACTER_DIR}/")));
    Ok(())
}

/// The config-copy directory holds a lowercase payload beside the character directory's uppercase
/// ones, so a single casing choice cannot cover both, and normalizing to either one drops the other.
#[test]
fn the_config_copy_payload_is_captured_despite_its_opposite_casing() -> Result<(), BackupError> {
    let tmp = tempfile::tempdir().unwrap();
    game_tree(tmp.path()).unwrap();

    let selected = resolve_game(tmp.path(), GameConfigOpts::default())?;
    let names = names(&selected);
    assert!(has(&names, "user/cfgcopy/FFXIV_CFGCPYB4E9C66C1760C0EE.dat"));
    assert!(has(&names, &format!("user/{CHARACTER_DIR}/HOTBAR.DAT")));
    Ok(())
}

/// Chat scrollback dwarfs the settings and is not settings; the rotation shadows are strictly older
/// copies of data already selected; the restore blob is a stale re-encoding of it.
#[test]
fn logs_rotations_screenshots_and_the_restore_blob_are_left_out() -> Result<(), BackupError> {
    let tmp = tempfile::tempdir().unwrap();
    game_tree(tmp.path()).unwrap();

    let selected = resolve_game(tmp.path(), GameConfigOpts::default())?;
    let names = names(&selected);
    assert!(
        !names.iter().any(|n| n.contains("/log")),
        "chat logs kept: {names:?}"
    );
    // A known, fixed, lowercase suffix this crate generates, not an arbitrary file from a real
    // filesystem: `Path::extension()`'s case-insensitivity buys nothing worth the indirection here.
    #[allow(clippy::case_sensitive_file_extension_comparisons)]
    let dropped_rotation = !names.iter().any(|n| n.ends_with(".old"));
    assert!(dropped_rotation);
    assert!(!names.iter().any(|n| n.contains("screenshots")));
    assert!(!names.iter().any(|n| n.contains("FFXIV_BKCHR")));
    Ok(())
}

/// Every exclusion is a switch, and the pruned subtree comes back whole when it is flipped.
#[test]
fn opting_in_brings_back_exactly_what_was_pruned() -> Result<(), BackupError> {
    let tmp = tempfile::tempdir().unwrap();
    game_tree(tmp.path()).unwrap();

    let all = GameConfigOpts {
        chat_logs: true,
        screenshots: true,
        rotations: true,
        game_restore_blob: true,
    };
    let selected = resolve_game(tmp.path(), all)?;
    let names = names(&selected);
    assert!(has(
        &names,
        &format!("user/{CHARACTER_DIR}/log/00000000.log")
    ));
    assert!(has(&names, &format!("user/{CHARACTER_DIR}/ADDON.DAT.old")));
    assert!(has(&names, "user/FFXIV.cfg.old"));
    assert!(has(&names, "user/screenshots/"));
    assert!(has(
        &names,
        "user/backup/FFXIV_BKCHR004000174C116E58_00.dat"
    ));
    Ok(())
}

/// An optional rule that matches nothing still reports, because a zero is something a reader can
/// act on and an absent row is not.
#[test]
fn a_rule_that_matches_nothing_is_reported_with_a_zero() -> Result<(), BackupError> {
    let tmp = tempfile::tempdir().unwrap();
    game_tree(tmp.path()).unwrap();
    // No character directory holds a chat log here, so the prune rule for them matches nothing.
    std::fs::remove_dir_all(tmp.path().join(CHARACTER_DIR).join("log")).unwrap();

    let selected = resolve_game(tmp.path(), GameConfigOpts::default())?;
    let root = &selected.roots()[0];
    let logs = root
        .rules()
        .iter()
        .find(|r| r.rule() == "dir log")
        .expect("the prune rule is reported even when it does nothing");
    assert_eq!(logs.matched(), 0);
    assert_eq!(logs.role(), RuleRole::Prune);
    // And the rules that did fire carry counts, so the report distinguishes the two.
    assert!(root.rules().iter().any(|r| r.matched() > 0));
    Ok(())
}

/// The launcher identity files carry an account name and a last-used one-time password. They are
/// withheld at any depth, in any casing, and the withholding is counted rather than silent.
#[test]
fn launcher_identity_files_are_withheld_in_any_casing() -> Result<(), BackupError> {
    let tmp = tempfile::tempdir().unwrap();
    game_tree(tmp.path()).unwrap();
    write(&tmp.path().join("accounts.json"), "secret").unwrap();
    write(
        &tmp.path().join(CHARACTER_DIR).join("Accounts.JSON"),
        "secret",
    )
    .unwrap();

    let selected = resolve_game(tmp.path(), GameConfigOpts::default())?;
    let names = names(&selected);
    assert!(
        !names
            .iter()
            .any(|n| n.to_ascii_lowercase().contains("accounts.json")),
        "identity file selected: {names:?}"
    );
    let denied: usize = selected.roots()[0]
        .rules()
        .iter()
        .filter(|r| r.role() == RuleRole::Deny)
        .map(apogee_addons::backup::RuleReport::matched)
        .sum();
    assert_eq!(denied, 2, "both casings counted");
    Ok(())
}

/// A prefix reaches one config tree under several names, so a selection that walked each of them
/// would archive the same settings repeatedly.
#[test]
fn a_symlink_is_skipped_and_counted() -> Result<(), BackupError> {
    let tmp = tempfile::tempdir().unwrap();
    game_tree(tmp.path()).unwrap();
    std::os::unix::fs::symlink(tmp.path().join(CHARACTER_DIR), tmp.path().join("My Chars"))
        .unwrap();

    let selected = resolve_game(tmp.path(), GameConfigOpts::default())?;
    assert_eq!(selected.roots()[0].links_skipped(), 1);
    assert!(!names(&selected).iter().any(|n| n.contains("My Chars")));
    Ok(())
}

/// The same tree reached twice through different names is one tree.
#[test]
fn two_roots_that_reach_the_same_tree_are_refused() {
    let tmp = tempfile::tempdir().unwrap();
    game_tree(tmp.path()).unwrap();
    std::os::unix::fs::symlink(tmp.path(), tmp.path().join("pfx")).unwrap();

    let err = Selection::new()
        .with_root(SelectionRoot::game_config(
            tmp.path(),
            GameConfigOpts::default(),
        ))
        .and_then(|s| {
            s.with_root(SelectionRoot::game_config(
                tmp.path().join("pfx"),
                GameConfigOpts::default(),
            ))
        });
    assert!(matches!(err, Err(BackupError::DuplicateRoot { .. })));
}

/// An archive holding nothing restores as a success that returns no settings, which is the outcome
/// this whole design is arranged to prevent.
#[test]
fn a_tree_that_yields_nothing_fails_instead_of_succeeding_empty() {
    let tmp = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(tmp.path().join("screenshots")).unwrap();

    let err = resolve_game(tmp.path(), GameConfigOpts::default());
    assert!(matches!(err, Err(BackupError::NothingSelected)));
}

/// Order comes from the archive names, not from the order the filesystem hands entries back, so two
/// trees with the same contents built in different orders select identically.
#[test]
fn the_order_does_not_depend_on_the_order_the_tree_was_built() -> Result<(), BackupError> {
    let forward = tempfile::tempdir().unwrap();
    game_tree(forward.path()).unwrap();

    let reverse = tempfile::tempdir().unwrap();
    // Same contents, written in the opposite order, which is the order tmpfs then reads them in.
    std::fs::create_dir_all(reverse.path().join("screenshots")).unwrap();
    write(
        &reverse
            .path()
            .join("backup")
            .join("FFXIV_BKCHR004000174C116E58_00.dat"),
        "blob",
    )
    .unwrap();
    write(
        &reverse
            .path()
            .join("cfgcopy")
            .join("FFXIV_CFGCPYB4E9C66C1760C0EE.dat"),
        "copy",
    )
    .unwrap();
    for n in (0..3).rev() {
        write(
            &reverse
                .path()
                .join(CHARACTER_DIR)
                .join("log")
                .join(format!("{n:08x}.log")),
            "chat",
        )
        .unwrap();
    }
    write(
        &reverse.path().join(CHARACTER_DIR).join("ADDON.DAT.old"),
        "stale",
    )
    .unwrap();
    for name in CHARACTER_FILES.iter().rev() {
        write(&reverse.path().join(CHARACTER_DIR).join(name), name).unwrap();
    }
    write(&reverse.path().join("FFXIV.cfg.old"), "stale").unwrap();
    write(&reverse.path().join("FFXIV.cfg"), "cfg").unwrap();

    let a = resolve_game(forward.path(), GameConfigOpts::default())?;
    let b = resolve_game(reverse.path(), GameConfigOpts::default())?;
    assert_eq!(names(&a), names(&b));
    // A parent sorts before what it holds, so an archive written in this order never names a file
    // before the directory it belongs to.
    let chr = format!("user/{CHARACTER_DIR}/");
    let names_a = names(&a);
    let dir_at = names_a.iter().position(|n| *n == chr).unwrap();
    // Strictly longer, so this finds a child rather than the directory entry itself.
    let file_at = names_a
        .iter()
        .position(|n| n.starts_with(&chr) && n.len() > chr.len())
        .unwrap();
    assert!(dir_at < file_at);
    Ok(())
}

/// A required root that is absent is a fault, because the caller asked for a tree that is not there.
#[test]
fn a_missing_required_root_fails() {
    let tmp = tempfile::tempdir().unwrap();
    let err = resolve_game(&tmp.path().join("nope"), GameConfigOpts::default());
    assert!(matches!(err, Err(BackupError::MissingRoot { .. })));
}

/// Presence is part of the root's contract, so it is readable back off the root.
#[test]
fn the_game_root_is_required() {
    assert_eq!(
        SelectionRoot::game_config("/tmp/x", GameConfigOpts::default()).presence(),
        Presence::Required
    );
}

/// The user directory inside a prefix is named after whoever the runner claims to be, and Proton
/// relocates the whole prefix a level down. Both shapes are real, and both must resolve.
#[test]
fn the_game_config_tree_is_found_in_either_prefix_shape() {
    use apogee_addons::backup::game_config_dirs;

    for (label, drive) in [("plain", ""), ("relocated", "pfx")] {
        let tmp = tempfile::tempdir().unwrap();
        let root = if drive.is_empty() {
            tmp.path().to_path_buf()
        } else {
            tmp.path().join(drive)
        };
        let config = root
            .join("drive_c/users/steamuser/Documents/My Games/FINAL FANTASY XIV - A Realm Reborn");
        game_tree(&config).unwrap();
        // A user that never owns a config tree.
        std::fs::create_dir_all(root.join("drive_c/users/Public/Documents")).unwrap();

        assert_eq!(game_config_dirs(tmp.path()), vec![config], "{label} prefix");
    }
}

/// A prefix run under two runners holds a full set of settings under each name. Choosing between
/// them by name would quietly back up whichever sorted first, so both are returned and the one the
/// game wrote to last comes first.
#[test]
fn a_prefix_run_under_two_runners_reports_both_trees_newest_first() {
    use apogee_addons::backup::game_config_dirs;

    let tmp = tempfile::tempdir().unwrap();
    let users = tmp.path().join("drive_c/users");
    let under = |user: &str| {
        users
            .join(user)
            .join("Documents/My Games/FINAL FANTASY XIV - A Realm Reborn")
    };
    // `lyra` sorts first by name, so an alphabetical pick would take it.
    game_tree(&under("lyra")).unwrap();
    game_tree(&under("steamuser")).unwrap();

    // The one the game touched last is the one it is using.
    let recent = std::time::SystemTime::now();
    let stale = recent - std::time::Duration::from_secs(60 * 60 * 24 * 30);
    std::fs::File::options()
        .write(true)
        .open(under("lyra").join("FFXIV.cfg"))
        .unwrap()
        .set_modified(stale)
        .unwrap();
    std::fs::File::options()
        .write(true)
        .open(under("steamuser").join("FFXIV.cfg"))
        .unwrap()
        .set_modified(recent)
        .unwrap();

    let found = game_config_dirs(tmp.path());
    assert_eq!(found.len(), 2, "both trees are real settings: {found:?}");
    assert_eq!(found[0], under("steamuser"), "the live tree comes first");
    assert_eq!(found[1], under("lyra"));
}

/// A prefix the game has never written into has no config tree, which is a state rather than a fault.
#[test]
fn a_prefix_the_game_never_ran_in_has_no_config_tree() {
    use apogee_addons::backup::game_config_dirs;

    let tmp = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(tmp.path().join("drive_c/users/steamuser/Documents")).unwrap();
    assert!(game_config_dirs(tmp.path()).is_empty());
    assert!(game_config_dirs(&tmp.path().join("absent")).is_empty());
}

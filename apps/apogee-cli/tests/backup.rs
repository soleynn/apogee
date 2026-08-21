//! `backup` command group over a prefix-shaped config tree: hermetic, no network, no wine.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use tempfile::tempdir;

fn run(home: &Path, args: &[&str]) -> std::io::Result<Output> {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_apogee-cli"));
    cmd.env("XDG_CONFIG_HOME", home.join("config"))
        .env("XDG_DATA_HOME", home.join("data"))
        .env("XDG_CACHE_HOME", home.join("cache"))
        .args(args);
    cmd.output()
}

fn stdout(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

#[cfg(not(unix))]
fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

type Fallible = Box<dyn std::error::Error>;

/// A profile, plus the config tree the game would have written inside its prefix.
fn setup(home: &Path) -> Result<PathBuf, Fallible> {
    let out = run(
        home,
        &[
            "profile",
            "add",
            "--name",
            "main",
            "--user",
            "someone",
            "--game-path",
            "/tmp/ffxiv",
        ],
    )?;
    assert!(out.status.success(), "profile add failed: {}", stdout(&out));

    // The launcher names a prefix after the profile, so read back what it chose.
    let listed = run(home, &["profile", "list"])?;
    let text = stdout(&listed);
    let id = text
        .split_whitespace()
        .find(|w| w.len() == 36 && w.matches('-').count() == 4)
        .ok_or("no profile id in the listing")?
        .to_owned();

    let config = home
        .join("data/apogee/prefixes")
        .join(&id)
        .join("drive_c/users/steamuser/Documents/My Games/FINAL FANTASY XIV - A Realm Reborn");
    std::fs::create_dir_all(config.join("FFXIV_CHR004000174C116E58"))?;
    std::fs::write(config.join("FFXIV.cfg"), "cfg")?;
    for name in ["HOTBAR.DAT", "MACRO.DAT", "GEARSET.DAT"] {
        std::fs::write(config.join("FFXIV_CHR004000174C116E58").join(name), name)?;
    }
    Ok(config)
}

/// Capture and list through the shell, then either restore or report the platform boundary.
#[test]
fn a_backup_is_created_listed_and_restore_respects_the_platform_boundary() -> Result<(), Fallible> {
    let home = tempdir()?;
    let config = setup(home.path())?;

    let out = run(home.path(), &["backup", "create", "--profile", "main"])?;
    let text = stdout(&out);
    assert!(out.status.success(), "create failed: {text}");
    assert!(text.contains("backed up 4 file(s)"), "unexpected: {text}");

    let listed = run(home.path(), &["backup", "list", "--profile", "main"])?;
    let listing = stdout(&listed);
    assert!(listing.contains(".apbk"), "nothing listed:\n{listing}");
    let archive = listing
        .split_whitespace()
        .find(|w| w.ends_with(".apbk"))
        .ok_or("no archive listed")?
        .to_owned();

    // Change the live tree, then put the backup back over it.
    std::fs::write(config.join("FFXIV.cfg"), "changed")?;
    std::fs::write(config.join("stray.txt"), "not in the backup")?;

    let restored = run(
        home.path(),
        &[
            "backup",
            "restore",
            "--profile",
            "main",
            "--archive",
            &archive,
        ],
    )?;

    #[cfg(unix)]
    {
        let text = stdout(&restored);
        assert!(restored.status.success(), "restore failed: {text}");
        assert_eq!(std::fs::read_to_string(config.join("FFXIV.cfg"))?, "cfg");
        assert!(
            !config.join("stray.txt").exists(),
            "restore merged rather than replaced"
        );
        // The tree that was there is kept, so the restore is reversible.
        assert!(
            text.contains("the tree that was there is at"),
            "not reported: {text}"
        );
    }

    #[cfg(not(unix))]
    {
        let text = stderr(&restored);
        assert!(!restored.status.success(), "restore unexpectedly succeeded");
        assert!(
            text.contains("restoring a backup is not supported on this platform"),
            "typed unsupported error was not reported: {text}"
        );
        assert_eq!(
            std::fs::read_to_string(config.join("FFXIV.cfg"))?,
            "changed",
            "a refused restore changed the live configuration"
        );
        assert!(
            config.join("stray.txt").exists(),
            "a refused restore replaced the live tree"
        );
    }
    Ok(())
}

/// Pruning keeps the newest and never touches a file it did not write.
#[test]
fn pruning_keeps_the_newest_and_leaves_strangers_alone() -> Result<(), Fallible> {
    let home = tempdir()?;
    setup(home.path())?;

    for _ in 0..3 {
        let out = run(home.path(), &["backup", "create", "--profile", "main"])?;
        assert!(out.status.success(), "create failed: {}", stdout(&out));
    }

    // Something that is not ours, sitting in the same directory.
    let listing = stdout(&run(home.path(), &["backup", "list", "--profile", "main"])?);
    let any = listing
        .split_whitespace()
        .find(|w| w.ends_with(".apbk"))
        .ok_or("no archive listed")?;
    let dir = Path::new(any).parent().ok_or("an archive has no parent")?;
    let stranger = dir.join("someone-elses.apbk");
    std::fs::write(&stranger, "not an archive")?;

    let out = run(
        home.path(),
        &["backup", "prune", "--profile", "main", "--keep", "1"],
    )?;
    let text = stdout(&out);
    assert!(out.status.success(), "prune failed: {text}");
    assert!(text.contains("kept 1"), "unexpected: {text}");
    assert!(stranger.exists(), "a file we did not write was deleted");

    let remaining = stdout(&run(home.path(), &["backup", "list", "--profile", "main"])?);
    assert_eq!(
        remaining.lines().filter(|l| l.contains(".apbk")).count(),
        1,
        "wrong number kept:\n{remaining}"
    );
    Ok(())
}

/// A prefix the game has never written into has nothing to back up, and says so.
#[test]
fn a_prefix_with_no_config_says_so() -> Result<(), Fallible> {
    let home = tempdir()?;
    let out = run(
        home.path(),
        &[
            "profile",
            "add",
            "--name",
            "main",
            "--user",
            "someone",
            "--game-path",
            "/tmp/ffxiv",
        ],
    )?;
    assert!(out.status.success());

    let out = run(home.path(), &["backup", "create", "--profile", "main"])?;
    assert!(!out.status.success(), "an empty prefix produced a backup");
    let listed = run(home.path(), &["backup", "list", "--profile", "main"])?;
    assert!(stdout(&listed).contains("no backups"));
    Ok(())
}

/// Keeping none would delete every backup there is, so it is not expressible.
#[test]
fn keeping_none_is_refused() -> Result<(), Fallible> {
    let home = tempdir()?;
    setup(home.path())?;
    run(home.path(), &["backup", "create", "--profile", "main"])?;

    let out = run(
        home.path(),
        &["backup", "prune", "--profile", "main", "--keep", "0"],
    )?;
    assert!(!out.status.success(), "keeping none was accepted");

    let listed = stdout(&run(home.path(), &["backup", "list", "--profile", "main"])?);
    assert!(listed.contains(".apbk"), "the backup was deleted anyway");
    Ok(())
}

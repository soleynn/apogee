#![cfg(unix)]
//! Registering a profile with Steam, end to end through the binary.
//!
//! Offline and contained: the Steam installation is a directory in a throwaway home, so the test
//! writes a real registration and reads real files back without touching the machine's own Steam. The
//! part no test can reach is Steam itself reading what was written, which is a manual check on a
//! machine that has it.

use std::path::Path;
use std::process::{Command, Output};

use tempfile::TempDir;

fn run(home: &Path, args: &[&str]) -> std::io::Result<Output> {
    Command::new(env!("CARGO_BIN_EXE_apogee-cli"))
        .args(args)
        .env("HOME", home)
        .env("XDG_CONFIG_HOME", home.join("config"))
        .env("XDG_DATA_HOME", home.join("data"))
        .env("XDG_CACHE_HOME", home.join("cache"))
        .output()
}

fn stdout(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

/// A home holding one profile and a Steam installation that has been started at least once.
fn with_profile_and_steam() -> std::io::Result<TempDir> {
    let home = TempDir::new()?;
    std::fs::create_dir_all(home.path().join(".steam/root"))?;
    run(
        home.path(),
        &[
            "profile",
            "add",
            "--name",
            "main",
            "--user",
            "me@example.invalid",
            "--game-path",
            "/games/ffxiv",
        ],
    )?;
    Ok(home)
}

fn tool_dir(home: &Path) -> std::path::PathBuf {
    home.join(".steam/root/compatibilitytools.d/apogee")
}

/// What Steam needs in order to offer the profile at all: a declaration naming it, a manifest
/// pointing at a program, and that program present and runnable.
#[test]
fn registering_writes_what_steam_reads() -> std::io::Result<()> {
    let home = with_profile_and_steam()?;

    let out = run(home.path(), &["steam", "register", "--profile", "main"])?;
    assert!(out.status.success(), "{}", stdout(&out));
    assert!(
        stdout(&out).contains("restart steam"),
        "a registration Steam has not reloaded yet is not visible: {}",
        stdout(&out)
    );

    let dir = tool_dir(home.path());
    let declaration = std::fs::read_to_string(dir.join("compatibilitytool.vdf"))?;
    assert!(
        declaration.contains("Apogee (main)"),
        "the profile is named where the user chooses between registrations: {declaration}"
    );
    let manifest = std::fs::read_to_string(dir.join("toolmanifest.vdf"))?;
    assert!(manifest.contains("%verb%"), "{manifest}");

    let script = dir.join("apogee-run");
    assert!(script.is_file());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&script)?.permissions().mode();
        assert_ne!(mode & 0o111, 0, "steam has to be able to run it");
    }
    Ok(())
}

/// Steam invokes the tool more than once for a single launch. The registration must start the game
/// on exactly one of those calls, so the other is exercised here for the no-op it has to be.
#[test]
fn the_registration_starts_nothing_on_the_verb_that_is_not_the_launch() -> std::io::Result<()> {
    let home = with_profile_and_steam()?;
    run(home.path(), &["steam", "register", "--profile", "main"])?;

    let out = Command::new(tool_dir(home.path()).join("apogee-run"))
        .args(["run", "/steam/library/some-other-game.exe", "-windowed"])
        .env("HOME", home.path())
        .output()?;
    assert!(out.status.success(), "the call still has to succeed");
    assert!(
        out.stdout.is_empty(),
        "nothing was started: {}",
        String::from_utf8_lossy(&out.stdout)
    );
    Ok(())
}

/// Withdrawing leaves the installation as it was found, including the directory that holds every
/// other tool the user has.
#[test]
fn unregistering_removes_only_this_launchers_entry() -> std::io::Result<()> {
    let home = with_profile_and_steam()?;
    let tools = home.path().join(".steam/root/compatibilitytools.d");
    std::fs::create_dir_all(tools.join("SomeoneElsesRunner"))?;

    run(home.path(), &["steam", "register", "--profile", "main"])?;
    let out = run(home.path(), &["steam", "unregister"])?;
    assert!(out.status.success(), "{}", stdout(&out));

    assert!(!tool_dir(home.path()).exists());
    assert!(tools.join("SomeoneElsesRunner").is_dir(), "left alone");

    // Withdrawing again says so rather than failing, so a script can run it unconditionally.
    let out = run(home.path(), &["steam", "unregister"])?;
    assert!(out.status.success());
    assert!(
        stdout(&out).contains("nothing registered"),
        "{}",
        stdout(&out)
    );
    Ok(())
}

/// A machine where Steam has never run has nowhere to register into, and saying so beats writing a
/// directory tree Steam will never look at.
#[test]
fn a_machine_without_steam_is_refused_rather_than_written_to() -> std::io::Result<()> {
    let home = TempDir::new()?;
    run(
        home.path(),
        &[
            "profile",
            "add",
            "--name",
            "main",
            "--user",
            "me@example.invalid",
            "--game-path",
            "/games/ffxiv",
        ],
    )?;

    let out = run(home.path(), &["steam", "register", "--profile", "main"])?;
    assert!(!out.status.success());
    assert!(!home.path().join(".steam").exists(), "nothing was created");

    let out = run(home.path(), &["steam", "status"])?;
    assert!(out.status.success(), "status still answers");
    assert!(
        stdout(&out).contains("no installation found"),
        "{}",
        stdout(&out)
    );
    Ok(())
}

/// The environment a game session hands a program is minimal, and a launch that went wrong there is
/// exactly when these two commands are worth running. Neither needs the profile store, so neither may
/// require the variables that locate it.
#[test]
fn asking_what_the_machine_is_works_with_no_environment_at_all() -> std::io::Result<()> {
    let bare = Command::new(env!("CARGO_BIN_EXE_apogee-cli"))
        .args(["steam", "status"])
        .env_clear()
        .output()?;
    assert!(
        bare.status.success(),
        "status failed with a bare environment: {}",
        String::from_utf8_lossy(&bare.stderr)
    );
    assert!(stdout(&bare).contains("machine:"), "{}", stdout(&bare));

    let bare = Command::new(env!("CARGO_BIN_EXE_apogee-cli"))
        .args(["steam", "unregister"])
        .env_clear()
        .output()?;
    // No home means no installation to withdraw from, which is an answer rather than a crash about
    // configuration directories.
    assert!(
        String::from_utf8_lossy(&bare.stderr).contains("no steam installation"),
        "stderr: {}",
        String::from_utf8_lossy(&bare.stderr)
    );
    Ok(())
}

/// Withdrawing is gated on the same test that reports a registration as present. A directory that
/// merely shares the name belongs to whoever wrote it, and a recursive delete is not the place to
/// find out this launcher did not.
#[test]
fn a_directory_this_launcher_did_not_write_is_not_removed() -> std::io::Result<()> {
    let home = with_profile_and_steam()?;
    let foreign = tool_dir(home.path());
    std::fs::create_dir_all(&foreign)?;
    std::fs::write(foreign.join("compatibilitytool.vdf"), "someone else's")?;

    let out = run(home.path(), &["steam", "status"])?;
    assert!(stdout(&out).contains("not registered"), "{}", stdout(&out));

    let out = run(home.path(), &["steam", "unregister"])?;
    assert!(out.status.success());
    assert!(
        stdout(&out).contains("nothing registered"),
        "{}",
        stdout(&out)
    );
    assert!(
        foreign.join("compatibilitytool.vdf").is_file(),
        "the other tool's file survived"
    );
    Ok(())
}

/// Status reports the machine as well as the registration, since which of the two a Deck-specific
/// problem lies in is the first thing worth knowing.
#[test]
fn status_reports_the_machine_and_whether_anything_is_registered() -> std::io::Result<()> {
    let home = with_profile_and_steam()?;

    let out = run(home.path(), &["steam", "status"])?;
    assert!(out.status.success());
    assert!(stdout(&out).contains("machine:"), "{}", stdout(&out));
    assert!(stdout(&out).contains("not registered"), "{}", stdout(&out));

    run(home.path(), &["steam", "register", "--profile", "main"])?;
    let out = run(home.path(), &["steam", "status"])?;
    assert!(stdout(&out).contains("registered at"), "{}", stdout(&out));
    Ok(())
}

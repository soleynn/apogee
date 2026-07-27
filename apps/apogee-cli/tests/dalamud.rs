//! The Dalamud toggle, end to end through the binary.
//!
//! Offline by construction: switching the setting on writes a profile field and nothing else, which is
//! the whole reason the toggle and the install are separate. A test that had to reach a distribution to
//! check a boolean would be testing the wrong thing.

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

/// A home with one profile in it.
fn with_profile() -> std::io::Result<TempDir> {
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
    Ok(home)
}

/// Off is the state a profile starts in. A launcher that loaded third-party code into the game client
/// without being asked would be making that decision for the user.
#[test]
fn a_new_profile_does_not_load_it() -> std::io::Result<()> {
    let home = with_profile()?;
    let out = run(home.path(), &["dalamud", "status", "--profile", "main"])?;
    assert!(out.status.success());
    assert!(stdout(&out).contains("disabled"), "{}", stdout(&out));
    Ok(())
}

/// The toggle persists, and reads back the way it was written.
#[test]
fn enabling_and_disabling_it_round_trips_through_the_profile() -> std::io::Result<()> {
    let home = with_profile()?;

    let out = run(home.path(), &["dalamud", "enable", "--profile", "main"])?;
    assert!(out.status.success());
    assert!(stdout(&out).contains("enabled dalamud"), "{}", stdout(&out));
    let out = run(home.path(), &["dalamud", "status", "--profile", "main"])?;
    assert!(stdout(&out).contains("enabled"), "{}", stdout(&out));

    let out = run(home.path(), &["dalamud", "disable", "--profile", "main"])?;
    assert!(out.status.success());
    let out = run(home.path(), &["dalamud", "status", "--profile", "main"])?;
    assert!(stdout(&out).contains("disabled"), "{}", stdout(&out));
    Ok(())
}

/// A profile that is not there is an error rather than a silent no-op, so a typo does not read as
/// having switched something on.
#[test]
fn a_profile_that_does_not_exist_is_refused() -> std::io::Result<()> {
    let home = with_profile()?;
    let out = run(home.path(), &["dalamud", "enable", "--profile", "other"])?;
    assert!(!out.status.success());
    Ok(())
}

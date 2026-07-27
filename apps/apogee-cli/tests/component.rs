//! `component` command group: hermetic, no network, no wine. Spawns the built binary, so it exercises
//! arg parsing, the profile round trip, and the rendered list end to end.
//!
//! The catalog-reading and installing subcommands are not here: both reach a hosted HTTPS catalog, and a
//! test that pointed them at a local server would be testing the fetcher. What is here is the part that
//! is the CLI's own: which choices persist, and what a launch is told to do with them.

use std::path::Path;
use std::process::{Command, Output};

use tempfile::tempdir;

/// Run the built CLI with storage pinned to a throwaway home so nothing touches real config.
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

/// Create a profile to hang components off.
fn profile(home: &Path) -> std::io::Result<()> {
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
    Ok(())
}

/// The round trip: a component chosen from the command line is listed back by a separate invocation,
/// which is what proves the choice was persisted rather than held in memory.
#[test]
fn a_component_is_chosen_listed_and_persisted() -> std::io::Result<()> {
    let home = tempdir()?;
    profile(home.path())?;

    let out = run(
        home.path(),
        &["component", "enable", "--profile", "main", "--name", "ACT"],
    )?;
    assert!(out.status.success(), "{}", stdout(&out));
    assert!(stdout(&out).contains("enabled component ACT"));

    let out = run(home.path(), &["component", "list", "--profile", "main"])?;
    assert!(out.status.success());
    let listed = stdout(&out);
    assert!(listed.contains("enabled"), "{listed}");
    assert!(listed.contains("ACT"), "{listed}");
    Ok(())
}

/// Disabling keeps the entry, so a component left out of one launch is not something the user has to
/// remember the name of to put back.
#[test]
fn disabling_keeps_the_choice_and_enabling_restores_it() -> std::io::Result<()> {
    let home = tempdir()?;
    profile(home.path())?;
    run(
        home.path(),
        &["component", "enable", "--profile", "main", "--name", "ACT"],
    )?;

    run(
        home.path(),
        &["component", "disable", "--profile", "main", "--name", "ACT"],
    )?;
    let listed = stdout(&run(
        home.path(),
        &["component", "list", "--profile", "main"],
    )?);
    assert!(listed.contains("disabled"), "{listed}");
    assert!(listed.contains("ACT"), "the entry is kept: {listed}");

    run(
        home.path(),
        &["component", "enable", "--profile", "main", "--name", "ACT"],
    )?;
    let listed = stdout(&run(
        home.path(),
        &["component", "list", "--profile", "main"],
    )?);
    assert!(listed.contains("enabled"), "{listed}");
    // And enabling twice does not leave two entries for one component.
    assert_eq!(listed.matches("ACT").count(), 1, "{listed}");
    Ok(())
}

#[test]
fn a_profile_with_no_components_says_so() -> std::io::Result<()> {
    let home = tempdir()?;
    profile(home.path())?;
    let out = run(home.path(), &["component", "list", "--profile", "main"])?;
    assert!(out.status.success());
    assert!(stdout(&out).contains("no components chosen"));
    Ok(())
}

/// Choosing a component for a profile that does not exist is an error rather than a choice stored under
/// a name nothing will ever read.
#[test]
fn an_unknown_profile_is_refused() -> std::io::Result<()> {
    let home = tempdir()?;
    profile(home.path())?;
    let out = run(
        home.path(),
        &["component", "enable", "--profile", "other", "--name", "ACT"],
    )?;
    assert!(!out.status.success());
    Ok(())
}

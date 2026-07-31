//! The prefix command family through the binary, for the parts that need no wine.
//!
//! Creating, checking and fixing all reach a real runner, so they belong to the wine-present job and
//! are exercised there through the library's own tests. What is checked here is the half a user can
//! get wrong without wine being involved at all: that the destructive verb refuses to run until it is
//! answered, and that refusing it leaves the prefix alone.

use std::io::Write;
use std::path::Path;
use std::process::{Command, Output, Stdio};

use tempfile::TempDir;

fn run_with_input(home: &Path, args: &[&str], input: &str) -> std::io::Result<Output> {
    let mut child = Command::new(env!("CARGO_BIN_EXE_apogee-cli"))
        .args(args)
        .env("HOME", home)
        .env("XDG_CONFIG_HOME", home.join("config"))
        .env("XDG_DATA_HOME", home.join("data"))
        .env("XDG_CACHE_HOME", home.join("cache"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    if let Some(stdin) = child.stdin.as_mut() {
        stdin.write_all(input.as_bytes())?;
    }
    child.wait_with_output()
}

fn run(home: &Path, args: &[&str]) -> std::io::Result<Output> {
    run_with_input(home, args, "")
}

fn stdout(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

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

/// The destructive verb discards the prefix and everything in it, including the settings the game
/// keeps there. Answering anything but the profile's own name leaves it alone, so a reflexive "y" is
/// not enough to lose them.
#[test]
fn recreating_refuses_until_the_profile_is_named() -> std::io::Result<()> {
    let home = with_profile()?;

    for answer in ["", "y\n", "yes\n", "Main\n", "other\n"] {
        let out = run_with_input(
            home.path(),
            &["prefix", "recreate", "--profile", "main"],
            answer,
        )?;
        assert!(out.status.success(), "refusing is not a failure");
        assert!(
            stdout(&out).contains("not recreating"),
            "answer {answer:?} should not have gone ahead: {}",
            stdout(&out)
        );
    }
    Ok(())
}

/// What it costs is said before the question, not after, since afterwards is too late to matter.
#[test]
fn the_cost_is_stated_before_the_question() -> std::io::Result<()> {
    let home = with_profile()?;
    let out = run_with_input(
        home.path(),
        &["prefix", "recreate", "--profile", "main"],
        "",
    )?;
    let text = stdout(&out);

    let warning = text.find("deletes the prefix").expect("the cost is stated");
    let question = text.find("type the profile name").expect("the question");
    assert!(warning < question, "{text}");
    assert!(
        text.contains("backup create"),
        "the way to keep them is named: {text}"
    );
    Ok(())
}

/// A profile whose name is empty is still a profile, and a closed stdin is what a script hands this.
/// The two together must not add up to a prefix being destroyed without an answer.
#[test]
fn an_empty_answer_never_confirms_even_for_an_empty_profile_name() -> std::io::Result<()> {
    let home = TempDir::new()?;
    run(
        home.path(),
        &[
            "profile",
            "add",
            "--name",
            "",
            "--user",
            "me@example.invalid",
            "--game-path",
            "/games/ffxiv",
        ],
    )?;

    let out = run_with_input(home.path(), &["prefix", "recreate", "--profile", ""], "")?;
    assert!(
        stdout(&out).contains("not recreating"),
        "an empty answer confirmed an empty name: {}",
        stdout(&out)
    );
    Ok(())
}

/// A profile that is not there is refused before anything touches a prefix directory.
#[test]
fn a_profile_that_does_not_exist_is_refused() -> std::io::Result<()> {
    let home = with_profile()?;
    let out = run(home.path(), &["prefix", "health", "--profile", "other"])?;
    assert!(!out.status.success());
    assert!(
        !home.path().join("data/apogee/prefixes").exists(),
        "nothing was created for a profile that does not exist"
    );
    Ok(())
}

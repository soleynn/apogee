//! The program switches, end to end through the binary.
//!
//! Switching one is a profile write and nothing else, so these run offline by construction: only
//! `status` reads a catalog, and it is pointed at a plain-http URL the fetcher refuses before it
//! connects to anything.

use std::path::Path;
use std::process::{Command, Output};

use tempfile::TempDir;

/// What every program is said to be granted. Pinned verbatim, because softening it is a decision
/// about what users are told about the access they hand over, and that belongs in a reviewed diff.
const TRUST: &str = "Runs in the game's wine session with the same access to the game, your files \
and your stored sign-in as Apogee itself.";

fn run(home: &Path, args: &[&str]) -> std::io::Result<Output> {
    Command::new(env!("CARGO_BIN_EXE_apogee-cli"))
        .args(args)
        .env("HOME", home)
        .env("XDG_CONFIG_HOME", home.join("config"))
        .env("XDG_DATA_HOME", home.join("data"))
        .env("XDG_CACHE_HOME", home.join("cache"))
        .env(
            "APOGEE_COMPONENT_CATALOG_URL",
            "http://127.0.0.1:9/components/manifest.json",
        )
        .output()
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
            "--runner",
            "managed:wine-xiv@test",
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

/// Every program starts off, and the list says so for all three.
#[test]
fn a_new_profile_runs_no_program() -> std::io::Result<()> {
    let home = with_profile()?;
    let out = run(home.path(), &["program", "list", "--profile", "main"])?;
    assert!(out.status.success());
    assert_eq!(
        stdout(&out),
        "dalamud\tdisabled\nxivalexander\tdisabled\nact\tdisabled\n"
    );
    Ok(())
}

/// Turning one on says what it is granted, and the switch persists without touching the others. The
/// `dalamud` family reads the same switch, so the two commands cannot disagree about it.
#[test]
fn enabling_one_persists_says_what_it_grants_and_leaves_the_others() -> std::io::Result<()> {
    let home = with_profile()?;

    let out = run(
        home.path(),
        &["program", "enable", "act", "--profile", "main"],
    )?;
    assert!(out.status.success(), "{out:?}");
    assert!(stdout(&out).contains(TRUST), "{}", stdout(&out));
    let out = run(home.path(), &["program", "list", "--profile", "main"])?;
    assert_eq!(
        stdout(&out),
        "dalamud\tdisabled\nxivalexander\tdisabled\nact\tenabled\n"
    );

    run(
        home.path(),
        &["program", "enable", "dalamud", "--profile", "main"],
    )?;
    let out = run(home.path(), &["dalamud", "status", "--profile", "main"])?;
    assert!(stdout(&out).contains("enabled"), "{}", stdout(&out));

    let out = run(
        home.path(),
        &["program", "disable", "act", "--profile", "main"],
    )?;
    assert!(out.status.success());
    let out = run(home.path(), &["program", "list", "--profile", "main"])?;
    assert_eq!(
        stdout(&out),
        "dalamud\tenabled\nxivalexander\tdisabled\nact\tdisabled\n"
    );
    Ok(())
}

/// `status` states the trust sentence for each program whether or not the catalog can be read, and
/// with no catalog it says there is no row rather than inventing one.
#[test]
fn status_states_the_trust_sentence_for_every_program() -> std::io::Result<()> {
    let home = with_profile()?;
    for program in ["dalamud", "xivalexander", "act"] {
        let out = run(
            home.path(),
            &["program", "status", program, "--profile", "main"],
        )?;
        assert!(out.status.success(), "{out:?}");
        let text = stdout(&out);
        assert!(
            text.starts_with(&format!("{program} is disabled\n")),
            "{text}"
        );
        assert!(text.contains(&format!("trust: {TRUST}\n")), "{text}");
        assert!(
            text.contains("catalog: no row could be read for it"),
            "{text}"
        );
    }
    Ok(())
}

/// `profile edit` is the other way to flip a switch, and it is the user's own typed command too.
#[test]
fn profile_edit_turns_a_companion_on() -> std::io::Result<()> {
    let home = with_profile()?;
    let out = run(
        home.path(),
        &[
            "profile",
            "edit",
            "--profile",
            "main",
            "--xivalexander",
            "true",
        ],
    )?;
    assert!(out.status.success(), "{out:?}");
    let out = run(home.path(), &["program", "list", "--profile", "main"])?;
    assert!(
        stdout(&out).contains("xivalexander\tenabled"),
        "{}",
        stdout(&out)
    );
    Ok(())
}

/// A program name the launcher does not know is refused before anything is written.
#[test]
fn an_unknown_program_is_refused() -> std::io::Result<()> {
    let home = with_profile()?;
    let out = run(
        home.path(),
        &["program", "enable", "overlayplugin", "--profile", "main"],
    )?;
    assert!(!out.status.success());
    Ok(())
}

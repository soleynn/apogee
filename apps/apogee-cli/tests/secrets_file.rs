//! The sealed secret file, driven through the binary.
//!
//! Offline by construction: every verb here reads and writes the store and the file beside it, and
//! nothing else. The passphrase and the account password both come from the fixture environment, so
//! there is no terminal in the loop.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use tempfile::TempDir;

/// What the fixture build answers every passphrase prompt with.
const PASSPHRASE: &str = "correct horse battery staple";

fn run(home: &Path, passphrase: &str, typed: &str, args: &[&str]) -> std::io::Result<Output> {
    let mut child = Command::new(env!("CARGO_BIN_EXE_apogee-cli"))
        .args(args)
        .env("HOME", home)
        .env("XDG_CONFIG_HOME", home.join("config"))
        .env("XDG_DATA_HOME", home.join("data"))
        .env("XDG_CACHE_HOME", home.join("cache"))
        .env("APOGEE_FIXTURE_PASSPHRASE", passphrase)
        // Only so the account password prompt is answered too. The scripted transport it also
        // installs is never reached: none of the verbs below talks to the network.
        .env("APOGEE_FIXTURE_LOGIN", "current")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    if let Some(stdin) = child.stdin.as_mut() {
        stdin.write_all(typed.as_bytes())?;
    }
    child.wait_with_output()
}

fn stdout(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn secrets_file(home: &Path) -> PathBuf {
    home.join("config").join("apogee").join("secrets.apsf")
}

/// A home with one profile in it, still on the platform store.
fn with_profile() -> std::io::Result<TempDir> {
    let home = TempDir::new()?;
    run(
        home.path(),
        PASSPHRASE,
        "",
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

/// The whole lifecycle in one run, because each step's precondition is the last step's result and
/// splitting them would mean re-driving the same four derivations per test.
#[test]
fn the_sealed_file_is_created_used_rotated_and_destroyed() -> std::io::Result<()> {
    let home = with_profile()?;
    let path = secrets_file(home.path());

    // Nothing is created until the word is typed, and the caveats are said out loud first.
    let out = run(
        home.path(),
        PASSPHRASE,
        "no\n",
        &["secrets", "backend", "--to", "file"],
    )?;
    assert!(out.status.success(), "{}", stdout(&out));
    assert!(stdout(&out).contains("weaker"), "{}", stdout(&out));
    assert!(!path.exists(), "a refused confirmation must create nothing");

    let out = run(
        home.path(),
        PASSPHRASE,
        "encrypt\n",
        &["secrets", "backend", "--to", "file"],
    )?;
    assert!(out.status.success(), "{}", stdout(&out));
    assert!(path.exists(), "{}", stdout(&out));

    // The status verb names the file and what is at it, without unlocking anything.
    let out = run(home.path(), PASSPHRASE, "", &["secrets", "status"])?;
    assert!(stdout(&out).contains("EncryptedFile"), "{}", stdout(&out));
    assert!(stdout(&out).contains("Sealed"), "{}", stdout(&out));

    // A save goes into the file, and the file is the only thing that changed.
    let before = std::fs::read(&path)?;
    let out = run(
        home.path(),
        PASSPHRASE,
        "",
        &["secrets", "save", "--profile", "main"],
    )?;
    assert!(out.status.success(), "{}", stdout(&out));
    let after = std::fs::read(&path)?;
    assert_ne!(before, after);
    assert_eq!(
        before.len(),
        after.len(),
        "the file's size must not track its contents"
    );

    // A rotation keeps what is in it and draws a fresh salt.
    let out = run(home.path(), PASSPHRASE, "", &["secrets", "passphrase"])?;
    assert!(out.status.success(), "{}", stdout(&out));
    let rotated = std::fs::read(&path)?;
    assert_ne!(
        rotated[20..36],
        after[20..36],
        "a rotation must draw a new salt"
    );

    let out = run(
        home.path(),
        PASSPHRASE,
        "",
        &["secrets", "forget", "--profile", "main"],
    )?;
    assert!(out.status.success(), "{}", stdout(&out));

    // The file cannot be destroyed while the launcher is still set to use it.
    let out = run(
        home.path(),
        PASSPHRASE,
        "destroy\n",
        &["secrets", "destroy-file"],
    )?;
    assert!(
        stdout(&out).contains("still set to use"),
        "{}",
        stdout(&out)
    );
    assert!(path.exists());

    run(
        home.path(),
        PASSPHRASE,
        "",
        &["secrets", "backend", "--to", "platform"],
    )?;
    let out = run(
        home.path(),
        PASSPHRASE,
        "destroy\n",
        &["secrets", "destroy-file"],
    )?;
    assert!(out.status.success(), "{}", stdout(&out));
    assert!(!path.exists(), "{}", stdout(&out));
    Ok(())
}

/// The choice survives a restart, which is the whole reason it is a setting rather than a flag.
#[test]
fn the_choice_is_remembered_and_shown() -> std::io::Result<()> {
    let home = with_profile()?;
    let out = run(home.path(), PASSPHRASE, "", &["settings", "show"])?;
    assert!(
        stdout(&out).contains("secret_backend      Platform"),
        "{}",
        stdout(&out)
    );

    run(
        home.path(),
        PASSPHRASE,
        "",
        &["secrets", "backend", "--to", "nothing"],
    )?;
    let out = run(home.path(), PASSPHRASE, "", &["settings", "show"])?;
    assert!(
        stdout(&out).contains("secret_backend      Nothing"),
        "{}",
        stdout(&out)
    );

    // And the store that keeps nothing refuses the save rather than losing it silently.
    let out = run(
        home.path(),
        PASSPHRASE,
        "",
        &["secrets", "save", "--profile", "main"],
    )?;
    assert!(!out.status.success());
    Ok(())
}

/// A mistyped passphrase and a damaged file must not look the same to a user: one is answered by
/// typing it again, the other by an offer that destroys what is stored.
#[test]
fn a_wrong_passphrase_reads_differently_from_a_damaged_file() -> std::io::Result<()> {
    let home = with_profile()?;
    let path = secrets_file(home.path());
    run(
        home.path(),
        PASSPHRASE,
        "encrypt\n",
        &["secrets", "backend", "--to", "file"],
    )?;
    run(
        home.path(),
        PASSPHRASE,
        "",
        &["secrets", "save", "--profile", "main"],
    )?;

    let out = run(
        home.path(),
        "not the passphrase",
        "",
        &["secrets", "save", "--profile", "main"],
    )?;
    assert!(!out.status.success());
    let wrong = String::from_utf8_lossy(&out.stderr).into_owned();
    assert!(wrong.contains("passphrase did not open"), "{wrong}");

    // Now damage the body rather than the key material, which the right passphrase still reaches.
    let mut sealed = std::fs::read(&path)?;
    let last = sealed.len() - 1;
    sealed[last] ^= 1;
    std::fs::write(&path, &sealed)?;
    let out = run(
        home.path(),
        PASSPHRASE,
        "",
        &["secrets", "save", "--profile", "main"],
    )?;
    assert!(!out.status.success());
    let damaged = String::from_utf8_lossy(&out.stderr).into_owned();
    assert!(damaged.contains("unreadable"), "{damaged}");
    assert_ne!(wrong, damaged);
    Ok(())
}

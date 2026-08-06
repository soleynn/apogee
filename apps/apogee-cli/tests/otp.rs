#![cfg(feature = "fixtures")]
//! Where a one-time code may enter this binary, driven through the binary.
//!
//! Offline: the login behind it is the scripted fixture transport, so the only thing under test is
//! how the code gets from the caller into the flow. The rule it holds to is that a live credential
//! never appears in `/proc/<pid>/cmdline`, which is world-readable with no `hidepid`.

use std::io::Write;
use std::path::Path;
use std::process::{Command, Output, Stdio};

use apogee_test_support::sandbox::build_game_install;
use tempfile::TempDir;

/// What the fixture build answers every passphrase prompt with, so the sealed store the secret goes
/// into needs no terminal.
const PASSPHRASE: &str = "correct horse battery staple";

/// Run the binary against `config` as its XDG root, feeding `typed` to stdin and closing it after.
fn run(config: &Path, typed: &str, args: &[&str]) -> std::io::Result<Output> {
    let mut child = Command::new(env!("CARGO_BIN_EXE_apogee-cli"))
        .args(args)
        .env("HOME", config)
        .env("XDG_CONFIG_HOME", config)
        .env("XDG_DATA_HOME", config.join("data"))
        .env("XDG_CACHE_HOME", config.join("cache"))
        // The canned password, so no prompt needs a terminal, and the scripted login behind it.
        .env("APOGEE_FIXTURE_LOGIN", "current")
        .env("APOGEE_FIXTURE_PASSPHRASE", PASSPHRASE)
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

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

/// A current install plus a profile whose account uses a one-time password.
fn with_otp_profile() -> std::io::Result<(TempDir, TempDir)> {
    // One expansion, because the scripted login reports a max expansion of one and a version report
    // that cannot answer for it fails the sanity check before registration.
    let install = build_game_install(
        "2024.03.28.0000.0000",
        [b"boot" as &[u8], b"boot64", b"launcher64", b"updater64"],
        "2024.03.28.0000.0000",
        &["2024.03.28.0001.0000"],
    )?;
    let config = TempDir::new()?;
    let out = run(
        config.path(),
        "",
        &[
            "profile",
            "add",
            "--name",
            "otp",
            "--user",
            "me@example.invalid",
            "--otp",
            "--game-path",
            install.path().to_str().unwrap_or_default(),
        ],
    )?;
    assert!(out.status.success(), "profile add: {}", stderr(&out));
    Ok((config, install))
}

/// Whether a session was cached, which only happens past a completed login.
fn session_cached(config: &Path) -> bool {
    let dir = config.join("apogee").join("uid-cache");
    std::fs::read_dir(dir).is_ok_and(|mut entries| entries.next().is_some())
}

/// The code arrives on stdin. Nothing else may carry it: an argument is readable out of
/// `/proc/<pid>/cmdline` by any local user for as long as the run lasts.
#[test]
fn a_one_time_code_is_read_from_stdin() -> std::io::Result<()> {
    let (config, _install) = with_otp_profile()?;

    let out = run(config.path(), "123456\n", &["patch", "--profile", "otp"])?;
    assert!(out.status.success(), "patch: {}", stdout(&out));
    assert!(
        !stdout(&out).contains("NeedsOtp"),
        "the code on stdin was not used: {}",
        stdout(&out)
    );
    assert!(
        session_cached(config.path()),
        "the login did not complete: {}",
        stdout(&out)
    );
    Ok(())
}

/// The other half of the same pin: with nothing on stdin the account is still gated, so the run
/// above got through because of what was typed and not because the gate is open.
#[test]
fn an_account_that_uses_one_is_gated_when_stdin_is_empty() -> std::io::Result<()> {
    let (config, _install) = with_otp_profile()?;

    let out = run(config.path(), "", &["patch", "--profile", "otp"])?;
    assert!(out.status.success(), "patch: {}", stdout(&out));
    assert!(
        stdout(&out).contains("NeedsOtp"),
        "expected the one-time-password gate: {}",
        stdout(&out)
    );
    assert!(
        !session_cached(config.path()),
        "a gated login must cache nothing"
    );
    Ok(())
}

/// There is no `--otp` on a flow that logs in, and there must not be one again: the value would sit
/// in this process's `cmdline` for the length of the run, world-readable.
#[test]
fn no_flow_that_logs_in_accepts_a_code_as_an_argument() -> std::io::Result<()> {
    let (config, _install) = with_otp_profile()?;

    for verb in ["login", "play", "patch", "install"] {
        let out = run(
            config.path(),
            "",
            &[verb, "--profile", "otp", "--otp", "123456"],
        )?;
        assert!(
            !out.status.success(),
            "{verb} accepted a code as an argument: {}",
            stdout(&out)
        );
        assert!(
            stderr(&out).contains("unexpected argument '--otp'"),
            "{verb} did not reject --otp: {}",
            stderr(&out)
        );
    }
    Ok(())
}

/// The example key from the format's own documentation, doubled to reach the length a key has to be.
/// Synthetic, and the only secret these tests offer.
const SEED: &str = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP";

/// A home whose secrets go into the sealed file rather than into whatever keyring the machine
/// running this has. Nothing here may touch a developer's login keyring or raise its unlock dialog.
fn on_the_sealed_store(config: &Path) -> std::io::Result<()> {
    let out = run(config, "encrypt\n", &["secrets", "backend", "--to", "file"])?;
    assert!(out.status.success(), "backend: {}", stderr(&out));
    Ok(())
}

/// The shared secret is worse to leak than a code, which expires in half a minute, so it takes the
/// same route: stdin, never an argument that sits in a world-readable `cmdline` for the whole run.
#[test]
fn a_shared_secret_is_read_from_stdin_and_never_taken_as_an_argument() -> std::io::Result<()> {
    let (config, _install) = with_otp_profile()?;
    on_the_sealed_store(config.path())?;

    let out = run(
        config.path(),
        "",
        &["secrets", "totp", "--profile", "otp", "--secret", SEED],
    )?;
    assert!(!out.status.success(), "{}", stdout(&out));
    assert!(
        stderr(&out).contains("unexpected argument '--secret'"),
        "{}",
        stderr(&out)
    );

    let out = run(
        config.path(),
        &format!("{SEED}\n"),
        &["secrets", "totp", "--profile", "otp"],
    )?;
    assert!(out.status.success(), "totp: {}", stderr(&out));
    assert!(
        !stdout(&out).contains("JBSWY3DP"),
        "the secret was echoed back: {}",
        stdout(&out)
    );
    assert!(
        stdout(&out).contains("saved the one-time-password secret"),
        "{}",
        stdout(&out)
    );
    Ok(())
}

/// The zero-interaction login: once a secret is stored the account is never asked for a code, and
/// nothing on stdin is what proves it.
#[test]
fn an_account_that_generates_its_own_code_is_never_prompted() -> std::io::Result<()> {
    let (config, _install) = with_otp_profile()?;
    on_the_sealed_store(config.path())?;
    let out = run(
        config.path(),
        &format!("{SEED}\n"),
        &["secrets", "totp", "--profile", "otp"],
    )?;
    assert!(out.status.success(), "totp: {}", stderr(&out));

    let out = run(config.path(), "", &["patch", "--profile", "otp"])?;
    assert!(out.status.success(), "patch: {}", stdout(&out));
    assert!(
        !stdout(&out).contains("NeedsOtp"),
        "the stored secret was not used: {}",
        stdout(&out)
    );
    assert!(
        !stdout(&out).contains("One-time password:"),
        "a generating account was still prompted: {}",
        stdout(&out)
    );
    assert!(
        session_cached(config.path()),
        "the login did not complete: {}",
        stdout(&out)
    );
    Ok(())
}

/// A secret whose parameters the login server will not take is stored anyway and said out loud. The
/// alternative, rewriting it to what would be accepted, is wrong codes with nothing said.
#[test]
fn a_secret_the_login_server_will_not_take_is_reported() -> std::io::Result<()> {
    let (config, _install) = with_otp_profile()?;
    on_the_sealed_store(config.path())?;

    let offered = format!("otpauth://totp/Example:me?secret={SEED}&digits=8&period=60");
    let out = run(
        config.path(),
        &format!("{offered}\n"),
        &["secrets", "totp", "--profile", "otp"],
    )?;

    assert!(out.status.success(), "totp: {}", stderr(&out));
    let printed = stdout(&out);
    assert!(printed.contains("8-digit codes"), "{printed}");
    assert!(printed.contains("every 60 seconds"), "{printed}");
    // Both halves of each comparison come from the core, so what counts as accepted is never a
    // literal this side has to keep in step.
    assert!(printed.contains("only takes 6"), "{printed}");
    assert!(printed.contains("expects 30"), "{printed}");
    assert!(!printed.contains("JBSWY3DP"), "{printed}");
    Ok(())
}

/// Forgetting the stored secret puts the account back to being asked for a code.
///
/// The setting that says a code is derived is written when a secret is imported, so an account left
/// on it with nothing stored is one this side never prompts and the flow can never satisfy: told a
/// code is needed, never asked for one, and a code piped in ignored. The sweep is the verb that has
/// to undo it, because it is the verb that takes the secret away.
#[test]
fn forgetting_the_secret_asks_for_a_code_again() -> std::io::Result<()> {
    let (config, _install) = with_otp_profile()?;
    on_the_sealed_store(config.path())?;
    let out = run(
        config.path(),
        &format!("{SEED}\n"),
        &["secrets", "totp", "--profile", "otp"],
    )?;
    assert!(out.status.success(), "totp: {}", stderr(&out));

    let out = run(
        config.path(),
        "",
        &["secrets", "forget", "--profile", "otp"],
    )?;
    assert!(out.status.success(), "forget: {}", stderr(&out));

    let out = run(config.path(), "123456\n", &["patch", "--profile", "otp"])?;
    assert!(out.status.success(), "patch: {}", stdout(&out));
    assert!(
        stdout(&out).contains("One-time password:"),
        "the account was never asked for a code: {}",
        stdout(&out)
    );
    assert!(
        !stdout(&out).contains("NeedsOtp"),
        "the code on stdin was ignored: {}",
        stdout(&out)
    );
    assert!(
        session_cached(config.path()),
        "the login did not complete: {}",
        stdout(&out)
    );
    Ok(())
}

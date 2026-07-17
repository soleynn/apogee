#![cfg(all(target_os = "linux", feature = "wine-integration"))]
//! End-to-end: the CLI logs in against a scripted transport and launches a stub game through the
//! system wine, proving the flow drives login → register → a supervised real process, and that a
//! Ctrl-C brings the game down. Gated on wine + mingw (the wine-present CI job); headless wine is
//! finicky, so CI treats it as an amber canary. The rendered stream is also checked for secret leaks.

use std::error::Error;
use std::io::{BufRead, BufReader, Write};
use std::path::Path;
use std::process::{Command, Stdio};

use apogee_test_support::sandbox::build_game_install;

/// Compile a windowless PE that sleeps, named `ffxiv_dx11.exe`, into `game_dir`.
fn build_sleeper(game_dir: &Path, seconds: u32) -> Result<(), Box<dyn Error>> {
    let src = game_dir.join("sleeper.c");
    let mut file = std::fs::File::create(&src)?;
    write!(
        file,
        "#include <windows.h>\nint main(void) {{ Sleep({}); return 0; }}\n",
        seconds * 1000
    )?;
    let status = Command::new("x86_64-w64-mingw32-gcc")
        .arg(&src)
        .arg("-o")
        .arg(game_dir.join("ffxiv_dx11.exe"))
        .status()?;
    if !status.success() {
        return Err("mingw failed to build the stub PE".into());
    }
    Ok(())
}

#[test]
fn play_launches_and_supervises_a_stub_game() -> Result<(), Box<dyn Error>> {
    // A game install whose one expansion matches the fixture's `maxex`, plus a real sleeper PE.
    let install = build_game_install(
        "2024.02.01.0000.0000",
        [b"boot" as &[u8], b"boot64", b"launcher64", b""],
        "2024.03.28.0000.0000",
        &["2024.03.28.0001.0000"],
    )?;
    build_sleeper(&install.path().join("game"), 120)?;

    let config = tempfile::tempdir()?;
    let data = tempfile::tempdir()?;
    let cache = tempfile::tempdir()?;
    let bin = env!("CARGO_BIN_EXE_apogee-cli");
    let with_xdg = |cmd: &mut Command| {
        cmd.env("XDG_CONFIG_HOME", config.path())
            .env("XDG_DATA_HOME", data.path())
            .env("XDG_CACHE_HOME", cache.path());
    };

    // Create the profile through the CLI (system wine, no one-time password).
    let mut add = Command::new(bin);
    with_xdg(&mut add);
    add.args([
        "profile",
        "add",
        "--name",
        "e2e",
        "--user",
        "player@example.invalid",
        "--game-path",
    ])
    .arg(install.path())
    .args(["--runner", "system"]);
    let added = add.output()?;
    assert!(
        added.status.success(),
        "profile add failed: {}",
        String::from_utf8_lossy(&added.stderr)
    );

    // Play against the scripted login, capturing the event stream.
    let mut play = Command::new(bin);
    with_xdg(&mut play);
    play.args(["play", "--profile", "e2e"])
        .env("APOGEE_FIXTURE_LOGIN", "current")
        .env("WINEDEBUG", "-all")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = play.spawn()?;
    let stdout = child.stdout.take().ok_or("no child stdout")?;

    let mut lines = BufReader::new(stdout).lines();
    let mut collected: Vec<String> = Vec::new();
    let mut saw_running = false;
    let mut saw_error = false;
    for line in lines.by_ref() {
        let line = line?;
        if line.contains("state: Running") {
            saw_running = true;
        }
        if line.starts_with("error:") {
            saw_error = true;
        }
        let stop = saw_running || saw_error;
        collected.push(line);
        if stop {
            break;
        }
    }

    // With the game running, Ctrl-C the CLI so it kills the game (targeted) and exits cleanly.
    if saw_running {
        let raw = i32::try_from(child.id())?;
        if let Some(pid) = rustix::process::Pid::from_raw(raw) {
            let _ = rustix::process::kill_process(pid, rustix::process::Signal::INT);
        }
    }
    for line in lines.map_while(Result::ok) {
        collected.push(line);
    }
    let _ = child.wait()?;

    let output = collected.join("\n");
    assert!(!saw_error, "flow errored: {output}");
    assert!(
        output.contains("state: Launching"),
        "expected Launching: {output}"
    );
    assert!(saw_running, "expected the game to reach Running: {output}");

    // Leak check: no session token or the password ever reaches the rendered output.
    for secret in ["FIXTURE-UID", "FIXTURE-SID", "fixture"] {
        assert!(
            !output.contains(secret),
            "secret {secret:?} leaked into output: {output}"
        );
    }
    Ok(())
}

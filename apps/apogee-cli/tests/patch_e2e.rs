#![cfg(all(target_os = "linux", feature = "fixtures"))]
//! Hermetic patch e2e: the `apogee-cli patch` command drives a real download-and-apply of a game
//! patch served by the chaos server, over a scripted login. `patch` never launches, so this needs no
//! wine and runs every push (unlike the wine-gated launch e2e). It proves the CLI → core → patcher →
//! fetch wiring end to end at the process level, and that no session credential leaks into the output.
//!
//! The patch bytes come from `apogee_zipatch::fixtures` (one owner of the format, no Square Enix
//! bytes); its per-block SHA1 stands in for a real game patchlist's hashes.

use std::error::Error;

use apogee_test_support::chaos::ChaosServer;
use apogee_test_support::sandbox::build_game_install;
use apogee_zipatch::fixtures;
use sha1::{Digest, Sha1};

/// The per-block hash width the synthetic patchlist advertises (small, so a patch spans many blocks).
const BLOCK_SIZE: usize = 64;

/// Per-block lowercase-hex SHA1 over `bytes`, the game-patchlist hash shape.
fn block_sha1_hex(bytes: &[u8]) -> Vec<String> {
    bytes
        .chunks(BLOCK_SIZE)
        .map(|block| {
            Sha1::digest(block)
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        })
        .collect()
}

/// A nine-field game patchlist entry over `bytes`, pointing at `url`, targeting `version`.
fn game_entry(url: &str, bytes: &[u8], version: &str) -> String {
    let hashes = block_sha1_hex(bytes).join(",");
    format!(
        "{}\t0\t0\t0\tD{version}\tsha1\t{BLOCK_SIZE}\t{hashes}\t{url}",
        bytes.len()
    )
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn patch_downloads_and_applies_a_game_patch_over_the_chaos_server()
-> Result<(), Box<dyn Error>> {
    // A real game patch served by the chaos server, and its patchlist entry with matching hashes.
    let patch = fixtures::patch_a();
    let version = "2024.03.28.0001.0000";
    let server = ChaosServer::serving(patch.clone()).start().await?;
    let url = server.url(&format!("game/4e9a232b/D{version}.patch"));
    let entry = game_entry(url.as_str(), &patch, version);

    // The CLI's fixture transport reads the pending patchlist entry from this file.
    let entry_file = tempfile::NamedTempFile::new()?;
    std::fs::write(entry_file.path(), &entry)?;

    // An outdated install (boot + game present, no expansions), plus fresh XDG roots.
    let install = build_game_install(
        "2024.02.01.0000.0000",
        [b"boot" as &[u8], b"boot64", b"launcher64", b"updater64"],
        "2024.03.28.0000.0000",
        &[],
    )?;
    let config = tempfile::tempdir()?;
    let data = tempfile::tempdir()?;
    let cache = tempfile::tempdir()?;
    let bin = env!("CARGO_BIN_EXE_apogee-cli");
    let with_xdg = |cmd: &mut tokio::process::Command| {
        cmd.env("XDG_CONFIG_HOME", config.path())
            .env("XDG_DATA_HOME", data.path())
            .env("XDG_CACHE_HOME", cache.path());
    };

    // Create the profile (system wine, no one-time password).
    let mut add = tokio::process::Command::new(bin);
    with_xdg(&mut add);
    add.args([
        "profile",
        "add",
        "--name",
        "patchtest",
        "--user",
        "player@example.invalid",
        "--game-path",
    ])
    .arg(install.path())
    .args(["--runner", "system"]);
    let added = add.output().await?;
    assert!(
        added.status.success(),
        "profile add failed: {}",
        String::from_utf8_lossy(&added.stderr)
    );

    // Patch against the scripted login and the chaos-served patch.
    let mut patch_cmd = tokio::process::Command::new(bin);
    with_xdg(&mut patch_cmd);
    patch_cmd
        .args(["patch", "--profile", "patchtest"])
        .env("APOGEE_FIXTURE_LOGIN", "patch")
        .env("APOGEE_FIXTURE_PATCH_ENTRY", entry_file.path())
        .env("APOGEE_FIXTURE_MAXEX", "0");
    let out = patch_cmd.output().await?;
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "patch failed:\nstdout={stdout}\nstderr={stderr}"
    );

    // The flow announced patching and applied the game patch.
    assert!(
        stdout.contains("state: Patching"),
        "expected Patching: {stdout}"
    );
    assert!(
        stdout.contains("applied"),
        "expected an applied frame: {stdout}"
    );

    // The patch's dat landed under game/, and the game `.ver` advanced to the applied version.
    let applied = install.path().join("game").join(fixtures::DAT0_PATH);
    assert!(
        applied.is_file(),
        "patch dat written: {}",
        applied.display()
    );
    let ver = std::fs::read_to_string(install.path().join("game/ffxivgame.ver"))?;
    assert_eq!(ver.trim(), version, "game .ver advanced");

    // Leak check: the session token never reaches the rendered output.
    for secret in ["FIXTURE-UID", "FIXTURE-SID"] {
        assert!(!stdout.contains(secret), "secret {secret} leaked: {stdout}");
    }
    Ok(())
}

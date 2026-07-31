//! The launcher's preferences and a profile's launch tuning, through the binary. Offline by
//! construction: both read and write the store and nothing else.

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

/// Keeping the patch files costs disk and buys a repair that rebuilds broken ranges from them
/// instead of downloading again. It ships on, so the cost has to be visible and reversible.
#[test]
fn the_patch_cache_ships_on_and_can_be_turned_off() -> std::io::Result<()> {
    let home = with_profile()?;

    let out = run(home.path(), &["settings", "show"])?;
    assert!(out.status.success());
    assert!(
        stdout(&out).contains("keep_patches        true"),
        "{}",
        stdout(&out)
    );

    run(home.path(), &["settings", "set", "--keep-patches", "false"])?;
    let out = run(home.path(), &["settings", "show"])?;
    assert!(
        stdout(&out).contains("keep_patches        false"),
        "{}",
        stdout(&out)
    );
    Ok(())
}

/// Only what is named changes, so setting one preference does not quietly reset the others.
#[test]
fn setting_one_preference_leaves_the_rest_alone() -> std::io::Result<()> {
    let home = with_profile()?;
    run(
        home.path(),
        &[
            "settings",
            "set",
            "--backups-kept",
            "9",
            "--keep-patches",
            "false",
        ],
    )?;
    run(
        home.path(),
        &["settings", "set", "--close-after-launch", "true"],
    )?;

    let text = stdout(&run(home.path(), &["settings", "show"])?);
    assert!(text.contains("backups_kept        9"), "{text}");
    assert!(text.contains("keep_patches        false"), "{text}");
    assert!(text.contains("close_after_launch  true"), "{text}");
    Ok(())
}

/// A profile starts with nothing chosen, so every knob resolves against the host and the runner at
/// launch time rather than against a value written on its behalf.
#[test]
fn a_new_profile_chooses_nothing_and_round_trips_what_it_is_given() -> std::io::Result<()> {
    let home = with_profile()?;

    let text = stdout(&run(home.path(), &["profile", "env", "--profile", "main"])?);
    assert!(text.contains("sync      auto"), "{text}");
    assert!(text.contains("hud       none"), "{text}");
    assert!(text.contains("gpu       default"), "{text}");
    assert!(text.contains("gamemode  false"), "{text}");

    run(
        home.path(),
        &[
            "profile",
            "env",
            "--profile",
            "main",
            "--sync",
            "esync",
            "--hud",
            "dxvk:fps",
            "--gpu",
            "vulkan:10de:2482",
            "--gamemode",
            "true",
        ],
    )?;
    let text = stdout(&run(home.path(), &["profile", "env", "--profile", "main"])?);
    assert!(text.contains("sync      esync"), "{text}");
    assert!(text.contains("hud       dxvk:fps"), "{text}");
    assert!(text.contains("gpu       vulkan:10de:2482"), "{text}");
    assert!(text.contains("gamemode  true"), "{text}");
    Ok(())
}

/// A value the launcher does not understand is refused rather than stored, so a typo does not become
/// a launch that quietly ignores it.
#[test]
fn an_unknown_value_is_refused_and_nothing_is_written() -> std::io::Result<()> {
    let home = with_profile()?;
    for bad in [
        ["--sync", "nope"],
        ["--hud", "dxvk:"],
        ["--gpu", "vulkan:"],
        ["--gpu", "amd"],
    ] {
        let out = run(
            home.path(),
            &["profile", "env", "--profile", "main", bad[0], bad[1]],
        )?;
        assert!(!out.status.success(), "{bad:?} was accepted");
    }

    let text = stdout(&run(home.path(), &["profile", "env", "--profile", "main"])?);
    assert!(
        text.contains("sync      auto"),
        "nothing was stored: {text}"
    );
    Ok(())
}

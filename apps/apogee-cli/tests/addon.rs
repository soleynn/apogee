//! `addon` command group: hermetic, no network, no wine. Spawns the built binary, so it exercises
//! arg parsing, the profile round trip, and the rendered list end to end.

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

/// Build a UTF-8 command-line path that is absolute on the host running the test.
fn absolute_arg(base: &Path, relative: &str) -> String {
    let path = base.join(relative);
    assert!(path.is_absolute(), "test fixture path must be absolute");
    path.to_string_lossy().into_owned()
}

/// Create a profile to hang tools off.
fn profile(home: &Path) -> std::io::Result<()> {
    let game_path = absolute_arg(home, "game");
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
            &game_path,
        ],
    )?;
    assert!(out.status.success(), "profile add failed: {}", stdout(&out));
    Ok(())
}

/// The round trip: a tool added from the command line is listed back, and survives a separate
/// invocation, which is what proves it was persisted rather than held in memory.
#[test]
fn a_tool_is_added_listed_and_persisted() -> std::io::Result<()> {
    let home = tempdir()?;
    profile(home.path())?;
    let program = absolute_arg(home.path(), "tools/act/act.sh");
    let config = absolute_arg(home.path(), "config/act.json");

    let out = run(
        home.path(),
        &[
            "addon",
            "add",
            "--profile",
            "main",
            "--program",
            &program,
            "--arg",
            "--config",
            "--arg",
            &config,
            "--trigger",
            "with-game",
        ],
    )?;
    assert!(out.status.success(), "add failed: {}", stdout(&out));

    let listed = run(home.path(), &["addon", "list", "--profile", "main"])?;
    let text = stdout(&listed);
    assert!(listed.status.success(), "list failed: {text}");
    assert!(text.contains(&program), "missing tool:\n{text}");
    assert!(text.contains("with-game"), "missing trigger:\n{text}");
    assert!(text.contains("host"), "missing location:\n{text}");
    Ok(())
}

/// A relative program is refused at the edge, because it would resolve against whatever directory
/// the launcher happened to start in.
#[test]
fn a_relative_program_is_refused() -> std::io::Result<()> {
    let home = tempdir()?;
    profile(home.path())?;

    let out = run(
        home.path(),
        &[
            "addon",
            "add",
            "--profile",
            "main",
            "--program",
            "tools/act.sh",
        ],
    )?;
    assert!(!out.status.success(), "a relative path was accepted");
    let listed = run(home.path(), &["addon", "list", "--profile", "main"])?;
    assert!(stdout(&listed).contains("no tools configured"));
    Ok(())
}

/// The trigger values are total over the library's states, so the combination that would start a
/// tool and immediately kill it cannot be expressed here either.
#[test]
fn the_trigger_values_cover_the_library_and_nothing_else() -> std::io::Result<()> {
    let home = tempdir()?;
    profile(home.path())?;
    let program = absolute_arg(home.path(), "tools/tool.sh");

    for trigger in ["with-game", "with-game-keep-running", "on-close"] {
        let out = run(
            home.path(),
            &[
                "addon",
                "add",
                "--profile",
                "main",
                "--program",
                &program,
                "--trigger",
                trigger,
            ],
        )?;
        assert!(out.status.success(), "{trigger} rejected: {}", stdout(&out));
    }

    let out = run(
        home.path(),
        &[
            "addon",
            "add",
            "--profile",
            "main",
            "--program",
            &program,
            "--trigger",
            "kill-after-close",
        ],
    )?;
    assert!(!out.status.success(), "an invented trigger was accepted");

    let listed = stdout(&run(home.path(), &["addon", "list", "--profile", "main"])?);
    assert!(listed.contains("with-game-keep-running"));
    assert!(listed.contains("on-close"));
    Ok(())
}

/// Disabling keeps the entry, so turning a tool off does not discard how it was configured.
#[test]
fn disabling_keeps_the_entry_and_enabling_restores_it() -> std::io::Result<()> {
    let home = tempdir()?;
    profile(home.path())?;
    let program = absolute_arg(home.path(), "tools/act/act.sh");
    run(
        home.path(),
        &["addon", "add", "--profile", "main", "--program", &program],
    )?;

    let out = run(
        home.path(),
        &["addon", "disable", "--profile", "main", "--index", "0"],
    )?;
    assert!(out.status.success(), "disable failed: {}", stdout(&out));
    let listed = stdout(&run(home.path(), &["addon", "list", "--profile", "main"])?);
    assert!(listed.contains("(disabled)"), "not marked:\n{listed}");
    assert!(listed.contains(&program), "entry lost:\n{listed}");

    run(
        home.path(),
        &["addon", "enable", "--profile", "main", "--index", "0"],
    )?;
    let listed = stdout(&run(home.path(), &["addon", "list", "--profile", "main"])?);
    assert!(!listed.contains("(disabled)"), "still disabled:\n{listed}");
    Ok(())
}

/// Removing takes the named entry and leaves the rest in order.
#[test]
fn removing_takes_only_the_named_entry() -> std::io::Result<()> {
    let home = tempdir()?;
    profile(home.path())?;
    for program in [
        absolute_arg(home.path(), "tools/one.sh"),
        absolute_arg(home.path(), "tools/two.sh"),
        absolute_arg(home.path(), "tools/three.sh"),
    ] {
        run(
            home.path(),
            &["addon", "add", "--profile", "main", "--program", &program],
        )?;
    }

    let out = run(
        home.path(),
        &["addon", "remove", "--profile", "main", "--index", "1"],
    )?;
    assert!(out.status.success(), "remove failed: {}", stdout(&out));

    let listed = stdout(&run(home.path(), &["addon", "list", "--profile", "main"])?);
    assert!(listed.contains("one.sh"));
    assert!(
        !listed.contains("two.sh"),
        "wrong entry survived:\n{listed}"
    );
    assert!(listed.contains("three.sh"));
    Ok(())
}

/// An index that names nothing says so rather than silently doing nothing.
#[test]
fn an_index_out_of_range_is_an_error() -> std::io::Result<()> {
    let home = tempdir()?;
    profile(home.path())?;

    let out = run(
        home.path(),
        &["addon", "remove", "--profile", "main", "--index", "7"],
    )?;
    assert!(!out.status.success(), "an absent index was accepted");
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("no tool at index 7"),
        "unhelpful message: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    Ok(())
}

/// A profile written by a build that predates companion tools still loads, gaining an empty list.
#[test]
fn a_profile_from_before_companion_tools_still_loads() -> std::io::Result<()> {
    let home = tempdir()?;
    profile(home.path())?;
    let program = absolute_arg(home.path(), "tools/act/act.sh");

    // Rewrite the stored profile as the older schema: version 1, and no `external` key at all.
    let dir = home.path().join("config/apogee/profiles");
    let file = std::fs::read_dir(&dir)?
        .filter_map(Result::ok)
        .map(|e| e.path())
        .find(|p| p.extension().is_some_and(|e| e == "json"))
        .expect("a stored profile");
    let mut doc: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(&file)?)?;
    doc["schema_version"] = serde_json::json!(1);
    doc["data"]
        .as_object_mut()
        .expect("a profile object")
        .remove("external");
    std::fs::write(&file, serde_json::to_string_pretty(&doc)?)?;

    let listed = run(home.path(), &["addon", "list", "--profile", "main"])?;
    let text = stdout(&listed);
    assert!(
        listed.status.success(),
        "the old profile failed to load: {text}"
    );
    assert!(text.contains("no tools configured"), "unexpected: {text}");

    // And it is usable afterwards, so the migration wrote a real list rather than a stopgap.
    let out = run(
        home.path(),
        &["addon", "add", "--profile", "main", "--program", &program],
    )?;
    assert!(
        out.status.success(),
        "add failed after migration: {}",
        stdout(&out)
    );
    Ok(())
}

/// The store names the programs the launcher runs, so it must never resolve against whatever
/// directory the launcher happened to start in. With no home and no base directory set, there is no
/// answer, and inventing a relative one would mean running whatever sits beside the working
/// directory.
#[test]
fn a_launcher_with_no_home_refuses_rather_than_using_the_working_directory() -> std::io::Result<()>
{
    let work = tempdir()?;
    // A profile store planted where a relative resolution would land.
    std::fs::create_dir_all(work.path().join(".config/apogee/profiles"))?;

    let out = Command::new(env!("CARGO_BIN_EXE_apogee-cli"))
        .current_dir(work.path())
        .env_remove("HOME")
        .env_remove("XDG_CONFIG_HOME")
        .env_remove("XDG_DATA_HOME")
        .env_remove("XDG_CACHE_HOME")
        .env_remove("APPDATA")
        .env_remove("LOCALAPPDATA")
        .args(["addon", "list", "--profile", "main"])
        .output()?;

    assert!(!out.status.success(), "a relative store was accepted");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("XDG_CONFIG_HOME") || stderr.contains("home directory"),
        "unhelpful message: {stderr}"
    );
    Ok(())
}

/// A normal Windows process has native application-data directories but no `HOME` or XDG
/// variables. That environment must be sufficient to start the CLI, and explicit test paths keep
/// this check out of the developer's real profile.
#[cfg(windows)]
#[test]
fn windows_application_data_resolves_without_xdg_or_home() -> std::io::Result<()> {
    let root = tempdir()?;
    let roaming = root.path().join("roaming");
    let local = root.path().join("local");

    let out = Command::new(env!("CARGO_BIN_EXE_apogee-cli"))
        .env_remove("HOME")
        .env_remove("XDG_CONFIG_HOME")
        .env_remove("XDG_DATA_HOME")
        .env_remove("XDG_CACHE_HOME")
        .env("APPDATA", &roaming)
        .env("LOCALAPPDATA", &local)
        .args(["profile", "list"])
        .output()?;

    assert!(
        out.status.success(),
        "native Windows directories were refused: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        roaming.join("apogee").is_dir(),
        "the profile store did not use APPDATA"
    );
    Ok(())
}

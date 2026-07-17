#![cfg(target_os = "linux")]
//! Hermetic `/proc` supervision: drive the public launch path through a custom runner that wraps a
//! stub renamed `ffxiv_dx11.exe`. No wine — this proves the scanner resolves the game by `comm` and
//! `WINEPREFIX`, distinguishes prefixes, and kills the right process. The real-wine proof lives in
//! `supervise_wine` (feature-gated).

use std::collections::BTreeMap;
use std::error::Error;
use std::io;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use apogee_fetch::Fetcher;
use apogee_runtime::{GameSession, LaunchPlan, Progress, RunnerKind, Runtime, RuntimePaths};
use serial_test::serial;
use tokio_util::sync::CancellationToken;

fn runtime_over(root: &Path) -> Result<Runtime, Box<dyn Error>> {
    let fetcher = Fetcher::builder().build()?;
    Ok(Runtime::new(
        fetcher,
        RuntimePaths {
            runners: root.join("runners"),
            prefixes: root.join("prefixes"),
        },
    ))
}

/// Compile a native ELF that sleeps `seconds`, named `ffxiv_dx11.exe`, in `dir`. A copied system
/// `sleep` is unusable here: it is a coreutils multicall binary that dispatches on argv[0], so under
/// a different name it errors instead of sleeping. A C compiler is always present in a Rust build.
fn build_sleeper(dir: &Path, seconds: u32) -> Result<PathBuf, Box<dyn Error>> {
    let src = dir.join("sleeper.c");
    std::fs::write(
        &src,
        format!("#include <unistd.h>\nint main(void) {{ sleep({seconds}); return 0; }}\n"),
    )?;
    let exe = dir.join("ffxiv_dx11.exe");
    let cc = std::env::var("CC").unwrap_or_else(|_| "cc".to_owned());
    let status = std::process::Command::new(cc)
        .arg(&src)
        .arg("-o")
        .arg(&exe)
        .status()?;
    if !status.success() {
        return Err("cc failed to build the stub".into());
    }
    Ok(exe)
}

/// A custom runner directory whose `bin/wine` runs its argument (forking it as a child, so the game
/// is a grandchild of the launcher — as under real Proton).
fn custom_runner(dir: &Path) -> io::Result<()> {
    let bin = dir.join("bin");
    std::fs::create_dir_all(&bin)?;
    let wine = bin.join("wine");
    std::fs::write(&wine, b"#!/bin/sh\n\"$@\"\n")?;
    std::fs::set_permissions(&wine, std::fs::Permissions::from_mode(0o755))?;
    Ok(())
}

/// Prepare a custom runner + prefix under `root/<tag>` and launch a stub `ffxiv_dx11.exe` that sleeps
/// `seconds`. Returns the supervised session and the prefix directory.
async fn launch_stub(
    runtime: &Runtime,
    root: &Path,
    tag: &str,
    seconds: u32,
) -> Result<(GameSession, PathBuf), Box<dyn Error>> {
    let runner_dir = root.join(format!("runner-{tag}"));
    custom_runner(&runner_dir)?;
    let stub = build_sleeper(&runner_dir, seconds)?;

    let prefix_dir = root.join(format!("prefix-{tag}"));
    let prefix = runtime
        .prepare_custom(&runner_dir, RunnerKind::Custom, "stub", &prefix_dir)
        .await?;
    let plan = LaunchPlan::new(
        stub.to_string_lossy().into_owned(),
        String::new(),
        BTreeMap::new(),
    )
    .prefix(&prefix);
    let session = runtime
        .launch(plan, &CancellationToken::new(), &Progress::none())
        .await?;
    Ok((session, prefix_dir))
}

/// The `WINEPREFIX` of a running process, from `/proc/<pid>/environ`.
fn wineprefix_of(pid: i32) -> io::Result<Option<String>> {
    let environ = std::fs::read(format!("/proc/{pid}/environ"))?;
    Ok(environ
        .split(|&b| b == 0)
        .find_map(|e| e.strip_prefix(b"WINEPREFIX="))
        .map(|v| String::from_utf8_lossy(v).into_owned()))
}

fn proc_exists(pid: i32) -> bool {
    Path::new(&format!("/proc/{pid}")).exists()
}

#[tokio::test]
#[serial]
async fn launch_resolves_the_game_and_wait_returns_on_exit() {
    let root = tempfile::tempdir().expect("tempdir");
    let runtime = runtime_over(root.path()).expect("runtime");
    let (session, _prefix) = launch_stub(&runtime, root.path(), "wait", 1)
        .await
        .expect("launch");

    assert!(session.game_pid() > 1, "resolved a real pid");
    // The stub exits on its own after ~1s; wait must resolve.
    tokio::time::timeout(Duration::from_secs(10), session.wait())
        .await
        .expect("wait timed out")
        .expect("wait");
}

#[tokio::test]
#[serial]
async fn a_second_prefixs_game_is_not_matched() {
    let root = tempfile::tempdir().expect("tempdir");
    let runtime = runtime_over(root.path()).expect("runtime");
    // Start B first, then A: if the scanner matched by name alone it could return B's pid for A.
    let (session_b, _prefix_b) = launch_stub(&runtime, root.path(), "b", 30)
        .await
        .expect("launch b");
    let (session_a, prefix_a) = launch_stub(&runtime, root.path(), "a", 30)
        .await
        .expect("launch a");

    assert_ne!(
        session_a.game_pid(),
        session_b.game_pid(),
        "each launch resolves its own game"
    );
    let resolved = wineprefix_of(session_a.game_pid())
        .expect("read environ")
        .expect("game has WINEPREFIX");
    assert_eq!(
        Path::new(&resolved),
        prefix_a,
        "A resolved the game in A's prefix"
    );

    session_a.kill().await.expect("kill a");
    session_b.kill().await.expect("kill b");
}

#[tokio::test]
#[serial]
async fn targeted_kill_stops_the_game() {
    let root = tempfile::tempdir().expect("tempdir");
    let runtime = runtime_over(root.path()).expect("runtime");
    let (session, _prefix) = launch_stub(&runtime, root.path(), "kill", 30)
        .await
        .expect("launch");
    let pid = session.game_pid();
    assert!(proc_exists(pid), "game is running");

    session.kill().await.expect("kill");
    assert!(!proc_exists(pid), "targeted kill stopped the game");
}

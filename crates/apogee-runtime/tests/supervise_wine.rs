#![cfg(target_os = "linux")]
//! Real-wine supervision proof (feature `wine-integration`, run only in the wine-present CI job).
//!
//! The hermetic `supervise` test covers the scanner logic with a script runner; this one proves the
//! same path against **stock wine**: that wine sets `/proc/<pid>/comm` to the PE basename, that the
//! scanner resolves the game, that a targeted kill stops it, and that `kill_prefix` (`wineserver -k`)
//! is the separate broad stop. The stub is a tiny PE compiled with mingw at test time.

use std::collections::BTreeMap;
use std::error::Error;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use apogee_fetch::Fetcher;
use apogee_runtime::{LaunchPlan, Progress, RunnerKind, Runtime, RuntimePaths};
use serial_test::serial;
use tokio_util::sync::CancellationToken;

/// A custom runner whose `bin/wine`/`bin/wineserver` shell out to the host's wine on `PATH`, so the
/// exact install location need not be known.
fn wine_runner(dir: &Path) -> Result<(), Box<dyn Error>> {
    let bin = dir.join("bin");
    std::fs::create_dir_all(&bin)?;
    write_script(&bin.join("wine"), "#!/bin/sh\nexec wine \"$@\"\n")?;
    write_script(
        &bin.join("wineserver"),
        "#!/bin/sh\nexec wineserver \"$@\"\n",
    )?;
    Ok(())
}

fn write_script(path: &Path, body: &str) -> Result<(), Box<dyn Error>> {
    std::fs::write(path, body)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755))?;
    Ok(())
}

/// Compile a windowless PE that sleeps, named `ffxiv_dx11.exe`.
fn build_sleeper_pe(dir: &Path, seconds: u32) -> Result<PathBuf, Box<dyn Error>> {
    let src = dir.join("sleeper.c");
    let mut file = std::fs::File::create(&src)?;
    write!(
        file,
        "#include <windows.h>\nint main(void) {{ Sleep({}); return 0; }}\n",
        seconds * 1000
    )?;
    let exe = dir.join("ffxiv_dx11.exe");
    let status = std::process::Command::new("x86_64-w64-mingw32-gcc")
        .arg(&src)
        .arg("-o")
        .arg(&exe)
        .status()?;
    if !status.success() {
        return Err("mingw failed to build the stub PE".into());
    }
    Ok(exe)
}

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

async fn launch_sleeper(
    runtime: &Runtime,
    root: &Path,
    tag: &str,
    seconds: u32,
) -> Result<apogee_runtime::GameSession, Box<dyn Error>> {
    let runner_dir = root.join(format!("runner-{tag}"));
    wine_runner(&runner_dir)?;
    let game_dir = root.join(format!("game-{tag}"));
    std::fs::create_dir_all(&game_dir)?;
    let exe = build_sleeper_pe(&game_dir, seconds)?;

    let prefix_dir = root.join(format!("prefix-{tag}"));
    let prefix = runtime
        .prepare_custom(
            &runner_dir,
            RunnerKind::Wine,
            "wine",
            &prefix_dir,
            &CancellationToken::new(),
            &Progress::none(),
        )
        .await?;
    let plan = LaunchPlan::new(
        exe.to_string_lossy().into_owned(),
        String::new(),
        BTreeMap::new(),
    )
    .prefix(&prefix);
    let session = runtime
        .launch(plan, &CancellationToken::new(), &Progress::none())
        .await?;
    Ok(session)
}

fn proc_exists(pid: i32) -> bool {
    Path::new(&format!("/proc/{pid}")).exists()
}

/// Poll until `pid` disappears from `/proc`. A terminated game is a non-child, so its parent reaps
/// the zombie asynchronously; termination and the `/proc` entry clearing are not simultaneous.
async fn wait_gone(pid: i32) -> bool {
    for _ in 0..50 {
        if !proc_exists(pid) {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    false
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[serial]
async fn stock_wine_launch_is_resolved_and_killed() {
    let root = tempfile::tempdir().expect("tempdir");
    let runtime = runtime_over(root.path()).expect("runtime");
    let session = launch_sleeper(&runtime, root.path(), "k", 120)
        .await
        .expect("launch under wine");

    let pid = session.game_pid();
    assert!(proc_exists(pid), "wine resolved a live game process");
    session.kill().await.expect("targeted kill");
    assert!(wait_gone(pid).await, "targeted kill stopped the game");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[serial]
async fn kill_prefix_is_the_separate_broad_stop() {
    let root = tempfile::tempdir().expect("tempdir");
    let runtime = runtime_over(root.path()).expect("runtime");
    let session = launch_sleeper(&runtime, root.path(), "p", 120)
        .await
        .expect("launch under wine");
    let pid = session.game_pid();
    let prefix = session.prefix().clone();

    runtime.kill_prefix(&prefix).await.expect("wineserver -k");
    assert!(wait_gone(pid).await, "kill_prefix stopped the game");
}

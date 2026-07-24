#![cfg(target_os = "linux")]
//! Real-wine prefix lifecycle (feature `wine-integration`, run only in the wine-present CI job).
//!
//! The hermetic `prefix` test uses a fake wineboot; this one proves the same path against **stock
//! wine**: that `wineboot -i` produces a recorded `prefix.json`, that a deliberately broken prefix is
//! detected and targeted-fixed without a delete, and that in-process path translation round-trips
//! against the `winepath` oracle.

use std::error::Error;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::Command;

use apogee_fetch::Fetcher;
use apogee_runtime::{HealthIssue, Prefix, Progress, RunnerKind, Runtime, RuntimePaths};
use serial_test::serial;
use tokio_util::sync::CancellationToken;

/// A custom runner whose `bin/wine` shims to the host's wine on `PATH`.
fn wine_runner(dir: &Path) -> Result<(), Box<dyn Error>> {
    let bin = dir.join("bin");
    std::fs::create_dir_all(&bin)?;
    let wine = bin.join("wine");
    std::fs::write(&wine, "#!/bin/sh\nexec wine \"$@\"\n")?;
    std::fs::set_permissions(&wine, std::fs::Permissions::from_mode(0o755))?;
    Ok(())
}

fn runtime_over(root: &Path) -> Result<Runtime, Box<dyn Error>> {
    Ok(Runtime::new(
        Fetcher::builder().build()?,
        RuntimePaths {
            runners: root.join("runners"),
            prefixes: root.join("prefixes"),
        },
    ))
}

/// Prepare (and thus `wineboot -i`) a fresh prefix under `root` with stock wine.
async fn prepared(root: &Path) -> Result<(Runtime, Prefix), Box<dyn Error>> {
    let runtime = runtime_over(root)?;
    let runner_dir = root.join("runner");
    wine_runner(&runner_dir)?;
    let prefix = runtime
        .prepare_custom(
            &runner_dir,
            RunnerKind::Wine,
            "wine",
            &root.join("prefix"),
            &CancellationToken::new(),
            &Progress::none(),
        )
        .await?;
    Ok((runtime, prefix))
}

/// The `winepath` oracle: what stock wine says `flag` (`-w` or `-u`) maps `arg` to, in this prefix.
fn winepath(prefix: &Path, flag: &str, arg: &str) -> Result<String, Box<dyn Error>> {
    let out = Command::new("wine")
        .arg("winepath")
        .arg(flag)
        .arg(arg)
        .env("WINEPREFIX", prefix)
        .env("WINEDEBUG", "-all")
        .output()?;
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_owned())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[serial]
async fn wineboot_initializes_and_records_a_real_prefix() {
    let root = tempfile::tempdir().expect("tempdir");
    let (runtime, prefix) = prepared(root.path()).await.expect("prepare under wine");

    let meta = prefix
        .metadata()
        .expect("load")
        .expect("prefix.json present");
    assert_eq!(meta.runner.name, "wine");
    assert!(
        !meta.setup_history.is_empty(),
        "a wineboot step is recorded"
    );
    // wineboot laid down a real skeleton.
    assert!(prefix.path().join("system.reg").is_file());
    assert!(prefix.path().join("drive_c").is_dir());
    assert!(
        runtime
            .check_prefix(&prefix)
            .await
            .expect("check")
            .is_healthy(),
        "a fresh wineboot prefix is healthy"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[serial]
async fn a_broken_prefix_is_repaired_without_delete() {
    let root = tempfile::tempdir().expect("tempdir");
    let (runtime, prefix) = prepared(root.path()).await.expect("prepare under wine");

    // Break both a drive map and the registry skeleton.
    let z = prefix.path().join("dosdevices/z:");
    std::fs::remove_file(&z).expect("remove z:");
    std::fs::remove_file(prefix.path().join("system.reg")).expect("remove system.reg");
    // A user file that must survive the repair (proving no rm -rf).
    let keep = prefix.path().join("drive_c/keep.txt");
    std::fs::write(&keep, b"user data").expect("write keep");

    let health = runtime.check_prefix(&prefix).await.expect("check");
    assert!(
        health
            .issues
            .iter()
            .any(|i| matches!(i, HealthIssue::MissingSkeleton { .. })),
        "missing registry detected"
    );
    assert!(
        health
            .issues
            .iter()
            .any(|i| matches!(i, HealthIssue::DriveMapping { letter: 'z', .. })),
        "broken drive map detected"
    );

    let residual = runtime
        .repair_prefix(
            &prefix,
            &health.issues,
            &CancellationToken::new(),
            &Progress::none(),
        )
        .await
        .expect("repair under wine");
    assert!(residual.is_healthy(), "targeted fix restored the prefix");
    assert_eq!(
        std::fs::read(&keep).expect("keep survived"),
        b"user data",
        "repair kept user data (no rm -rf)"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[serial]
async fn path_round_trips_match_the_winepath_oracle() {
    let root = tempfile::tempdir().expect("tempdir");
    let (_runtime, prefix) = prepared(root.path()).await.expect("prepare under wine");
    let drives = prefix.drive_map().expect("drive map");

    // A Z:-mapped path below root (not under drive_c) exercises the longest-match choice between the
    // c: and z: drives; the drive-c path checks the other side of that choice.
    let drive_c = prefix.path().join("drive_c").canonicalize().expect("canon");
    let windows_dir = drive_c.join("windows");
    let z_probe = prefix.path().join("z_probe.txt");
    std::fs::write(&z_probe, b"x").expect("z_probe");
    let z_probe = z_probe.canonicalize().expect("canon z_probe");

    // unix -> windows against `winepath -w`.
    for unix in [Path::new("/"), windows_dir.as_path(), z_probe.as_path()] {
        let ours = drives.to_windows(unix).expect("to_windows");
        let oracle = winepath(prefix.path(), "-w", &unix.to_string_lossy()).expect("winepath -w");
        assert_eq!(ours, oracle, "to_windows({unix:?}) must match winepath -w");
    }

    // windows -> unix against `winepath -u`, including a `..`-bearing path (drive-root clamp) and a
    // trailing separator.
    for windows in ["C:\\windows", "Z:\\", "C:\\..\\windows", "C:\\windows\\"] {
        let ours = drives.to_unix(windows).expect("to_unix");
        let oracle = winepath(prefix.path(), "-u", windows).expect("winepath -u");
        let ours = ours.canonicalize().unwrap_or(ours);
        let oracle_path = Path::new(&oracle);
        let oracle = oracle_path
            .canonicalize()
            .unwrap_or_else(|_| oracle_path.to_path_buf());
        assert_eq!(ours, oracle, "to_unix({windows}) must match winepath -u");
    }
}

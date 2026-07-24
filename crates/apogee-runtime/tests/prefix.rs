#![cfg(target_os = "linux")]
//! Hermetic prefix-lifecycle coverage through the public `Runtime` API.
//!
//! A fake `wine` shim mimics `wineboot`'s skeleton creation, so the whole init → record → check →
//! repair → recreate flow runs with no real wine. The wine-present counterpart (`prefix_wine.rs`)
//! proves the same against stock wine and cross-checks path translation against the `winepath` oracle.

use std::error::Error;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use apogee_fetch::Fetcher;
use apogee_runtime::{HealthIssue, Prefix, Progress, RunnerKind, Runtime, RuntimePaths};
use tokio_util::sync::CancellationToken;

/// A `wine` stand-in: on `wineboot` it lays down the prefix skeleton the real one would, then exits 0.
const FAKE_WINE: &str = "#!/bin/sh
if [ \"$1\" = wineboot ]; then
  mkdir -p \"$WINEPREFIX/drive_c/windows\" \"$WINEPREFIX/dosdevices\"
  ln -sfn ../drive_c \"$WINEPREFIX/dosdevices/c:\"
  ln -sfn / \"$WINEPREFIX/dosdevices/z:\"
  printf 'WINE REGISTRY Version 2\\n' > \"$WINEPREFIX/system.reg\"
fi
exit 0
";

fn fake_runner(dir: &Path) -> Result<(), Box<dyn Error>> {
    let bin = dir.join("bin");
    std::fs::create_dir_all(&bin)?;
    let wine = bin.join("wine");
    std::fs::write(&wine, FAKE_WINE)?;
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

/// A runtime plus a freshly prepared prefix (fake-wineboot initialized) rooted under `root`.
async fn prepared(root: &Path) -> Result<(Runtime, Prefix), Box<dyn Error>> {
    let runtime = runtime_over(root)?;
    let runner_dir = root.join("runner");
    fake_runner(&runner_dir)?;
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

#[tokio::test]
async fn prepare_initializes_and_records_a_fresh_prefix() {
    let root = tempfile::tempdir().expect("tempdir");
    let (runtime, prefix) = prepared(root.path()).await.expect("prepare");

    let meta = prefix
        .metadata()
        .expect("load")
        .expect("prefix.json present");
    assert_eq!(meta.runner.name, "wine");
    assert_eq!(meta.runner.version, "custom");
    assert_eq!(meta.setup_history.len(), 1, "one wineboot step recorded");
    assert!(meta.setup_history[0].ok);

    assert!(
        runtime
            .check_prefix(&prefix)
            .await
            .expect("check")
            .is_healthy(),
        "the initialized prefix is healthy"
    );
}

#[tokio::test]
async fn a_ready_prefix_is_not_reinitialized() {
    let root = tempfile::tempdir().expect("tempdir");
    let (runtime, prefix) = prepared(root.path()).await.expect("prepare");
    let before = std::fs::read(prefix.metadata_path()).expect("read metadata");

    let again = runtime
        .prepare_custom(
            &root.path().join("runner"),
            RunnerKind::Wine,
            "wine",
            prefix.path(),
            &CancellationToken::new(),
            &Progress::none(),
        )
        .await
        .expect("re-prepare");

    let after = std::fs::read(again.metadata_path()).expect("read metadata");
    assert_eq!(before, after, "a ready prefix's record is untouched");
}

#[tokio::test]
async fn a_broken_drive_map_is_repaired_without_delete() {
    let root = tempfile::tempdir().expect("tempdir");
    let (runtime, prefix) = prepared(root.path()).await.expect("prepare");

    // Point Z: at the wrong place.
    let z = prefix.path().join("dosdevices/z:");
    std::fs::remove_file(&z).expect("remove z:");
    std::os::unix::fs::symlink("/tmp", &z).expect("wrong z:");

    let health = runtime.check_prefix(&prefix).await.expect("check");
    assert!(matches!(
        health.issues.as_slice(),
        [HealthIssue::DriveMapping { letter: 'z', .. }]
    ));

    let residual = runtime
        .repair_prefix(
            &prefix,
            &health.issues,
            &CancellationToken::new(),
            &Progress::none(),
        )
        .await
        .expect("repair");
    assert!(residual.is_healthy(), "drive map repaired");
    assert!(
        prefix.path().join("system.reg").is_file(),
        "repair never deleted the prefix"
    );
}

#[tokio::test]
async fn drive_map_translates_paths_in_process() {
    let root = tempfile::tempdir().expect("tempdir");
    let (_runtime, prefix) = prepared(root.path()).await.expect("prepare");

    let drives = prefix.drive_map().expect("drive map");
    assert_eq!(drives.to_windows(Path::new("/")).expect("z root"), "Z:\\");

    let drive_c = prefix.path().join("drive_c").canonicalize().expect("canon");
    assert_eq!(drives.to_windows(&drive_c).expect("c root"), "C:\\");
    assert_eq!(
        drives.to_unix("C:\\windows").expect("c win"),
        drive_c.join("windows")
    );
}

#[tokio::test]
async fn recreate_wipes_and_rebuilds_the_prefix() {
    let root = tempfile::tempdir().expect("tempdir");
    let (runtime, prefix) = prepared(root.path()).await.expect("prepare");

    let marker = prefix.path().join("drive_c/marker.txt");
    std::fs::write(&marker, b"stale").expect("marker");

    let fresh = runtime
        .recreate_prefix(&prefix, &CancellationToken::new(), &Progress::none())
        .await
        .expect("recreate");

    assert!(!marker.exists(), "recreate wiped the old prefix");
    assert!(
        runtime
            .check_prefix(&fresh)
            .await
            .expect("check")
            .is_healthy(),
        "the recreated prefix is healthy"
    );
}

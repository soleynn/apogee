//! Prefix lifecycle: real `wineboot -i` initialization recorded in `prefix.json`, a structural health
//! check with targeted fixes (never `rm -rf`), and an explicit destructive recreate.
//!
//! Initialization is idempotent: a prefix that already carries a `prefix.json` is returned untouched.
//! The health check compares the on-disk prefix to its recorded metadata and the wine skeleton, and
//! [`repair`] resolves the fixable drift — a missing drive symlink is rewritten in place, a missing
//! skeleton is regenerated with `wineboot -u` — while a runner change is left for an explicit recreate.

use std::io;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use tokio::process::Command;
use tokio_util::sync::CancellationToken;

use crate::catalog::RunnerKind;
use crate::dosdevices::resolve_drive_target;
use crate::error::{HealthIssue, PrefixHealth, RuntimeError, SetupStep};
use crate::metadata::{PrefixMetadata, RunnerRef, SetupRecord};
use crate::plan::{Prefix, RunnerHandle};
use crate::progress::{Progress, RuntimeEvent};
use crate::spawn::{DEFAULT_GAMEID, find_wine};

/// Cap on a single `wineboot`/`createprefix` run. A fresh prefix on a loaded machine can take tens of
/// seconds; past this it is treated as hung and killed.
const WINEBOOT_TIMEOUT: Duration = Duration::from_secs(300);

/// The wine skeleton files/dirs a healthy prefix always has, relative to its wine root.
const SKELETON: &[&str] = &["drive_c", "dosdevices", "system.reg"];

/// After `wineboot` exits, its wineserver persists `system.reg` on an idle shutdown a moment later,
/// so the registry is not on disk the instant the command returns. Poll for it up to this many
/// intervals so `prepare` yields a durable prefix rather than one whose registry is still in memory.
const REGISTRY_FLUSH_POLLS: u32 = 300;
const REGISTRY_FLUSH_INTERVAL: Duration = Duration::from_millis(100);

/// Ensure the prefix at `prefix_dir` is initialized and return its handle. Downloads nothing (the
/// caller has already installed `runner`); runs `wineboot` only if the prefix has no `prefix.json`
/// yet, so a re-`prepare` of a ready prefix is free.
pub(crate) async fn ensure_ready(
    runner: RunnerHandle,
    prefix_dir: &Path,
    umu: Option<&Path>,
    cancel: &CancellationToken,
    progress: &Progress,
) -> Result<Prefix, RuntimeError> {
    tokio::fs::create_dir_all(prefix_dir)
        .await
        .map_err(|source| RuntimeError::Io {
            path: prefix_dir.to_path_buf(),
            source,
        })?;
    let prefix = Prefix::new(prefix_dir.to_path_buf(), runner);

    if is_initialized(&prefix)? {
        return Ok(prefix);
    }
    initialize(&prefix, umu, cancel, progress).await?;
    Ok(prefix)
}

/// Whether the prefix already has a valid `prefix.json`. A corrupt record is treated as
/// uninitialized (and reinitialized non-destructively), rather than bricking `prepare`.
fn is_initialized(prefix: &Prefix) -> Result<bool, RuntimeError> {
    match PrefixMetadata::load(&prefix.metadata_path()) {
        Ok(Some(_)) => Ok(true),
        Ok(None) => Ok(false),
        Err(RuntimeError::PrefixJson { path, .. }) => {
            tracing::warn!(?path, "prefix.json is corrupt; reinitializing the prefix");
            Ok(false)
        }
        Err(other) => Err(other),
    }
}

/// Run `wineboot` and record the result in a fresh `prefix.json`. Chooses a full init (`-i`) for a
/// brand-new prefix and a non-destructive update (`-u`) for one whose skeleton already exists (e.g.
/// an adopted XL prefix, or one whose `prefix.json` was lost).
async fn initialize(
    prefix: &Prefix,
    umu: Option<&Path>,
    cancel: &CancellationToken,
    progress: &Progress,
) -> Result<(), RuntimeError> {
    let fresh = !prefix.wine_root().join("system.reg").exists();
    progress.emit(RuntimeEvent::PrefixInitializing { fresh });
    run_wineboot(prefix, umu, fresh, cancel).await?;

    let mut meta = PrefixMetadata::new(RunnerRef::from(prefix.runner()));
    meta.record(SetupRecord::ok(wineboot_step(fresh)));
    meta.save(&prefix.metadata_path())?;
    progress.emit(RuntimeEvent::PrefixReady);
    Ok(())
}

/// Diagnose a prefix against its recorded metadata and the wine skeleton, returning every drift found
/// without touching the prefix. Read-only.
pub(crate) async fn check(prefix: &Prefix) -> Result<PrefixHealth, RuntimeError> {
    let wine_root = prefix.wine_root();
    let mut issues = Vec::new();

    for rel in SKELETON {
        let path = wine_root.join(rel);
        if !path.exists() {
            issues.push(HealthIssue::MissingSkeleton { path });
        }
    }

    // Drive maps are only checkable when `dosdevices` exists; its absence is already a skeleton issue.
    let dosdevices = wine_root.join("dosdevices");
    if dosdevices.is_dir() {
        for expected in expected_drives(&wine_root) {
            let found = resolve_drive_target(&dosdevices, expected.letter);
            let ok = found
                .as_deref()
                .is_some_and(|f| same_path(f, &expected.resolves_to));
            if !ok {
                issues.push(HealthIssue::DriveMapping {
                    letter: expected.letter,
                    expected: expected.link_target,
                    found,
                });
            }
        }
    }

    // A runner change is drift, and any DXVK the record claims must be on disk. A corrupt
    // `prefix.json` is treated as "no record" (a warning, not a hard error) so `check` stays total
    // over a broken-but-present prefix — the same tolerance `is_initialized` applies before reinit.
    if let Some(meta) = recorded_metadata(prefix)? {
        let current = RunnerRef::from(prefix.runner());
        if meta.runner != current {
            issues.push(HealthIssue::RunnerMismatch {
                recorded: meta.runner,
                expected: current,
            });
        }
        if let Some(dxvk) = &meta.dxvk {
            crate::dxvk::check(&wine_root, dxvk, &mut issues);
        }
    }

    Ok(PrefixHealth { issues })
}

/// The recorded `prefix.json`, `None` if the prefix has no record or the record is corrupt (logged),
/// so the health check never aborts on unreadable metadata. Only a hard IO error propagates.
fn recorded_metadata(prefix: &Prefix) -> Result<Option<PrefixMetadata>, RuntimeError> {
    match PrefixMetadata::load(&prefix.metadata_path()) {
        Ok(meta) => Ok(meta),
        Err(RuntimeError::PrefixJson { path, .. }) => {
            tracing::warn!(
                ?path,
                "prefix.json is corrupt; skipping metadata-based checks"
            );
            Ok(None)
        }
        Err(other) => Err(other),
    }
}

/// Apply targeted fixes for `issues` and return the residual health (a re-check). A drive-mapping is
/// rewritten in place with no wine; a missing skeleton is regenerated with `wineboot -u`; a runner
/// mismatch is left untouched (it needs an explicit recreate) and reappears in the residual.
pub(crate) async fn repair(
    prefix: &Prefix,
    issues: &[HealthIssue],
    umu: Option<&Path>,
    cancel: &CancellationToken,
    progress: &Progress,
) -> Result<PrefixHealth, RuntimeError> {
    progress.emit(RuntimeEvent::PrefixRepairing {
        issues: issues.len(),
    });
    let wine_root = prefix.wine_root();
    let mut regenerate_skeleton = false;

    for issue in issues {
        match issue {
            // Re-derive the correct target from our own source of truth rather than trusting the
            // caller-supplied `expected` (repair_prefix is public; the issue can be fabricated). A
            // letter we do not manage is left alone.
            HealthIssue::DriveMapping { letter, .. } => {
                if let Some(drive) = expected_drives(&wine_root)
                    .into_iter()
                    .find(|d| d.letter == *letter)
                {
                    rewrite_drive(&wine_root, drive.letter, &drive.link_target)?;
                }
            }
            HealthIssue::MissingSkeleton { .. } => regenerate_skeleton = true,
            // Both need an action the local repair cannot take (a recreate; a DXVK reinstall via the
            // catalog), so they are left to reappear in the residual health.
            HealthIssue::RunnerMismatch { .. } | HealthIssue::MissingDxvkDll { .. } => {}
        }
    }

    if regenerate_skeleton {
        let fresh = !wine_root.join("system.reg").exists();
        run_wineboot(prefix, umu, fresh, cancel).await?;
        // Record the repair so the history reflects it; a missing metadata file is not fatal here.
        if let Some(mut meta) = PrefixMetadata::load(&prefix.metadata_path())? {
            meta.record(SetupRecord::ok(SetupStep::WinebootUpdate));
            meta.save(&prefix.metadata_path())?;
        }
    }

    check(prefix).await
}

/// Destructively recreate a prefix: delete it entirely, then reinitialize (`wineboot -i` + a fresh
/// `prefix.json`). The caller-facing gate — this is never the automatic response to a problem.
pub(crate) async fn recreate(
    prefix: &Prefix,
    umu: Option<&Path>,
    cancel: &CancellationToken,
    progress: &Progress,
) -> Result<Prefix, RuntimeError> {
    progress.emit(RuntimeEvent::PrefixRecreating);
    if prefix.path().exists() {
        tokio::fs::remove_dir_all(prefix.path())
            .await
            .map_err(|source| RuntimeError::Io {
                path: prefix.path().to_path_buf(),
                source,
            })?;
    }
    ensure_ready(
        prefix.runner().clone(),
        prefix.path(),
        umu,
        cancel,
        progress,
    )
    .await
}

/// Build and run the `wineboot`/`createprefix` command, waiting for it under a cancellation token and
/// a hard timeout. A non-zero exit, a timeout, or cancellation is a [`RuntimeError::PrefixInit`].
async fn run_wineboot(
    prefix: &Prefix,
    umu: Option<&Path>,
    fresh: bool,
    cancel: &CancellationToken,
) -> Result<(), RuntimeError> {
    let step = wineboot_step(fresh);
    let mut command = wineboot_command(prefix, umu, fresh)?;
    let mut child = command.spawn().map_err(|e| {
        prefix_init(
            step,
            io::Error::new(e.kind(), format!("spawn wineboot: {e}")),
        )
    })?;

    let waited = tokio::time::timeout(WINEBOOT_TIMEOUT, async {
        tokio::select! {
            status = child.wait() => Some(status),
            () = cancel.cancelled() => None,
        }
    })
    .await;

    match waited {
        Ok(Some(Ok(status))) if status.success() => {
            await_registry_flush(&prefix.wine_root()).await;
            Ok(())
        }
        Ok(Some(Ok(status))) => Err(prefix_init(
            step,
            io::Error::other(format!("wineboot exited unsuccessfully: {status}")),
        )),
        Ok(Some(Err(source))) => Err(prefix_init(step, source)),
        Ok(None) => {
            let _ = child.start_kill();
            Err(prefix_init(
                step,
                io::Error::new(io::ErrorKind::Interrupted, "prefix init cancelled"),
            ))
        }
        Err(_elapsed) => {
            let _ = child.start_kill();
            Err(prefix_init(
                step,
                io::Error::new(io::ErrorKind::TimedOut, "wineboot timed out"),
            ))
        }
    }
}

/// Compose the `wineboot`/`createprefix` command with the init environment. `WINEDLLOVERRIDES`
/// disables the Mono/Gecko installers so a headless init never blocks on their download prompt.
fn wineboot_command(
    prefix: &Prefix,
    umu: Option<&Path>,
    fresh: bool,
) -> Result<Command, RuntimeError> {
    let runner = prefix.runner();
    let mut command = match runner.kind() {
        RunnerKind::ProtonUmu => {
            let umu = umu.ok_or(RuntimeError::MissingHostTool {
                tool: crate::error::HostTool::Umu,
            })?;
            let mut command = Command::new(umu);
            command.arg("createprefix");
            command.env("GAMEID", DEFAULT_GAMEID);
            command.env("PROTONPATH", runner.dir());
            // umu relocates the live prefix under `<WINEPREFIX>/pfx` itself.
            command.env("WINEPREFIX", prefix.path());
            command
        }
        RunnerKind::Wine | RunnerKind::Custom => {
            let wine = find_wine(runner.dir()).ok_or(RuntimeError::MissingHostTool {
                tool: crate::error::HostTool::Wine,
            })?;
            let mut command = Command::new(wine);
            command.arg("wineboot").arg(if fresh { "-i" } else { "-u" });
            command.env("WINEPREFIX", prefix.path());
            command
        }
    };
    command.env("WINEDEBUG", "-all");
    command.env("WINEDLLOVERRIDES", "mscoree,mshtml=");
    command.stdin(Stdio::null());
    command.stdout(Stdio::null());
    command.stderr(Stdio::null());
    command.kill_on_drop(true);
    Ok(command)
}

/// The setup step a `wineboot` run records: a full init on a fresh prefix, an update otherwise.
fn wineboot_step(fresh: bool) -> SetupStep {
    if fresh {
        SetupStep::WinebootInit
    } else {
        SetupStep::WinebootUpdate
    }
}

fn prefix_init(step: SetupStep, source: io::Error) -> RuntimeError {
    RuntimeError::PrefixInit {
        step,
        source: Box::new(source),
    }
}

/// Wait, bounded, for `system.reg` to appear after a `wineboot`. Best-effort: if it never flushes (a
/// broken wine), initialization still proceeds and the health check reports the missing skeleton.
async fn await_registry_flush(wine_root: &Path) {
    let registry = wine_root.join("system.reg");
    for _ in 0..REGISTRY_FLUSH_POLLS {
        if registry.exists() {
            return;
        }
        tokio::time::sleep(REGISTRY_FLUSH_INTERVAL).await;
    }
}

/// A drive the health check requires and knows how to restore.
struct ExpectedDrive {
    letter: char,
    /// The literal symlink target to write when restoring (wine's own convention).
    link_target: PathBuf,
    /// The absolute path that target must resolve to.
    resolves_to: PathBuf,
}

/// The two drives every wine prefix has: `c:` → `../drive_c` and `z:` → `/`.
fn expected_drives(wine_root: &Path) -> Vec<ExpectedDrive> {
    vec![
        ExpectedDrive {
            letter: 'c',
            link_target: PathBuf::from("../drive_c"),
            resolves_to: wine_root.join("drive_c"),
        },
        ExpectedDrive {
            letter: 'z',
            link_target: PathBuf::from("/"),
            resolves_to: PathBuf::from("/"),
        },
    ]
}

/// Rewrite a single drive symlink to `link_target`, replacing whatever is there. No wine involved.
fn rewrite_drive(wine_root: &Path, letter: char, link_target: &Path) -> Result<(), RuntimeError> {
    let dosdevices = wine_root.join("dosdevices");
    std::fs::create_dir_all(&dosdevices).map_err(|source| RuntimeError::Io {
        path: dosdevices.clone(),
        source,
    })?;
    let link = dosdevices.join(format!("{letter}:"));
    remove_path(&link)?;
    std::os::unix::fs::symlink(link_target, &link)
        .map_err(|source| RuntimeError::Io { path: link, source })
}

/// Remove whatever is at `path` (a symlink, file, or directory), tolerating its absence.
fn remove_path(path: &Path) -> Result<(), RuntimeError> {
    match std::fs::symlink_metadata(path) {
        Ok(meta) if meta.is_dir() => {
            std::fs::remove_dir_all(path).map_err(|source| RuntimeError::Io {
                path: path.to_path_buf(),
                source,
            })
        }
        Ok(_) => std::fs::remove_file(path).map_err(|source| RuntimeError::Io {
            path: path.to_path_buf(),
            source,
        }),
        Err(_) => Ok(()),
    }
}

/// Whether two paths refer to the same location, comparing canonical forms where available.
fn same_path(a: &Path, b: &Path) -> bool {
    let ca = a.canonicalize();
    let cb = b.canonicalize();
    match (ca, cb) {
        (Ok(a), Ok(b)) => a == b,
        _ => a == b,
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::symlink;

    use super::*;

    /// A minimal healthy wine prefix skeleton under a temp dir, plus a matching `prefix.json`.
    fn healthy_prefix(name: &str, version: &str) -> (tempfile::TempDir, Prefix) {
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path();
        apogee_test_support::sandbox::write_prefix_skeleton(root).expect("skeleton");

        let handle = RunnerHandle::for_test(root.join("runner"), RunnerKind::Wine, name, version);
        let prefix = Prefix::new(root.to_path_buf(), handle);
        let meta = PrefixMetadata::new(RunnerRef {
            name: name.to_owned(),
            version: version.to_owned(),
        });
        meta.save(&prefix.metadata_path()).expect("save metadata");
        (dir, prefix)
    }

    #[tokio::test]
    async fn a_pristine_prefix_is_healthy() {
        let (_dir, prefix) = healthy_prefix("wine", "custom");
        assert!(check(&prefix).await.expect("check").is_healthy());
    }

    #[tokio::test]
    async fn a_broken_drive_map_is_detected_and_repaired_in_place() {
        let (_dir, prefix) = healthy_prefix("wine", "custom");
        // Break z: so it points at the wrong place.
        let z = prefix.wine_root().join("dosdevices/z:");
        std::fs::remove_file(&z).expect("remove z:");
        symlink("/tmp", &z).expect("wrong z:");

        let health = check(&prefix).await.expect("check");
        assert!(matches!(
            health.issues.as_slice(),
            [HealthIssue::DriveMapping { letter: 'z', .. }]
        ));

        let residual = repair(
            &prefix,
            &health.issues,
            None,
            &CancellationToken::new(),
            &Progress::none(),
        )
        .await
        .expect("repair");
        assert!(residual.is_healthy(), "drive map repaired with no delete");
        // The prefix directory itself was never removed.
        assert!(prefix.path().join("system.reg").is_file());
    }

    #[tokio::test]
    async fn a_missing_drive_symlink_is_detected() {
        let (_dir, prefix) = healthy_prefix("wine", "custom");
        std::fs::remove_file(prefix.wine_root().join("dosdevices/c:")).expect("remove c:");
        let health = check(&prefix).await.expect("check");
        assert!(matches!(
            health.issues.as_slice(),
            [HealthIssue::DriveMapping {
                letter: 'c',
                found: None,
                ..
            }]
        ));
    }

    #[tokio::test]
    async fn a_missing_skeleton_file_is_detected() {
        let (_dir, prefix) = healthy_prefix("wine", "custom");
        std::fs::remove_file(prefix.wine_root().join("system.reg")).expect("remove reg");
        let health = check(&prefix).await.expect("check");
        assert!(
            health
                .issues
                .iter()
                .any(|i| matches!(i, HealthIssue::MissingSkeleton { .. }))
        );
    }

    #[tokio::test]
    async fn a_runner_change_is_reported_as_a_mismatch() {
        let (_dir, prefix_a) = healthy_prefix("UMU-Proton", "9-20");
        // Re-open the same prefix directory under a different runner identity.
        let handle = RunnerHandle::for_test(
            prefix_a.path().join("runner"),
            RunnerKind::Wine,
            "wine-xiv",
            "8.5.r4",
        );
        let prefix_b = Prefix::new(prefix_a.path().to_path_buf(), handle);
        let health = check(&prefix_b).await.expect("check");
        assert!(matches!(
            health.issues.as_slice(),
            [HealthIssue::RunnerMismatch { .. }]
        ));
    }
}

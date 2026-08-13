//! Prefix initialization, health checking, targeted repair, and recreate.
//!
//! A prefix is initialized by a real `wineboot` and described by the `prefix.json` that run writes.
//!
//! Initialization is idempotent on the record rather than on the steps. A prefix that already carries
//! a parsable `prefix.json` is returned untouched, and nothing here reads the setup history back, so
//! that history is a log of what ran and never a gate on what runs next. A prefix gutted behind this
//! crate's back still has its record, so [`ensure_ready`] leaves it alone and [`check`] is what
//! notices; a prefix whose record was lost or corrupted is initialized again with the non-destructive
//! verb, so nothing already in it is thrown away.
//!
//! [`repair`] is targeted, never `rm -rf`: a broken drive symlink is rewritten in place and a missing
//! skeleton is regenerated with `wineboot -u`. [`recreate`] is the only path here that deletes
//! anything, and a runner change is the drift that requires it.

use std::io;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use tokio::process::Command;
use tokio_util::sync::CancellationToken;

use crate::catalog::RunnerKind;
use crate::dosdevices::resolve_drive_target;
use crate::error::{
    HealthIssue, PrefixHealth, PrefixWants, RuntimeError, SetupStep, StepCancelled,
};
use crate::metadata::{PrefixMetadata, RunnerRef, SetupRecord};
use crate::plan::{Prefix, RunnerHandle};
use crate::progress::{Progress, RuntimeEvent};
use crate::spawn::{DEFAULT_GAMEID, find_wine};

/// Cap on a single `wineboot` run. A fresh prefix on a loaded machine can take tens of seconds; past
/// this it is treated as hung and killed.
const WINEBOOT_TIMEOUT: Duration = Duration::from_secs(300);

/// The wine skeleton files and directories a healthy prefix always has, relative to its wine root.
const SKELETON: &[&str] = &["drive_c", "dosdevices", "system.reg"];

/// How many times to poll for `system.reg` after `wineboot` exits.
///
/// Its wineserver persists the registry on an idle shutdown a moment later, so the file is not on
/// disk the instant the command returns. Polling for it is what makes a prepared prefix durable
/// rather than one whose registry is still in memory.
const REGISTRY_FLUSH_POLLS: u32 = 300;

/// The pause between those polls.
const REGISTRY_FLUSH_INTERVAL: Duration = Duration::from_millis(100);

/// Ensure the prefix at `prefix_dir` is initialized and return its handle.
///
/// Downloads nothing: the caller has already installed `runner`. Runs `wineboot` only if the prefix
/// has no readable `prefix.json` yet, so re-preparing a ready prefix costs one file read.
///
/// # Errors
///
/// [`RuntimeError::Io`] if `prefix_dir` cannot be created or an existing record cannot be read, then
/// whatever [`initialize`] raises.
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

/// Whether the prefix already has a readable `prefix.json`.
///
/// A corrupt record is logged and reads as uninitialized, so a bad file leads to a non-destructive
/// re-init rather than bricking every prepare of that prefix.
///
/// # Errors
///
/// [`RuntimeError::Io`] if the record is present and cannot be read at all.
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

/// Run `wineboot` and record the result in a fresh `prefix.json`.
///
/// Picks a full init (`-i`) for a brand-new prefix and a non-destructive update (`-u`) for one whose
/// skeleton already exists, which is a prefix adopted from another launcher or one whose
/// `prefix.json` was lost.
///
/// # Errors
///
/// [`RuntimeError::MissingHostTool`] if the runner's launcher is absent,
/// [`RuntimeError::PrefixInit`] if `wineboot` fails, times out, or is stopped, and
/// [`RuntimeError::Io`] or [`RuntimeError::PrefixJson`] if the record cannot be written.
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

/// Diagnose a prefix against its recorded metadata, the wine skeleton, and what `wants` asked of it.
///
/// Read-only: it reports every drift it finds and changes nothing. A corrupt `prefix.json` reads as
/// no record, so the metadata half of the check is skipped rather than the whole check failing.
///
/// # Errors
///
/// [`RuntimeError::Io`] if `prefix.json` is present and unreadable for a reason other than being
/// corrupt.
pub(crate) async fn check(
    prefix: &Prefix,
    wants: &PrefixWants,
) -> Result<PrefixHealth, RuntimeError> {
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

    // A runner change is drift, any DXVK the record claims must be on disk, and a companion that was
    // wanted must be in the record. A corrupt `prefix.json` is treated as "no record" (a warning, not
    // a hard error) so `check` stays total over a broken-but-present prefix — the same tolerance
    // `is_initialized` applies before reinit. The wanted-companion half sits inside that same
    // tolerance deliberately: with no readable record there is nothing to compare a wish against, and
    // reporting one anyway would name the same prefix's missing record twice.
    if let Some(meta) = recorded_metadata(prefix)? {
        let current = RunnerRef::from(prefix.runner());
        if meta.runner != current {
            issues.push(HealthIssue::RunnerMismatch {
                recorded: meta.runner,
                expected: current,
            });
        }
        crate::dxvk::check(&wine_root, meta.dxvk.as_ref(), wants, &mut issues);
    }

    Ok(PrefixHealth { issues })
}

/// The recorded `prefix.json`, or `None` if the prefix has no record or the record is corrupt.
///
/// A corrupt record is logged and treated as absent, so the health check never aborts on unreadable
/// metadata. Only a hard read failure propagates.
///
/// # Errors
///
/// [`RuntimeError::Io`] on a read failure that is neither a missing nor a corrupt file.
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

/// Apply targeted fixes for `issues` and return the residual health, which is a fresh [`check`].
///
/// Two issues are fixable here. [`HealthIssue::DriveMapping`] is rewritten in place with no wine
/// involved, from this module's own idea of the drive rather than from the caller-supplied
/// `expected`; a letter this module does not manage is left alone. [`HealthIssue::MissingSkeleton`]
/// is regenerated with `wineboot -u`, which keeps user data. The other three are untouched and
/// reappear in the residual: [`HealthIssue::RunnerMismatch`] needs an explicit [`recreate`], and
/// [`HealthIssue::MissingDxvkDll`] and [`HealthIssue::MissingNvapi`] need a DXVK install the caller
/// drives with a catalog in hand.
///
/// # Errors
///
/// [`RuntimeError::Io`] if a drive symlink cannot be rewritten, whatever [`run_wineboot`] raises when
/// a skeleton is regenerated, and [`RuntimeError::Io`] or [`RuntimeError::PrefixJson`] if the repair
/// cannot be recorded.
pub(crate) async fn repair(
    prefix: &Prefix,
    issues: &[HealthIssue],
    wants: &PrefixWants,
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
            // All three need an action the local repair cannot take (a recreate; a DXVK install via
            // the catalog, which also places the companion), so they are left to reappear in the
            // residual health.
            HealthIssue::RunnerMismatch { .. }
            | HealthIssue::MissingDxvkDll { .. }
            | HealthIssue::MissingNvapi => {}
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

    // Re-checked against the same wants, so an issue this repair could not resolve is still in the
    // residual. Dropping them here would let a fix report a prefix as clean for the one reason a
    // check would not.
    check(prefix, wants).await
}

/// Delete the prefix entirely, then initialize it again.
///
/// The only path in this module that destroys anything, and caller-facing on purpose: it is never the
/// automatic response to a health problem.
///
/// # Errors
///
/// [`RuntimeError::Io`] if the directory cannot be removed, then whatever [`ensure_ready`] raises.
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

/// Run `wineboot` and wait for the prefix it leaves behind.
///
/// The wait is under both the cancellation token and a hard timeout, and a successful run is followed
/// by a wait for the registry to reach disk.
///
/// # Errors
///
/// [`RuntimeError::MissingHostTool`] if the runner's launcher is absent, and
/// [`RuntimeError::PrefixInit`] for a spawn failure, a non-zero exit, a timeout, or a stop. The
/// stopped one carries [`StepCancelled`] as its source, which is what
/// [`RuntimeError::is_cancellation`] reads.
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
            // Carried as a type, not a message: this is the error a first run produces when the user
            // stops the longest phase of it, and every consumer above has to be able to tell it from a
            // wine that failed.
            Err(RuntimeError::PrefixInit {
                step,
                source: Box::new(StepCancelled),
            })
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

/// Compose the `wineboot` command with the initialization environment.
///
/// `WINEDLLOVERRIDES` disables the Mono and Gecko installers, so a headless init never blocks on
/// their download prompt. Output is discarded and the child is killed on drop.
///
/// # Errors
///
/// [`RuntimeError::MissingHostTool`] if a Proton runner was given no `umu-run`, or a wine runner has
/// no `wine` binary under its directory.
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
            command.env("WINEPREFIX", prefix.path());
            command
        }
    };
    // Both runners take the program to run inside the prefix: umu-run has no prefix-creation verb of
    // its own (umu 1.4.1 dropped `createprefix`), and initializing is the side effect of wineboot.
    command.arg("wineboot").arg(if fresh { "-i" } else { "-u" });
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

/// A setup step that failed for an ordinary I/O reason, as opposed to one that was stopped.
fn prefix_init(step: SetupStep, source: io::Error) -> RuntimeError {
    RuntimeError::PrefixInit {
        step,
        source: Box::new(source),
    }
}

/// Wait, bounded, for `system.reg` to appear after a `wineboot`.
///
/// Best-effort: if it never flushes, which is a broken wine, initialization still proceeds and the
/// health check reports the missing skeleton.
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
    /// The DOS drive letter, lowercase.
    letter: char,
    /// The literal symlink target to write when restoring, in wine's own convention.
    link_target: PathBuf,
    /// The absolute path that target must resolve to.
    resolves_to: PathBuf,
}

/// The two drives every wine prefix has: `c:` pointing at `../drive_c`, and `z:` at `/`.
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

/// Rewrite one drive symlink to `link_target`, replacing whatever is there. No wine involved.
///
/// # Errors
///
/// [`RuntimeError::Io`] if `dosdevices` cannot be created, the old entry cannot be removed, or the
/// symlink cannot be written.
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

/// Remove whatever is at `path`, symlink, file, or directory, tolerating its absence.
///
/// # Errors
///
/// [`RuntimeError::Io`] if something is there and cannot be removed.
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

/// Whether two paths name the same location.
///
/// Compares canonical forms where both canonicalize, and the literal paths otherwise.
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
    // `body` is what `wineboot` becomes.
    use crate::shim::scripted_prefix as scripted_runner;

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

    /// Both runners initialize through `wineboot`, and `fresh` picks the verb.
    ///
    /// umu 1.4.1 dropped `createprefix`: it still created the prefix as a side effect but exited
    /// nonzero, so init failed on a prefix that was in fact there.
    #[test]
    fn umu_prefix_init_runs_wineboot_with_the_fresh_verb() {
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path();
        let handle = RunnerHandle::for_test(
            root.join("runner"),
            RunnerKind::ProtonUmu,
            "GE-Proton",
            "11-1",
        );
        let prefix = Prefix::new(root.to_path_buf(), handle);
        let umu = PathBuf::from("/usr/bin/umu-run");

        for (fresh, verb) in [(true, "-i"), (false, "-u")] {
            let command = wineboot_command(&prefix, Some(&umu), fresh).expect("command");
            let args: Vec<_> = command.as_std().get_args().collect();
            assert_eq!(args, ["wineboot", verb], "fresh = {fresh}");
        }
    }

    /// Creating the prefix is the longest phase of a first run and the one a user is most likely to
    /// stop. A `wineboot` the token interrupted has to be tellable from one that failed, and the
    /// error variant alone does not distinguish them, so the error itself answers.
    #[tokio::test]
    async fn a_prefix_init_the_token_stopped_reads_as_a_cancellation() {
        let (_dir, prefix) = scripted_runner("sleep 30");
        let cancel = CancellationToken::new();
        cancel.cancel();

        let err = run_wineboot(&prefix, None, true, &cancel)
            .await
            .expect_err("a prefix init that was stopped did not finish");
        assert!(err.is_cancellation(), "{err:?}");
    }

    /// A wine that ran and failed is a failure, whatever the token says afterwards.
    ///
    /// The case the one above has to stay distinct from.
    #[tokio::test]
    async fn a_prefix_init_that_failed_is_not_a_cancellation() {
        let (_dir, prefix) = scripted_runner("exit 1");

        let err = run_wineboot(&prefix, None, true, &CancellationToken::new())
            .await
            .expect_err("a wineboot that exits non-zero failed the init");
        assert!(!err.is_cancellation(), "{err:?}");
    }

    /// A skeleton with a matching record produces no issues at all.
    ///
    /// The floor the drift tests below are read against.
    #[tokio::test]
    async fn a_pristine_prefix_is_healthy() {
        let (_dir, prefix) = healthy_prefix("wine", "custom");
        assert!(
            check(&prefix, &PrefixWants::default())
                .await
                .expect("check")
                .is_healthy()
        );
    }

    /// A drive pointing at the wrong place is fixed by rewriting one symlink.
    ///
    /// The prefix directory survives the repair, which is the whole point of the targeted fix.
    #[tokio::test]
    async fn a_broken_drive_map_is_detected_and_repaired_in_place() {
        let (_dir, prefix) = healthy_prefix("wine", "custom");
        // Break z: so it points at the wrong place.
        let z = prefix.wine_root().join("dosdevices/z:");
        std::fs::remove_file(&z).expect("remove z:");
        symlink("/tmp", &z).expect("wrong z:");

        let health = check(&prefix, &PrefixWants::default())
            .await
            .expect("check");
        assert!(matches!(
            health.issues.as_slice(),
            [HealthIssue::DriveMapping { letter: 'z', .. }]
        ));

        let residual = repair(
            &prefix,
            &health.issues,
            &PrefixWants::default(),
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

    /// An absent drive link reports as the same issue as a wrong one, with `found: None`.
    ///
    /// So a caller has one case to render rather than two.
    #[tokio::test]
    async fn a_missing_drive_symlink_is_detected() {
        let (_dir, prefix) = healthy_prefix("wine", "custom");
        std::fs::remove_file(prefix.wine_root().join("dosdevices/c:")).expect("remove c:");
        let health = check(&prefix, &PrefixWants::default())
            .await
            .expect("check");
        assert!(matches!(
            health.issues.as_slice(),
            [HealthIssue::DriveMapping {
                letter: 'c',
                found: None,
                ..
            }]
        ));
    }

    /// A missing `system.reg` is reported even though the record still parses.
    ///
    /// The skeleton sweep is structural, and runs whether or not the metadata half has anything to
    /// say.
    #[tokio::test]
    async fn a_missing_skeleton_file_is_detected() {
        let (_dir, prefix) = healthy_prefix("wine", "custom");
        std::fs::remove_file(prefix.wine_root().join("system.reg")).expect("remove reg");
        let health = check(&prefix, &PrefixWants::default())
            .await
            .expect("check");
        assert!(
            health
                .issues
                .iter()
                .any(|i| matches!(i, HealthIssue::MissingSkeleton { .. }))
        );
    }

    /// Reopening one prefix under a different runner reports a mismatch.
    ///
    /// The one issue no in-place fix resolves, so the check has to surface it on its own.
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
        let health = check(&prefix_b, &PrefixWants::default())
            .await
            .expect("check");
        assert!(matches!(
            health.issues.as_slice(),
            [HealthIssue::RunnerMismatch { .. }]
        ));
    }
}

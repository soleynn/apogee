#![cfg(target_os = "linux")]
//! Applying a real verb to a real prefix (feature `wine-integration`, run only in the wine-present CI
//! job).
//!
//! The hermetic tests apply verbs that place files, because a registry write needs a wine. This is the
//! other half: the verb the hosted manifest actually ships, applied to a `wineboot`-initialized prefix,
//! three times over. What it proves is the gate's property: that applying a verb again is a no-op that
//! succeeds rather than a program waiting on a prompt, and that the prefix records it once either way.
//!
//! And the other direction, which no hermetic test reaches: the value taken back out of a real prefix
//! and the next pass noticing. The hermetic tests write a `user.reg` themselves, so what they check is
//! the decision over a file of their own making; this checks it over one a wine wrote, after a real
//! `reg delete`.

use std::error::Error;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use apogee_addons::{AddonPaths, Addons, SetupEvents, SetupState, VerifiedManifest};
use apogee_fetch::Fetcher;
use apogee_runtime::{Prefix, ProgramInPrefix, Progress, RunnerKind, Runtime, RuntimePaths};
use serial_test::serial;
use tokio_util::sync::CancellationToken;

/// The manifest the launcher actually ships, so this exercises the shipped verb rather than a fixture
/// written to pass.
fn hosted() -> Result<VerifiedManifest, Box<dyn Error>> {
    Ok(VerifiedManifest::verify_trusted(
        include_bytes!("../../../site/components/manifest.json"),
        include_bytes!("../../../site/components/manifest.json.sig"),
    )?)
}

/// A custom runner whose `bin/wine` shims to the host's wine on `PATH`.
fn wine_runner(dir: &Path) -> Result<(), Box<dyn Error>> {
    let bin = dir.join("bin");
    std::fs::create_dir_all(&bin)?;
    let wine = bin.join("wine");
    std::fs::write(&wine, "#!/bin/sh\nexec wine \"$@\"\n")?;
    std::fs::set_permissions(&wine, std::fs::Permissions::from_mode(0o755))?;
    Ok(())
}

/// A wineboot-initialized prefix under `root`, and the addon layer over it.
async fn prepared(root: &Path) -> Result<(Runtime, Addons, Prefix), Box<dyn Error>> {
    let fetcher = Fetcher::builder().build()?;
    let runtime = Runtime::new(
        fetcher.clone(),
        RuntimePaths {
            runners: root.join("runners"),
            prefixes: root.join("prefixes"),
        },
    );
    let addons = Addons::new(
        runtime.clone(),
        fetcher,
        AddonPaths::new(root.join("addons")),
    );
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
    Ok((runtime, addons, prefix))
}

/// Whether the override the verb writes is present, by exit status alone. `reg query`'s text goes through
/// wine's console layer and lands in the console codepage when redirected, so its bytes are not an
/// interface; its status is.
async fn override_present(runtime: &Runtime, prefix: &Prefix) -> Result<bool, Box<dyn Error>> {
    let query = ProgramInPrefix::new(
        "reg",
        vec![
            "query".to_owned(),
            r"HKCU\Software\Wine\DllOverrides".to_owned(),
            "/v".to_owned(),
            "winemenubuilder.exe".to_owned(),
        ],
    );
    Ok(runtime
        .run_in_prefix(prefix, &query, &CancellationToken::new())
        .await?
        .ok())
}

/// The names the prefix records.
fn recorded(prefix: &Prefix) -> Result<Vec<String>, Box<dyn Error>> {
    Ok(prefix
        .components()?
        .iter()
        .map(|c| c.name().to_owned())
        .collect())
}

/// Rewrite the prefix's record with nothing applied, standing in for a record lost or truncated
/// between two runs.
fn forget_applied_verbs(prefix: &Prefix) -> Result<(), Box<dyn Error>> {
    let path = prefix.metadata_path();
    let mut meta =
        apogee_runtime::PrefixMetadata::load(&path)?.ok_or("the prefix has no record to edit")?;
    meta.components.clear();
    std::fs::write(&path, serde_json::to_vec_pretty(&meta)?)?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[serial]
async fn the_shipped_verb_applies_to_a_real_prefix_and_re_applies_as_a_no_op() {
    let root = tempfile::tempdir().expect("tempdir");
    let (runtime, addons, prefix) = prepared(root.path()).await.expect("prepare under wine");
    let manifest = hosted().expect("the hosted manifest verifies");
    let cancel = CancellationToken::new();
    let events = SetupEvents::none();

    assert!(
        !override_present(&runtime, &prefix)
            .await
            .expect("query a fresh prefix"),
        "the override cannot already be there"
    );

    let first = addons
        .apply_setup(&manifest, &prefix, &cancel, &events)
        .await
        .expect("first apply");
    assert_eq!(first.present(), ["no-desktop-integration"]);
    assert!(
        first
            .outcomes
            .iter()
            .all(|o| o.state == SetupState::Applied),
        "{first:?}"
    );
    assert!(
        override_present(&runtime, &prefix)
            .await
            .expect("query after applying"),
        "the verb wrote the value"
    );
    assert_eq!(
        recorded(&prefix).expect("record"),
        ["no-desktop-integration"]
    );

    // The gate's property: applying again succeeds and does nothing, and the record does not grow a
    // second entry for the same verb.
    let second = addons
        .apply_setup(&manifest, &prefix, &cancel, &events)
        .await
        .expect("second apply");
    assert!(
        second
            .outcomes
            .iter()
            .all(|o| o.state == SetupState::AlreadyPresent),
        "{second:?}"
    );
    assert_eq!(
        recorded(&prefix).expect("record"),
        ["no-desktop-integration"]
    );

    // With the record cleared, the ops themselves still have to converge rather than failing on a value
    // that is already set. That is what keeps an interrupted apply recoverable, and it is the part the
    // record cannot stand in for.
    forget_applied_verbs(&prefix).expect("clear the record");
    let third = addons
        .apply_setup(&manifest, &prefix, &cancel, &events)
        .await
        .expect("apply over a value that is already set");
    assert!(
        third
            .outcomes
            .iter()
            .all(|o| o.state == SetupState::Applied),
        "{third:?}"
    );
    assert!(
        override_present(&runtime, &prefix)
            .await
            .expect("query after re-applying"),
        "the value is still there"
    );
}

/// Take the override back out of the prefix the way anything else on the host would, with the runner's
/// own `reg`. This is the live repro: the value is removed while the prefix's record still claims the
/// verb, and the key it lived in stays behind.
async fn delete_override(runtime: &Runtime, prefix: &Prefix) -> Result<(), Box<dyn Error>> {
    let delete = ProgramInPrefix::new(
        "reg",
        vec![
            "delete".to_owned(),
            r"HKCU\Software\Wine\DllOverrides".to_owned(),
            "/v".to_owned(),
            "winemenubuilder.exe".to_owned(),
            "/f".to_owned(),
        ],
    );
    let run = runtime
        .run_in_prefix(prefix, &delete, &CancellationToken::new())
        .await?;
    if run.ok() {
        return Ok(());
    }
    Err(format!("reg delete did not remove the value: {}", run.diagnostic()).into())
}

/// Wait, bounded, for the prefix's registry file to catch up with a write.
///
/// Wine persists the registry on an idle wineserver shutdown some time after the program that wrote it
/// exits, so a file read taken straight afterwards still shows the old contents. On the launch path
/// this never arises, because setup is planned before anything has run in the prefix; here the write
/// and the read are seconds apart, so the wait has to be explicit.
///
/// Reads the raw file rather than going through the reader under test, so what it waits for is the
/// on-disk state itself.
fn await_flush(prefix: &Prefix, still_there: bool) -> Result<(), Box<dyn Error>> {
    let hive = prefix.path().join("user.reg");
    for _ in 0..300 {
        let text = std::fs::read_to_string(&hive).unwrap_or_default();
        if text.contains("\"winemenubuilder.exe\"") == still_there {
            return Ok(());
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    Err(format!("{} never caught up with the write", hive.display()).into())
}

/// The failure this reaches for: the value removed from under the launcher, the prefix still recording
/// the verb, and the next pass having to notice rather than report it as already applied.
///
/// Proved by hand before it was fixed, by deleting the value and launching again: the launcher said
/// `no-desktop-integration` was already applied and left the value gone. Nothing on disk names it, so
/// the record was the only evidence there was and the record was wrong.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[serial]
async fn a_recorded_verb_whose_registry_value_was_deleted_is_applied_again() {
    let root = tempfile::tempdir().expect("tempdir");
    let (runtime, addons, prefix) = prepared(root.path()).await.expect("prepare under wine");
    let manifest = hosted().expect("the hosted manifest verifies");
    let cancel = CancellationToken::new();
    let events = SetupEvents::none();

    addons
        .apply_setup(&manifest, &prefix, &cancel, &events)
        .await
        .expect("first apply");
    assert_eq!(
        recorded(&prefix).expect("record"),
        ["no-desktop-integration"]
    );
    await_flush(&prefix, true).expect("the value reaches the file");

    delete_override(&runtime, &prefix)
        .await
        .expect("remove the value");
    assert!(
        !override_present(&runtime, &prefix)
            .await
            .expect("query after deleting"),
        "the value really is gone, by the runner's own reading of it"
    );
    await_flush(&prefix, false).expect("the removal reaches the file");
    assert_eq!(
        recorded(&prefix).expect("record"),
        ["no-desktop-integration"],
        "and the prefix still claims the verb, which is what makes this the failing case"
    );

    let report = addons
        .apply_setup(&manifest, &prefix, &cancel, &events)
        .await
        .expect("apply over a prefix whose value was removed");

    // `Reapplied` rather than `Applied`, and the distinction is the point: the prefix recorded this
    // verb, so what happened is setup coming back rather than setup that was missing, and the reason
    // is the reading that says so.
    let [outcome] = report.outcomes.as_slice() else {
        panic!("one verb ran, so one outcome: {report:?}");
    };
    let SetupState::Reapplied { because, .. } = &outcome.state else {
        panic!("the record does not stand in for a registry value that is gone: {report:?}");
    };
    assert!(
        because.contains("winemenubuilder.exe"),
        "the reason names the value that was read, so a reapply on every launch can be told from a \
         wrong reading: {because:?}"
    );
    assert!(
        override_present(&runtime, &prefix)
            .await
            .expect("query after re-applying"),
        "and the value is back"
    );
    assert_eq!(
        recorded(&prefix).expect("record"),
        ["no-desktop-integration"],
        "reapplying does not record the verb twice"
    );
}

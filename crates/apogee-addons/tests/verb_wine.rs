#![cfg(target_os = "linux")]
//! Applying a real verb to a real prefix (feature `wine-integration`, run only in the wine-present CI
//! job).
//!
//! The hermetic install tests use a verb with no ops, because a registry write needs a wine. This is the
//! other half: the verb the hosted manifest actually ships, applied to a `wineboot`-initialized prefix,
//! three times over. What it proves is the gate's property — that applying a verb again is a no-op that
//! succeeds rather than a program waiting on a prompt, and that the prefix records it once either way.

use std::error::Error;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use apogee_addons::{AddonPaths, Addons, ComponentEvents, ComponentManifest, ComponentState};
use apogee_fetch::Fetcher;
use apogee_runtime::{Prefix, ProgramInPrefix, Progress, RunnerKind, Runtime, RuntimePaths};
use serial_test::serial;
use tokio_util::sync::CancellationToken;

/// The manifest the launcher actually ships, so this exercises the shipped verb rather than a fixture
/// written to pass.
fn hosted() -> Result<ComponentManifest, Box<dyn Error>> {
    Ok(ComponentManifest::verify_default(
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
        AddonPaths {
            components: root.join("components"),
        },
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

/// Rewrite the prefix's record without its component list, standing in for a record lost or truncated
/// between two runs.
fn forget_components(prefix: &Prefix) -> Result<(), Box<dyn Error>> {
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
    let wanted = vec!["no-desktop-integration".to_owned()];
    let cancel = CancellationToken::new();
    let events = ComponentEvents::none();

    assert!(
        !override_present(&runtime, &prefix)
            .await
            .expect("query a fresh prefix"),
        "the override cannot already be there"
    );

    let first = addons
        .ensure(&manifest, &prefix, &wanted, &cancel, &events)
        .await
        .expect("first apply");
    assert_eq!(first.present(), ["no-desktop-integration"]);
    assert!(
        first
            .outcomes
            .iter()
            .all(|o| o.state == ComponentState::Installed),
        "{first:?}"
    );
    assert!(
        override_present(&runtime, &prefix)
            .await
            .expect("query after applying"),
        "the verb wrote the value"
    );
    assert_eq!(
        prefix.components().expect("record"),
        ["no-desktop-integration"]
    );

    // The gate's property: applying again succeeds and does nothing, and the record does not grow a
    // second entry for the same verb.
    let second = addons
        .ensure(&manifest, &prefix, &wanted, &cancel, &events)
        .await
        .expect("second apply");
    assert!(
        second
            .outcomes
            .iter()
            .all(|o| o.state == ComponentState::AlreadyPresent),
        "{second:?}"
    );
    assert_eq!(
        prefix.components().expect("record"),
        ["no-desktop-integration"]
    );

    // With the record cleared, the ops themselves still have to converge rather than failing on a value
    // that is already set. That is what keeps an interrupted apply recoverable, and it is the part the
    // record cannot stand in for.
    forget_components(&prefix).expect("clear the record");
    let third = addons
        .ensure(&manifest, &prefix, &wanted, &cancel, &events)
        .await
        .expect("apply over a value that is already set");
    assert!(
        third
            .outcomes
            .iter()
            .all(|o| o.state == ComponentState::Installed),
        "{third:?}"
    );
    assert!(
        override_present(&runtime, &prefix)
            .await
            .expect("query after re-applying"),
        "the value is still there"
    );
}

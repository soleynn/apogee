#![cfg(target_os = "linux")]
//! Running a program inside a real prefix (feature `wine-integration`, run only in the wine-present
//! CI job).
//!
//! The in-module tests compose the command against a shell script standing in for the runner, which
//! proves the argv and the budget but not that wine agrees. These prove the part only stock wine can:
//! that `reg` resolves as a program inside a prefix under both a plain name and a redirected launcher,
//! that a write is visible to a later read, and that repeating it changes nothing.
//!
//! The read-back here is an exit status, never parsed text. `reg query`'s output goes through wine's
//! console layer and lands in the console codepage when redirected, so its bytes are not an interface;
//! its exit status is.

use std::error::Error;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use apogee_fetch::Fetcher;
use apogee_runtime::{
    Prefix, ProgramInPrefix, Progress, RegistryEdit, RegistryValue, RunnerKind, Runtime,
    RuntimePaths,
};
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

/// A wineboot-initialized prefix under `root`, using stock wine.
async fn prepared(root: &Path) -> Result<(Runtime, Prefix), Box<dyn Error>> {
    let runtime = Runtime::new(
        Fetcher::builder().build()?,
        RuntimePaths {
            runners: root.join("runners"),
            prefixes: root.join("prefixes"),
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
    Ok((runtime, prefix))
}

const KEY: &str = r"HKCU\Software\Apogee\PrefixProgramTest";

fn edit(value: &str) -> RegistryEdit {
    RegistryEdit {
        key: KEY.to_owned(),
        name: "Setting".to_owned(),
        value: RegistryValue::String(value.to_owned()),
    }
}

/// Whether the test value is present, by exit status alone.
async fn value_present(runtime: &Runtime, prefix: &Prefix) -> Result<bool, Box<dyn Error>> {
    let query = ProgramInPrefix::new(
        "reg",
        vec![
            "query".to_owned(),
            KEY.to_owned(),
            "/v".to_owned(),
            "Setting".to_owned(),
        ],
    );
    Ok(runtime
        .run_in_prefix(prefix, &query, &CancellationToken::new())
        .await?
        .ok())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[serial]
async fn a_registry_write_lands_and_repeating_it_changes_nothing() {
    let root = tempfile::tempdir().expect("tempdir");
    let (runtime, prefix) = prepared(root.path()).await.expect("prepare under wine");
    let cancel = CancellationToken::new();

    assert!(
        !value_present(&runtime, &prefix).await.expect("query"),
        "the value cannot already be there in a fresh prefix"
    );

    runtime
        .registry_set(&prefix, &edit("first"), &cancel)
        .await
        .expect("the first write");
    assert!(
        value_present(&runtime, &prefix).await.expect("query"),
        "the write landed"
    );

    // The point of `/f`: the second write overwrites rather than prompting, so it succeeds instead of
    // blocking on a question nobody can answer.
    runtime
        .registry_set(&prefix, &edit("first"), &cancel)
        .await
        .expect("the same write again");
    runtime
        .registry_set(&prefix, &edit("second"), &cancel)
        .await
        .expect("a changed write");
    assert!(value_present(&runtime, &prefix).await.expect("query"));
}

/// A program the prefix does not have is a non-zero status from the runner, not a launcher error: the
/// distinction is what lets a setup step report "that step failed" instead of "the launcher broke".
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[serial]
async fn a_program_the_prefix_does_not_have_reports_a_status() {
    let root = tempfile::tempdir().expect("tempdir");
    let (runtime, prefix) = prepared(root.path()).await.expect("prepare under wine");

    let run = runtime
        .run_in_prefix(
            &prefix,
            &ProgramInPrefix::new("apogee-no-such-program.exe", Vec::new()),
            &CancellationToken::new(),
        )
        .await
        .expect("the run itself completed");
    assert!(!run.ok(), "a missing program is not a success");
}

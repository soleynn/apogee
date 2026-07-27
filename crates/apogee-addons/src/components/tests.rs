//! Installing components against a scratch prefix and a chaos-served archive.
//!
//! No wine and no network here. The prefix is a handle over a temporary directory, and the archives are
//! built in-process and served by the test HTTP server, which is what makes the properties that matter
//! checkable: where files land, what the prefix records, that a second run does nothing, and that a pin
//! that does not match stops before anything is written.

use std::io::{Cursor, Write};
use std::time::Duration;

use apogee_fetch::Fetcher;
use apogee_runtime::{Prefix, RunnerKind, Runtime, RuntimePaths};
use apogee_test_support::chaos::{ChaosServer, sha256_of};
use tokio_util::sync::CancellationToken;
use zip::write::SimpleFileOptions;

use super::*;

/// A component archive: a wrapping top directory, a Windows program, and a launcher script.
fn component_zip(top: &str) -> Vec<u8> {
    let mut writer = zip::ZipWriter::new(Cursor::new(Vec::new()));
    let plain = SimpleFileOptions::DEFAULT.last_modified_time(zip::DateTime::default());
    writer.start_file(format!("{top}/tool.exe"), plain).unwrap();
    writer.write_all(b"MZ").unwrap();
    // Left non-executable on purpose, which is how a script comes out of an archive built on Windows:
    // the install is what has to make it runnable.
    writer.start_file(format!("{top}/run.sh"), plain).unwrap();
    writer.write_all(b"#!/bin/sh\nexit 0\n").unwrap();
    writer.finish().unwrap().into_inner()
}

/// A prefix handle over a scratch directory with a wine skeleton, plus the addon paths beside it.
fn scratch(root: &std::path::Path) -> (Prefix, AddonPaths) {
    apogee_test_support::sandbox::write_prefix_skeleton(root).unwrap();
    let prefix = Prefix::for_testing(
        root,
        root.join("runner"),
        RunnerKind::Wine,
        "wine",
        "custom",
    );
    let paths = AddonPaths {
        components: root.join("components"),
    };
    (prefix, paths)
}

fn runtime() -> Runtime {
    Runtime::new(Fetcher::builder().build().unwrap(), RuntimePaths::default())
}

/// A manifest offering one prefix tool and one native tool, both served from `server`, plus the verb the
/// first one asks for. The verb has no ops, so it records without needing a wine.
fn manifest(server: &ChaosServer, pin: &str) -> ComponentManifest {
    let json = format!(
        r#"{{
          "version": 1,
          "tools": [
            {{ "name": "InPrefix", "version": "1.2", "kind": "prefix_tool",
               "url": "{url}", "sha256": "{pin}",
               "archive": {{ "format": "zip", "strip_prefix": "top" }},
               "into": "apogee/InPrefix",
               "verbs": ["marker"],
               "caveats": ["It wants something this launcher does not install."],
               "register": {{ "program": "tool.exe", "args": ["-portable"],
                              "trigger": "with_game" }} }},
            {{ "name": "Native", "version": "3.4", "kind": "external_native",
               "url": "{url}", "sha256": "{pin}",
               "archive": {{ "format": "zip", "strip_prefix": "top" }},
               "into": "Native",
               "register": {{ "program": "run.sh", "args": [], "trigger": "with_game" }} }}
          ],
          "verbs": [
            {{ "name": "marker", "reason": "Recorded without touching anything.", "ops": [] }},
            {{ "name": "checked", "reason": "It states what it produces.",
               "verify": ["apogee/checked/tool.exe"],
               "ops": [ {{ "files": {{ "url": "{url}", "sha256": "{pin}",
                                       "archive": {{ "format": "zip", "strip_prefix": "top" }},
                                       "into": "apogee/checked" }} }} ] }},
            {{ "name": "unproduced", "reason": "Its op runs but produces nothing it names.",
               "verify": ["apogee/never/lands.dll"],
               "ops": [ {{ "files": {{ "url": "{url}", "sha256": "{pin}",
                                       "archive": {{ "format": "zip", "strip_prefix": "top" }},
                                       "into": "apogee/elsewhere" }} }} ] }},
            {{ "name": "unfixable", "reason": "Its op cannot succeed.",
               "ops": [ {{ "files": {{ "url": "{url}", "sha256": "{wrong_pin}",
                                       "archive": {{ "format": "zip" }},
                                       "into": "apogee/verb" }} }} ] }}
          ]
        }}"#,
        url = server.url("component.zip"),
        // A pin the served bytes cannot match, so the op fails without needing a wine.
        wrong_pin = "f".repeat(64),
    );
    ComponentManifest::from_json_bytes(json.as_bytes()).expect("fixture parses")
}

async fn ensure_all(
    prefix: &Prefix,
    paths: &AddonPaths,
    manifest: &ComponentManifest,
    wanted: &[&str],
    events: &ComponentEvents,
) -> Result<ComponentReport> {
    ensure_with(
        prefix,
        paths,
        manifest,
        wanted,
        &CancellationToken::new(),
        events,
    )
    .await
}

async fn ensure_with(
    prefix: &Prefix,
    paths: &AddonPaths,
    manifest: &ComponentManifest,
    wanted: &[&str],
    cancel: &CancellationToken,
    events: &ComponentEvents,
) -> Result<ComponentReport> {
    let fetcher = Fetcher::builder().build().unwrap();
    let wanted: Vec<String> = wanted.iter().map(|s| (*s).to_owned()).collect();
    ensure(
        &runtime(),
        &fetcher,
        paths,
        manifest,
        prefix,
        &wanted,
        cancel,
        events,
    )
    .await
}

fn collect(rx: &mut tokio::sync::mpsc::UnboundedReceiver<ComponentEvent>) -> Vec<ComponentEvent> {
    let mut out = Vec::new();
    while let Ok(event) = rx.try_recv() {
        out.push(event);
    }
    out
}

/// The names the prefix records, which is what these assertions are about; the versions have their own
/// test in the planner.
fn recorded(prefix: &Prefix) -> Vec<String> {
    prefix
        .components()
        .expect("record")
        .iter()
        .map(|c| c.name().to_owned())
        .collect()
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut out, b| {
        let _ = write!(out, "{b:02x}");
        out
    })
}

/// Where each kind of component lands, that the prefix records both of them plus the verb one of them
/// asked for, and that the caveats reach the caller while it happens.
#[tokio::test]
async fn installing_puts_each_kind_where_it_belongs_and_records_it() {
    let zip = component_zip("top");
    let pin = hex(&sha256_of(&zip));
    let server = ChaosServer::serving(zip).start().await.unwrap();

    let dir = tempfile::tempdir().unwrap();
    let (prefix, paths) = scratch(dir.path());
    let manifest = manifest(&server, &pin);
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();

    let report = ensure_all(
        &prefix,
        &paths,
        &manifest,
        &["InPrefix", "Native"],
        &ComponentEvents::new(tx),
    )
    .await
    .expect("ensure");

    assert!(!report.any_failed(), "{report:?}");
    // The verb the prefix tool asked for is in the report too, ahead of it.
    assert_eq!(report.present(), ["marker", "InPrefix", "Native"]);

    // A prefix tool goes under the prefix's C: drive; a native one goes under the host component dir.
    assert!(
        prefix.drive_c().join("apogee/InPrefix/tool.exe").is_file(),
        "the prefix tool landed inside the prefix"
    );
    assert!(
        paths.components.join("Native/run.sh").is_file(),
        "the native tool landed on the host"
    );

    assert_eq!(recorded(&prefix), ["marker", "InPrefix", "Native"]);

    // The caveat is reported while the component is being set up, which is the only time it is useful.
    let events = collect(&mut rx);
    assert!(
        events.iter().any(|e| matches!(
            e,
            ComponentEvent::Caveat { component, .. } if component == "InPrefix"
        )),
        "the caveat was reported: {events:?}"
    );
    assert!(
        events
            .iter()
            .any(|e| matches!(e, ComponentEvent::Applying { verb, .. } if verb == "marker")),
        "the verb said why it was running: {events:?}"
    );
}

/// The whole point of recording an install: the second one does nothing and fetches nothing.
#[tokio::test]
async fn a_second_ensure_installs_nothing_and_downloads_nothing() {
    let zip = component_zip("top");
    let pin = hex(&sha256_of(&zip));
    let server = ChaosServer::serving(zip).start().await.unwrap();

    let dir = tempfile::tempdir().unwrap();
    let (prefix, paths) = scratch(dir.path());
    let manifest = manifest(&server, &pin);

    ensure_all(
        &prefix,
        &paths,
        &manifest,
        &["InPrefix"],
        &ComponentEvents::none(),
    )
    .await
    .expect("first ensure");
    let after_first = server.stats().requests();

    let report = ensure_all(
        &prefix,
        &paths,
        &manifest,
        &["InPrefix"],
        &ComponentEvents::none(),
    )
    .await
    .expect("second ensure");

    assert!(
        report
            .outcomes
            .iter()
            .all(|o| o.state == ComponentState::AlreadyPresent),
        "{report:?}"
    );
    assert_eq!(
        server.stats().requests(),
        after_first,
        "a recorded component must not be re-fetched"
    );
    // And the record did not grow a duplicate.
    assert_eq!(recorded(&prefix), ["marker", "InPrefix"]);
}

/// A native component's directory is shared by every profile, so a second prefix wanting the same
/// companion has to find it rather than fetch it again.
#[tokio::test]
async fn a_native_component_is_fetched_once_across_prefixes() {
    let zip = component_zip("top");
    let pin = hex(&sha256_of(&zip));
    let server = ChaosServer::serving(zip).start().await.unwrap();

    let dir = tempfile::tempdir().unwrap();
    let shared = AddonPaths {
        components: dir.path().join("components"),
    };
    let manifest = manifest(&server, &pin);

    for name in ["first", "second"] {
        let root = dir.path().join(name);
        std::fs::create_dir_all(&root).unwrap();
        let (prefix, _) = scratch(&root);
        ensure_all(
            &prefix,
            &shared,
            &manifest,
            &["Native"],
            &ComponentEvents::none(),
        )
        .await
        .expect("ensure");
        // Each prefix records it for itself: whether this profile has it is a different question from
        // whether the bytes are on this machine.
        assert_eq!(recorded(&prefix), ["Native"]);
    }
    assert_eq!(
        server.stats().requests(),
        1,
        "the second prefix reused the host install"
    );

    // A marker on its own would make a deleted component directory unrecoverable: the fetch would be
    // skipped and the registration check would then fail on the missing program, forever.
    std::fs::remove_dir_all(shared.components.join("Native")).unwrap();
    let root = dir.path().join("third");
    std::fs::create_dir_all(&root).unwrap();
    let (prefix, _) = scratch(&root);
    ensure_all(
        &prefix,
        &shared,
        &manifest,
        &["Native"],
        &ComponentEvents::none(),
    )
    .await
    .expect("ensure");
    assert!(shared.components.join("Native/run.sh").is_file());
    assert_eq!(
        server.stats().requests(),
        2,
        "a component whose files are gone is fetched again"
    );
}

/// A native companion is exec'd by the launcher itself, and a component archive is built on Windows,
/// where nothing carries an executable bit: an entry point arrives unrunnable unless the install says
/// otherwise.
#[tokio::test]
async fn a_native_companions_entry_point_is_made_executable() {
    use std::os::unix::fs::PermissionsExt;

    let zip = component_zip("top");
    let pin = hex(&sha256_of(&zip));
    let server = ChaosServer::serving(zip).start().await.unwrap();

    let dir = tempfile::tempdir().unwrap();
    let (prefix, paths) = scratch(dir.path());
    ensure_all(
        &prefix,
        &paths,
        &manifest(&server, &pin),
        &["Native"],
        &ComponentEvents::none(),
    )
    .await
    .expect("ensure");

    let program = paths.components.join("Native/run.sh");
    let mode = std::fs::metadata(&program).unwrap().permissions().mode();
    assert_ne!(mode & 0o100, 0, "the launcher script is executable");
}

/// A run somebody stopped is not a run that failed. Every step left over would fail on its own once the
/// token fires (a download returns cancelled, a verb's process is killed the moment it starts), and the
/// caller counts failures to decide the install did not work: recording them would tell a user who
/// pressed ctrl-c that their components could not be installed.
#[tokio::test]
async fn a_cancelled_run_ends_rather_than_failing_every_step_that_is_left() {
    let zip = component_zip("top");
    let pin = hex(&sha256_of(&zip));
    let server = ChaosServer::serving(zip).start().await.unwrap();

    let dir = tempfile::tempdir().unwrap();
    let (prefix, paths) = scratch(dir.path());
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    let cancel = CancellationToken::new();
    cancel.cancel();

    // "InPrefix" is two steps: the verb it requires, which needs nothing and would otherwise apply
    // happily, and the tool itself, whose download is what returns cancelled.
    let err = ensure_with(
        &prefix,
        &paths,
        &manifest(&server, &pin),
        &["InPrefix"],
        &cancel,
        &ComponentEvents::new(tx),
    )
    .await
    .expect_err("a cancelled run is not a report of failures");

    assert!(matches!(err, AddonError::Cancelled), "{err:?}");
    assert_eq!(
        server.stats().requests(),
        0,
        "nothing was fetched after the token fired"
    );
    assert!(
        recorded(&prefix).is_empty(),
        "a run that stopped before doing anything leaves the prefix as it found it"
    );
    let events = collect(&mut rx);
    assert!(
        !events
            .iter()
            .any(|e| matches!(e, ComponentEvent::Failed { .. })),
        "no component failed; the run stopped: {events:?}"
    );
}

/// Ctrl-c does not wait for a step boundary. The step that was running when the token fired is the one
/// that comes back with an error, and the check at the top of the loop cannot have seen it: it ran before
/// the step started. Letting that error fall through to the ordinary failure path would put a
/// `Failed` event and a failed outcome against a component nothing is wrong with, which is the same
/// "your components could not be installed" the step-boundary check exists to avoid.
///
/// The token fires once the server has actually written body bytes, so the download is genuinely open
/// rather than refused at the start; the server then hangs, so it cannot finish while the test is
/// arranging that.
#[tokio::test]
async fn a_step_cancelled_while_it_was_running_is_not_a_component_that_failed() {
    let zip = component_zip("top");
    let pin = hex(&sha256_of(&zip));
    // A chunk, then a hang with no more data and no EOF: the download is in flight and stays there.
    let slow = ChaosServer::serving(zip.clone())
        .chunk(32)
        .throttle(Duration::from_millis(50))
        .stall_after(32)
        .start()
        .await
        .unwrap();
    // The step after it lives on its own server, so "never attempted" is a request count rather than an
    // inference from the report.
    let later = ChaosServer::serving(zip).start().await.unwrap();

    let dir = tempfile::tempdir().unwrap();
    let (prefix, paths) = scratch(dir.path());
    let json = format!(
        r#"{{
          "version": 1,
          "tools": [
            {{ "name": "InPrefix", "version": "1", "kind": "prefix_tool",
               "url": "{slow_url}", "sha256": "{pin}",
               "archive": {{ "format": "zip", "strip_prefix": "top" }},
               "into": "apogee/InPrefix", "verbs": ["marker"] }},
            {{ "name": "Native", "version": "1", "kind": "external_native",
               "url": "{later_url}", "sha256": "{pin}",
               "archive": {{ "format": "zip", "strip_prefix": "top" }},
               "into": "Native" }}
          ],
          "verbs": [
            {{ "name": "marker", "reason": "Recorded without touching anything.", "ops": [] }}
          ]
        }}"#,
        slow_url = slow.url("component.zip"),
        later_url = later.url("component.zip"),
    );
    let manifest = ComponentManifest::from_json_bytes(json.as_bytes()).expect("fixture parses");
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    let events = ComponentEvents::new(tx);
    let cancel = CancellationToken::new();

    // Joined rather than spawned so the canceller can watch this server's counters by reference, and
    // timed out so a token the download does not honor fails the test instead of hanging on the stall.
    let (result, ()) = tokio::time::timeout(Duration::from_secs(30), async {
        tokio::join!(
            ensure_with(
                &prefix,
                &paths,
                &manifest,
                &["InPrefix", "Native"],
                &cancel,
                &events,
            ),
            async {
                while slow.stats().bytes_served() == 0 {
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
                cancel.cancel();
            }
        )
    })
    .await
    .expect("a cancelled install must not sit on the stalled download");

    let err = result.expect_err("a run somebody stopped is not a report of failures");
    assert!(matches!(err, AddonError::Cancelled), "{err:?}");
    let emitted = collect(&mut rx);
    assert!(
        !emitted
            .iter()
            .any(|e| matches!(e, ComponentEvent::Failed { .. })),
        "the step the token interrupted is not a component that failed: {emitted:?}"
    );
    assert_eq!(
        recorded(&prefix),
        ["marker"],
        "the verb ahead of it applied; the interrupted tool is not remembered as installed"
    );
    assert_eq!(
        later.stats().requests(),
        0,
        "the run stopped at the interrupted step rather than working through what was left"
    );
}

/// The other half of the same problem, and the worse half: a step that answers success in the instant
/// the token fires. There is no error to read, so a run stopped during its last step falls off the end of
/// the plan and hands back a report of installed components, telling a user who pressed ctrl-c that the
/// install they stopped worked. Whether the step really finished or a callee cut it short and called it
/// done is not something this layer can see, which is why it reads the token rather than trusting the
/// answer.
///
/// The token is fired from the artifact's own progress, on the frame the fetcher emits once the body is
/// in and it turns to hashing it. Past that point the transfer consults the token no more, so the step
/// runs on to a genuine success with the token already gone: the ordering this needs, arrived at by
/// construction rather than by waiting for it.
#[tokio::test]
async fn a_step_that_finished_as_the_token_fired_stops_the_run_rather_than_reporting_success() {
    let zip = component_zip("top");
    let pin = hex(&sha256_of(&zip));
    let server = ChaosServer::serving(zip).start().await.unwrap();

    let dir = tempfile::tempdir().unwrap();
    let (prefix, paths) = scratch(dir.path());
    let manifest = manifest(&server, &pin);
    let cancel = CancellationToken::new();

    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    // Left to run rather than awaited: it ends when the sink closes, and its result is the token.
    let _watcher = {
        let cancel = cancel.clone();
        tokio::spawn(async move {
            while let Some(event) = rx.recv().await {
                if let ComponentEvent::Downloading {
                    bytes_done,
                    total: Some(total),
                    ..
                } = event
                    && bytes_done > 0
                    && bytes_done == total
                {
                    cancel.cancel();
                }
            }
        })
    };

    // One step, so its outcome is the last thing the loop reads: the run ends on this step's answer or
    // it ends on the plan running out.
    let err = ensure_with(
        &prefix,
        &paths,
        &manifest,
        &["Native"],
        &cancel,
        &ComponentEvents::new(tx),
    )
    .await
    .expect_err("a run stopped while its last step was running did not install what was asked for");
    assert!(matches!(err, AddonError::Cancelled), "{err:?}");
    // And the step's own record stands: the files are there, the work happened, and a stop is not a
    // reason to make the next run do it again.
    assert_eq!(recorded(&prefix), ["Native"]);
    assert!(paths.components.join("Native/run.sh").is_file());
}

/// The one install path that does no work: a native component already on this machine is skipped rather
/// than fetched. Skipping is not the same as having installed it, so a cancelled run must not return
/// success from here, which is what would get the component recorded in the prefix and reported
/// installed by a run that installed nothing.
#[tokio::test]
async fn a_skipped_native_component_is_not_reported_installed_after_cancellation() {
    let zip = component_zip("top");
    let pin = hex(&sha256_of(&zip));
    let server = ChaosServer::serving(zip).start().await.unwrap();

    let dir = tempfile::tempdir().unwrap();
    let (prefix, paths) = scratch(dir.path());
    let manifest = manifest(&server, &pin);
    // A first run puts the files on the host and seals the marker a later run skips on.
    ensure_all(
        &prefix,
        &paths,
        &manifest,
        &["Native"],
        &ComponentEvents::none(),
    )
    .await
    .expect("first ensure");

    let dest = paths.components.join("Native");
    let cancel = CancellationToken::new();
    cancel.cancel();
    let err = install_native(
        &Fetcher::builder().build().unwrap(),
        &paths,
        manifest.tool("Native").expect("the fixture row"),
        &dest,
        Some(&dest.join("run.sh")),
        &dir.path().join("work"),
        &cancel,
        &ComponentEvents::none(),
    )
    .await
    .expect_err("a skip that outlives the run is the one thing cancellation must not leave behind");
    assert!(matches!(err, AddonError::Cancelled), "{err:?}");
}

/// The pin is what authenticates the bytes, so a mismatch has to stop before anything is laid down, and
/// must not be remembered as installed.
#[tokio::test]
async fn an_artifact_that_does_not_match_its_pin_fails_that_component_only() {
    let zip = component_zip("top");
    let wrong = hex(&sha256_of(b"not this archive"));
    let server = ChaosServer::serving(zip).start().await.unwrap();

    let dir = tempfile::tempdir().unwrap();
    let (prefix, paths) = scratch(dir.path());
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();

    let report = ensure_all(
        &prefix,
        &paths,
        &manifest(&server, &wrong),
        &["InPrefix"],
        &ComponentEvents::new(tx),
    )
    .await
    .expect("the call itself succeeds; the component is what failed");

    assert!(report.any_failed(), "{report:?}");
    // The verb ahead of it still ran, which is what per-component outcomes are for.
    assert_eq!(report.present(), ["marker"]);
    assert!(
        !prefix.drive_c().join("apogee/InPrefix").exists(),
        "nothing was written from bytes that failed their pin"
    );
    assert_eq!(
        recorded(&prefix),
        ["marker"],
        "a failed install is not recorded, so it is retried rather than remembered as done"
    );
    // The reason names the pin, not a generic download problem: the bytes arrived, they are just not the
    // bytes the signed manifest promised, and that distinction is what tells a user their catalog and
    // their mirror disagree.
    let events = collect(&mut rx);
    let reason = events
        .iter()
        .find_map(|e| match e {
            ComponentEvent::Failed { component, reason } if component == "InPrefix" => {
                Some(reason.clone())
            }
            _ => None,
        })
        .unwrap_or_else(|| panic!("no failure reported: {events:?}"));
    assert!(
        reason.contains("integrity mismatch"),
        "a pin failure is reported as one: {reason}"
    );
}

/// An archive whose layout does not match its row yields nothing, and sealing that as installed would
/// leave an empty directory nobody ever fixes.
#[tokio::test]
async fn an_archive_that_does_not_match_its_declared_layout_fails() {
    let zip = component_zip("elsewhere");
    let pin = hex(&sha256_of(&zip));
    let server = ChaosServer::serving(zip).start().await.unwrap();

    let dir = tempfile::tempdir().unwrap();
    let (prefix, paths) = scratch(dir.path());
    let report = ensure_all(
        &prefix,
        &paths,
        &manifest(&server, &pin),
        &["InPrefix"],
        &ComponentEvents::none(),
    )
    .await
    .expect("call");

    assert!(report.any_failed(), "{report:?}");
    assert!(!recorded(&prefix).contains(&"InPrefix".to_owned()));
}

/// A verb whose op failed must not be recorded, or the prefix would claim a setup step that never landed
/// and the next run would skip it. The tool path has its own test for this; a verb takes the other branch.
#[tokio::test]
async fn a_verb_whose_op_fails_is_not_recorded() {
    let zip = component_zip("top");
    let pin = hex(&sha256_of(&zip));
    let server = ChaosServer::serving(zip).start().await.unwrap();

    let dir = tempfile::tempdir().unwrap();
    let (prefix, paths) = scratch(dir.path());
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();

    let report = ensure_all(
        &prefix,
        &paths,
        &manifest(&server, &pin),
        &["unfixable"],
        &ComponentEvents::new(tx),
    )
    .await
    .expect("the call itself succeeds");

    assert!(report.any_failed(), "{report:?}");
    assert!(
        recorded(&prefix).is_empty(),
        "a verb that did not apply is not remembered as applied"
    );
    let events = collect(&mut rx);
    assert!(
        events.iter().any(|e| matches!(
            e,
            ComponentEvent::Failed { component, .. } if component == "unfixable"
        )),
        "{events:?}"
    );
    assert!(
        !events
            .iter()
            .any(|e| matches!(e, ComponentEvent::Applied { .. })),
        "a verb that failed is not reported as applied: {events:?}"
    );
}

/// A verb a tool declares is the prefix setup that tool needs. Installing the tool anyway would leave a
/// component in place that cannot work, recorded as installed, so the next run skips both.
#[tokio::test]
async fn a_tool_is_not_installed_when_the_verb_it_requires_failed() {
    let zip = component_zip("top");
    let pin = hex(&sha256_of(&zip));
    let server = ChaosServer::serving(zip).start().await.unwrap();

    let dir = tempfile::tempdir().unwrap();
    let (prefix, paths) = scratch(dir.path());
    // A tool whose prerequisite is the verb that cannot succeed.
    let json = format!(
        r#"{{
          "version": 1,
          "tools": [
            {{ "name": "Blocked", "version": "1", "kind": "prefix_tool",
               "url": "{url}", "sha256": "{pin}",
               "archive": {{ "format": "zip", "strip_prefix": "top" }},
               "into": "apogee/Blocked", "verbs": ["unfixable"] }}
          ],
          "verbs": [
            {{ "name": "checked", "reason": "It states what it produces.",
               "verify": ["apogee/checked/tool.exe"],
               "ops": [ {{ "files": {{ "url": "{url}", "sha256": "{pin}",
                                       "archive": {{ "format": "zip", "strip_prefix": "top" }},
                                       "into": "apogee/checked" }} }} ] }},
            {{ "name": "unproduced", "reason": "Its op runs but produces nothing it names.",
               "verify": ["apogee/never/lands.dll"],
               "ops": [ {{ "files": {{ "url": "{url}", "sha256": "{pin}",
                                       "archive": {{ "format": "zip", "strip_prefix": "top" }},
                                       "into": "apogee/elsewhere" }} }} ] }},
            {{ "name": "unfixable", "reason": "Its op cannot succeed.",
               "ops": [ {{ "files": {{ "url": "{url}", "sha256": "{wrong}",
                                       "archive": {{ "format": "zip" }},
                                       "into": "apogee/verb" }} }} ] }}
          ]
        }}"#,
        url = server.url("component.zip"),
        wrong = "f".repeat(64),
    );
    let manifest = ComponentManifest::from_json_bytes(json.as_bytes()).expect("parse");

    let report = ensure_all(
        &prefix,
        &paths,
        &manifest,
        &["Blocked"],
        &ComponentEvents::none(),
    )
    .await
    .expect("call");

    assert!(report.present().is_empty(), "{report:?}");
    assert!(
        recorded(&prefix).is_empty(),
        "neither the verb nor the tool it blocks is recorded"
    );
    assert!(
        !prefix.drive_c().join("apogee/Blocked").exists(),
        "the tool's files were never laid down"
    );
    // And the reason points at the setup rather than at the tool's own download, which succeeded.
    let blocked = report
        .outcomes
        .iter()
        .find(|o| o.name == "Blocked")
        .expect("an outcome for the tool");
    match &blocked.state {
        ComponentState::Failed { reason } => assert!(
            reason.contains("unfixable"),
            "the reason names the setup that did not apply: {reason}"
        ),
        other => panic!("expected a failure, got {other:?}"),
    }
}

/// A registration naming a program the archive does not contain is a manifest mistake, and finding it at
/// install time is the difference between "that row is wrong" and a spawn failure at the next launch.
#[tokio::test]
async fn a_registration_naming_a_program_the_archive_lacks_fails_the_component() {
    let zip = component_zip("top");
    let pin = hex(&sha256_of(&zip));
    let server = ChaosServer::serving(zip).start().await.unwrap();

    let dir = tempfile::tempdir().unwrap();
    let (prefix, paths) = scratch(dir.path());
    // The archive holds `tool.exe`, not `missing.exe`.
    let json = serde_json::to_string(&serde_json::json!({
        "version": 1,
        "tools": [{
            "name": "InPrefix", "version": "1.2", "kind": "prefix_tool",
            "url": server.url("component.zip").to_string(), "sha256": pin,
            "archive": { "format": "zip", "strip_prefix": "top" },
            "into": "apogee/InPrefix",
            "register": { "program": "missing.exe", "args": [], "trigger": "with_game" }
        }]
    }))
    .unwrap();
    let manifest = ComponentManifest::from_json_bytes(json.as_bytes()).expect("parse");

    let report = ensure_all(
        &prefix,
        &paths,
        &manifest,
        &["InPrefix"],
        &ComponentEvents::none(),
    )
    .await
    .expect("call");

    assert!(report.any_failed(), "{report:?}");
    assert!(
        recorded(&prefix).is_empty(),
        "a component whose registration cannot be honored is not recorded as installed"
    );
}

/// A launch reads its companions from the manifest every time, so where each program is and how it runs
/// follows the manifest rather than a copy taken when it was installed.
#[test]
fn registrations_point_at_where_each_kind_was_installed() {
    let dir = tempfile::tempdir().unwrap();
    let (prefix, paths) = scratch(dir.path());
    // Recorded as installed, since a launch only starts what is actually there.
    prefix.record_component("InPrefix", Some("1")).unwrap();
    prefix.record_component("Native", Some("1")).unwrap();
    prefix.record_component("Unstarted", Some("1")).unwrap();
    let json = r#"{
      "version": 1,
      "tools": [
        { "name": "InPrefix", "version": "1", "kind": "prefix_tool",
          "url": "https://example.invalid/a.zip",
          "sha256": "0000000000000000000000000000000000000000000000000000000000000000",
          "archive": { "format": "zip" }, "into": "apogee/InPrefix",
          "register": { "program": "tool.exe", "args": ["-portable"], "trigger": "with_game" } },
        { "name": "Native", "version": "1", "kind": "external_native",
          "url": "https://example.invalid/b.zip",
          "sha256": "0000000000000000000000000000000000000000000000000000000000000000",
          "archive": { "format": "zip" }, "into": "Native",
          "register": { "program": "run.sh", "args": [], "trigger": "on_close" } },
        { "name": "Unstarted", "version": "1", "kind": "prefix_tool",
          "url": "https://example.invalid/c.zip",
          "sha256": "0000000000000000000000000000000000000000000000000000000000000000",
          "archive": { "format": "zip" }, "into": "apogee/Unstarted" }
      ],
      "verbs": [ { "name": "marker", "reason": "r", "ops": [] } ]
    }"#;
    let manifest = ComponentManifest::from_json_bytes(json.as_bytes()).expect("parse");

    let wanted: Vec<String> = ["InPrefix", "Native", "Unstarted", "marker"]
        .into_iter()
        .map(str::to_owned)
        .collect();
    let addons = registrations(&paths, &manifest, &prefix, &wanted).expect("registrations");

    // A component with no registration, and a verb, both contribute nothing to a launch.
    assert_eq!(addons.len(), 2, "{addons:?}");
    assert_eq!(addons[0].run_in(), RunIn::Prefix);
    assert_eq!(
        addons[0].program(),
        prefix.drive_c().join("apogee/InPrefix/tool.exe")
    );
    assert_eq!(addons[0].args(), ["-portable"]);
    assert_eq!(addons[1].run_in(), RunIn::Host);
    assert_eq!(addons[1].program(), paths.components.join("Native/run.sh"));
    assert_eq!(addons[1].trigger(), crate::Trigger::OnClose);
}

/// An enabled component that was never installed has no files, so registering it would hand the launch a
/// program that is not there and turn one un-run setup step into a spawn failure at every launch.
#[test]
fn registrations_skip_a_component_the_prefix_does_not_record() {
    let dir = tempfile::tempdir().unwrap();
    let (prefix, paths) = scratch(dir.path());
    let json = r#"{
      "version": 1,
      "tools": [
        { "name": "Installed", "version": "1", "kind": "prefix_tool",
          "url": "https://example.invalid/a.zip",
          "sha256": "0000000000000000000000000000000000000000000000000000000000000000",
          "archive": { "format": "zip" }, "into": "apogee/Installed",
          "register": { "program": "tool.exe", "args": [], "trigger": "with_game" } },
        { "name": "Enabled", "version": "1", "kind": "prefix_tool",
          "url": "https://example.invalid/b.zip",
          "sha256": "0000000000000000000000000000000000000000000000000000000000000000",
          "archive": { "format": "zip" }, "into": "apogee/Enabled",
          "register": { "program": "tool.exe", "args": [], "trigger": "with_game" } }
      ]
    }"#;
    let manifest = ComponentManifest::from_json_bytes(json.as_bytes()).expect("parse");
    prefix.record_component("Installed", Some("1")).unwrap();

    let wanted: Vec<String> = ["Installed", "Enabled"]
        .into_iter()
        .map(str::to_owned)
        .collect();
    let addons = registrations(&paths, &manifest, &prefix, &wanted).expect("registrations");
    assert_eq!(addons.len(), 1, "{addons:?}");
    assert_eq!(
        addons[0].program(),
        prefix.drive_c().join("apogee/Installed/tool.exe")
    );
}

/// A verb is judged on what it produced, not on whether its ops returned success. Several vendor
/// installers exit zero having done nothing, which is exactly the case this exists for.
#[tokio::test]
async fn a_verb_that_did_not_produce_what_it_names_is_a_failure() {
    let zip = component_zip("top");
    let pin = hex(&sha256_of(&zip));
    let server = ChaosServer::serving(zip).start().await.unwrap();

    let dir = tempfile::tempdir().unwrap();
    let (prefix, paths) = scratch(dir.path());
    let manifest = manifest(&server, &pin);

    // Its file op succeeds, but into a different place than it claims to verify.
    let report = ensure_all(
        &prefix,
        &paths,
        &manifest,
        &["unproduced"],
        &ComponentEvents::none(),
    )
    .await
    .expect("call");
    assert!(report.any_failed(), "{report:?}");
    assert!(recorded(&prefix).is_empty());
    // The files it did place are there; the verb still failed, because what it promised is not.
    assert!(prefix.drive_c().join("apogee/elsewhere/tool.exe").is_file());

    // And one that does produce what it names succeeds and is recorded.
    let report = ensure_all(
        &prefix,
        &paths,
        &manifest,
        &["checked"],
        &ComponentEvents::none(),
    )
    .await
    .expect("call");
    assert!(!report.any_failed(), "{report:?}");
    assert_eq!(recorded(&prefix), ["checked"]);
}

/// The point of a verb saying what it produces: when a runner upgrade removes it, the next run notices
/// and puts it back, rather than skipping it forever on the strength of the record.
#[tokio::test]
async fn a_recorded_verb_whose_effect_was_removed_is_applied_again() {
    let zip = component_zip("top");
    let pin = hex(&sha256_of(&zip));
    let server = ChaosServer::serving(zip).start().await.unwrap();

    let dir = tempfile::tempdir().unwrap();
    let (prefix, paths) = scratch(dir.path());
    let manifest = manifest(&server, &pin);

    ensure_all(
        &prefix,
        &paths,
        &manifest,
        &["checked"],
        &ComponentEvents::none(),
    )
    .await
    .expect("first apply");
    assert_eq!(recorded(&prefix), ["checked"]);

    // Nothing changed: the record stands and the effect is there.
    let again = ensure_all(
        &prefix,
        &paths,
        &manifest,
        &["checked"],
        &ComponentEvents::none(),
    )
    .await
    .expect("second apply");
    assert!(
        again
            .outcomes
            .iter()
            .all(|o| o.state == ComponentState::AlreadyPresent),
        "{again:?}"
    );

    // Now something outside the launcher removes what it produced, which is what a Proton prefix
    // upgrade does to a .NET install.
    std::fs::remove_dir_all(prefix.drive_c().join("apogee/checked")).unwrap();
    let healed = ensure_all(
        &prefix,
        &paths,
        &manifest,
        &["checked"],
        &ComponentEvents::none(),
    )
    .await
    .expect("third apply");
    assert!(
        healed
            .outcomes
            .iter()
            .all(|o| o.state == ComponentState::Installed),
        "the record did not stop it being re-applied: {healed:?}"
    );
    assert!(prefix.drive_c().join("apogee/checked/tool.exe").is_file());
}

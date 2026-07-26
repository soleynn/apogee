//! Installing components against a scratch prefix and a chaos-served archive.
//!
//! No wine and no network here. The prefix is a handle over a temporary directory, and the archives are
//! built in-process and served by the test HTTP server, which is what makes the properties that matter
//! checkable: where files land, what the prefix records, that a second run does nothing, and that a pin
//! that does not match stops before anything is written.

use std::io::{Cursor, Write};

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
    // Left non-executable on purpose: the one native companion in the hosted manifest ships its
    // launcher script exactly this way, so the install is what has to make it runnable.
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
            {{ "name": "marker", "reason": "Recorded without touching anything.", "ops": [] }}
          ]
        }}"#,
        url = server.url("component.zip"),
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
    let fetcher = Fetcher::builder().build().unwrap();
    let wanted: Vec<String> = wanted.iter().map(|s| (*s).to_owned()).collect();
    ensure(
        &runtime(),
        &fetcher,
        paths,
        manifest,
        prefix,
        &wanted,
        &CancellationToken::new(),
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

/// A native companion is exec'd by the launcher itself, and these archives are built on Windows: the one
/// in the hosted manifest ships its launcher script without an executable bit.
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
    let events = collect(&mut rx);
    assert!(
        events.iter().any(
            |e| matches!(e, ComponentEvent::Failed { component, .. } if component == "InPrefix")
        ),
        "{events:?}"
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

    println!("REPORT: {report:?}");
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

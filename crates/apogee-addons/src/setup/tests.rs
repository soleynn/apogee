//! Applying prefix setup against a scratch prefix and a chaos-served archive.
//!
//! No wine and no network here. The prefix is a handle over a temporary directory, and the archives are
//! built in-process and served by the test HTTP server, which is what makes the properties that matter
//! checkable: what the prefix records, that a second pass does nothing, that a verb which did not land
//! is not remembered as done, and that a pin which does not match stops before anything is written.
//!
//! The verbs here carry `files` ops rather than registry ones, since a registry op needs a wine. The
//! registry path has its own test against a real one.

use std::io::{Cursor, Write};

use apogee_fetch::Fetcher;
use apogee_runtime::{Prefix, RunnerKind, Runtime, RuntimePaths};
use apogee_test_support::chaos::{ChaosServer, sha256_of};
use tokio_util::sync::CancellationToken;
use zip::write::SimpleFileOptions;

use super::*;
use crate::AddonPaths;

/// An archive with one file in it, under a wrapping top directory.
fn payload_zip(top: &str) -> Vec<u8> {
    let mut writer = zip::ZipWriter::new(Cursor::new(Vec::new()));
    let plain = SimpleFileOptions::DEFAULT.last_modified_time(zip::DateTime::default());
    writer
        .start_file(format!("{top}/thing.dll"), plain)
        .unwrap();
    writer.write_all(b"MZ").unwrap();
    writer.finish().unwrap().into_inner()
}

/// A prefix handle over a scratch directory with a wine skeleton, plus the addon root beside it.
fn scratch(root: &std::path::Path) -> (Prefix, AddonPaths) {
    apogee_test_support::sandbox::write_prefix_skeleton(root).unwrap();
    let prefix = Prefix::for_testing(
        root,
        root.join("runner"),
        RunnerKind::Wine,
        "wine",
        "custom",
    );
    (prefix, AddonPaths::new(root.join("addons")))
}

fn runtime() -> Runtime {
    Runtime::new(Fetcher::builder().build().unwrap(), RuntimePaths::default())
}

/// Three verbs: one that lands what it promises, one whose op succeeds without producing what it names,
/// and one whose op cannot succeed at all.
fn manifest(server: &ChaosServer, pin: &str) -> ComponentManifest {
    let json = format!(
        r#"{{
          "version": 1,
          "verbs": [
            {{ "name": "checked", "reason": "It states what it produces.",
               "verify": ["apogee/checked/thing.dll"],
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
        url = server.url("payload.zip"),
        // A pin the served bytes cannot match, so the op fails without needing a wine.
        wrong_pin = "f".repeat(64),
    );
    ComponentManifest::from_json_bytes(json.as_bytes()).expect("fixture parses")
}

/// Only the verb named, so one test's subject is not another's noise.
fn only(manifest: &ComponentManifest, name: &str) -> ComponentManifest {
    ComponentManifest {
        verbs: manifest
            .verbs
            .iter()
            .filter(|verb| verb.name == name)
            .cloned()
            .collect(),
        ..manifest.clone()
    }
}

async fn apply(
    prefix: &Prefix,
    manifest: &ComponentManifest,
    events: &SetupEvents,
) -> Result<SetupReport> {
    apply_with(prefix, manifest, &CancellationToken::new(), events).await
}

async fn apply_with(
    prefix: &Prefix,
    manifest: &ComponentManifest,
    cancel: &CancellationToken,
    events: &SetupEvents,
) -> Result<SetupReport> {
    let fetcher = Fetcher::builder().build().unwrap();
    apply_verbs(&runtime(), &fetcher, manifest, prefix, cancel, events).await
}

fn collect(rx: &mut tokio::sync::mpsc::UnboundedReceiver<SetupEvent>) -> Vec<SetupEvent> {
    let mut out = Vec::new();
    while let Ok(event) = rx.try_recv() {
        out.push(event);
    }
    out
}

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

async fn served() -> (ChaosServer, String) {
    let zip = payload_zip("top");
    let pin = hex(&sha256_of(&zip));
    (ChaosServer::serving(zip).start().await.unwrap(), pin)
}

/// A verb lands what it promises, is recorded, and says why it ran while it was running.
#[tokio::test]
async fn applying_a_verb_lands_its_files_and_records_it() {
    let (server, pin) = served().await;
    let dir = tempfile::tempdir().unwrap();
    let (prefix, _paths) = scratch(dir.path());
    let manifest = only(&manifest(&server, &pin), "checked");
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();

    let report = apply(&prefix, &manifest, &SetupEvents::new(tx))
        .await
        .expect("apply");

    assert!(!report.any_failed(), "{report:?}");
    assert_eq!(report.present(), ["checked"]);
    assert!(
        prefix.drive_c().join("apogee/checked/thing.dll").is_file(),
        "the verb's files landed under the prefix's C: drive"
    );
    assert_eq!(recorded(&prefix), ["checked"]);

    let events = collect(&mut rx);
    assert!(
        events
            .iter()
            .any(|e| matches!(e, SetupEvent::Applying { verb, reason } if verb == "checked" && !reason.is_empty())),
        "the verb said why it was running: {events:?}"
    );
}

/// The whole point of recording an apply: the second pass does nothing and fetches nothing.
#[tokio::test]
async fn a_second_pass_applies_nothing_and_downloads_nothing() {
    let (server, pin) = served().await;
    let dir = tempfile::tempdir().unwrap();
    let (prefix, _paths) = scratch(dir.path());
    let manifest = only(&manifest(&server, &pin), "checked");

    apply(&prefix, &manifest, &SetupEvents::none())
        .await
        .expect("first pass");
    let after_first = server.stats().requests();

    let report = apply(&prefix, &manifest, &SetupEvents::none())
        .await
        .expect("second pass");

    assert_eq!(
        report.outcomes.iter().map(|o| &o.state).collect::<Vec<_>>(),
        [&SetupState::AlreadyPresent]
    );
    assert_eq!(
        server.stats().requests(),
        after_first,
        "a pass with nothing to do makes no request"
    );
}

/// A verb whose ops "succeeded" without producing what it names is a failure, and an unrecorded one, so
/// the next pass tries again instead of remembering a half-finished apply as done.
#[tokio::test]
async fn a_verb_that_did_not_produce_what_it_names_fails_and_is_not_recorded() {
    let (server, pin) = served().await;
    let dir = tempfile::tempdir().unwrap();
    let (prefix, _paths) = scratch(dir.path());
    let manifest = only(&manifest(&server, &pin), "unproduced");

    let report = apply(&prefix, &manifest, &SetupEvents::none())
        .await
        .expect("apply");

    assert!(report.any_failed(), "{report:?}");
    assert!(
        prefix
            .drive_c()
            .join("apogee/elsewhere/thing.dll")
            .is_file(),
        "its op did land files, just not the ones it promised"
    );
    assert!(
        recorded(&prefix).is_empty(),
        "an apply that did not land is not remembered as done"
    );
}

/// A verb the record claims but whose effect has been removed from the prefix comes back. This is what a
/// runner upgrade does to prefix state a verb wrote, so it is simulated by deleting what the verb
/// produced.
#[tokio::test]
async fn a_recorded_verb_whose_effect_was_removed_is_applied_again() {
    let (server, pin) = served().await;
    let dir = tempfile::tempdir().unwrap();
    let (prefix, _paths) = scratch(dir.path());
    let manifest = only(&manifest(&server, &pin), "checked");

    apply(&prefix, &manifest, &SetupEvents::none())
        .await
        .expect("first pass");
    std::fs::remove_dir_all(prefix.drive_c().join("apogee/checked")).expect("remove the effect");

    let report = apply(&prefix, &manifest, &SetupEvents::none())
        .await
        .expect("second pass");

    assert_eq!(
        report.outcomes.iter().map(|o| &o.state).collect::<Vec<_>>(),
        [&SetupState::Applied],
        "the record does not stand in for an effect that is gone"
    );
    assert!(prefix.drive_c().join("apogee/checked/thing.dll").is_file());
}

/// One verb failing costs the prefix that verb. A launch that is otherwise fine should not be stopped by
/// one piece of hygiene, and the rest of the setup still has to happen.
#[tokio::test]
async fn one_failing_verb_does_not_stop_the_others() {
    let (server, pin) = served().await;
    let dir = tempfile::tempdir().unwrap();
    let (prefix, _paths) = scratch(dir.path());
    let manifest = manifest(&server, &pin);

    let report = apply(&prefix, &manifest, &SetupEvents::none())
        .await
        .expect("apply");

    assert_eq!(report.outcomes.len(), 3, "every verb was considered");
    assert_eq!(report.present(), ["checked"]);
    assert!(report.any_failed());
    assert_eq!(recorded(&prefix), ["checked"]);
}

/// A pin that does not match is its own thing, not a download problem: the bytes arrived, they are just
/// not the bytes the signed manifest promised. Nothing is written and nothing is recorded.
#[tokio::test]
async fn a_pin_that_does_not_match_is_an_integrity_failure_and_writes_nothing() {
    let (server, pin) = served().await;
    let dir = tempfile::tempdir().unwrap();
    let (prefix, _paths) = scratch(dir.path());
    let manifest = only(&manifest(&server, &pin), "unfixable");
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();

    let report = apply(&prefix, &manifest, &SetupEvents::new(tx))
        .await
        .expect("apply");

    assert!(report.any_failed(), "{report:?}");
    assert!(!prefix.drive_c().join("apogee/verb").exists());
    assert!(recorded(&prefix).is_empty());
    let events = collect(&mut rx);
    assert!(
        events.iter().any(|e| matches!(
            e,
            SetupEvent::Failed { what, reason } if what == "unfixable" && reason.contains("integrity mismatch")
        )),
        "a pin failure is reported as one: {events:?}"
    );
}

/// A pass the user stopped ends as a cancellation, not as a report full of failures. A caller counts
/// failures to decide whether it got what it asked for, and a run somebody stopped has nothing to count.
#[tokio::test]
async fn a_stopped_pass_is_a_cancellation_rather_than_a_set_of_failures() {
    let (server, pin) = served().await;
    let dir = tempfile::tempdir().unwrap();
    let (prefix, _paths) = scratch(dir.path());
    let manifest = manifest(&server, &pin);
    let cancel = CancellationToken::new();
    cancel.cancel();

    let outcome = apply_with(&prefix, &manifest, &cancel, &SetupEvents::none()).await;

    assert!(
        matches!(outcome, Err(AddonError::Cancelled)),
        "expected Cancelled, got {outcome:?}"
    );
    assert!(recorded(&prefix).is_empty());
}

/// The catalog decides the setup, so a manifest with no verbs is a prefix with nothing to do rather than
/// an error.
#[tokio::test]
async fn a_manifest_with_no_verbs_does_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let (prefix, _paths) = scratch(dir.path());
    let manifest = ComponentManifest::from_json_bytes(br#"{ "version": 1 }"#).expect("parse");

    let report = apply(&prefix, &manifest, &SetupEvents::none())
        .await
        .expect("apply");

    assert!(report.outcomes.is_empty());
    assert!(recorded(&prefix).is_empty());
}

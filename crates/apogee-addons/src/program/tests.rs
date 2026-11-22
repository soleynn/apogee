//! A curated program from its row to the companion entry that starts it, over a scratch prefix and a
//! chaos-served archive: no wine, no network.
//!
//! What matters here is what a launch can get wrong without anything failing loudly: installing a
//! program nobody enabled, starting one whose files changed or whose updater was turned back on,
//! starting one on a game or runner it was never validated on, two programs that cannot share a
//! session both starting, and a link in the prefix carrying a write outside it.

use std::io::{Cursor, Write};
use std::path::Path;

use apogee_fetch::Fetcher;
use apogee_runtime::{Prefix, RunnerKind, RunnerRef, Runtime, RuntimePaths};
use apogee_test_support::chaos::{ChaosServer, sha256_of};
use tokio_util::sync::CancellationToken;
use zip::write::SimpleFileOptions;

use crate::manifest::program::tests::act_row;
use crate::{
    AddonError, AddonPaths, Addons, ComponentManifest, GameContext, RunIn, SetupEvent, SetupEvents,
    SetupState, SkipReason, VerifiedManifest,
};

const GAME: &str = "2026.11.03.0000.0000";
const EXE: &str = "Apogee/ACT/Advanced Combat Tracker.exe";

fn runner() -> RunnerRef {
    RunnerRef {
        name: "GE-Proton".to_owned(),
        version: "11-12+remote-thread-actctx".to_owned(),
    }
}

/// ACT's archive: the executable and its settings file under a wrapping directory.
fn act_zip(updater: &str) -> Vec<u8> {
    let mut writer = zip::ZipWriter::new(Cursor::new(Vec::new()));
    let plain = SimpleFileOptions::DEFAULT.last_modified_time(zip::DateTime::default());
    writer
        .start_file("top/Advanced Combat Tracker.exe", plain)
        .unwrap();
    writer.write_all(b"MZ act").unwrap();
    writer.start_file("top/act.json", plain).unwrap();
    write!(writer, r#"{{"cbAutoCheck": "{updater}"}}"#).unwrap();
    writer.finish().unwrap().into_inner()
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut out, b| {
        let _ = write!(out, "{b:02x}");
        out
    })
}

async fn served(updater: &str) -> (ChaosServer, String) {
    let zip = act_zip(updater);
    let pin = hex(&sha256_of(&zip));
    (ChaosServer::serving(zip).start().await.unwrap(), pin)
}

/// A Proton prefix over a scratch directory, whose user is always `steamuser`.
fn scratch(root: &Path) -> Prefix {
    apogee_test_support::sandbox::write_prefix_skeleton(&root.join("pfx")).unwrap();
    std::fs::create_dir_all(root.join("pfx/drive_c/users/steamuser")).unwrap();
    Prefix::for_testing(
        root,
        root.join("runner"),
        RunnerKind::ProtonUmu,
        "GE-Proton",
        "11-12+remote-thread-actctx",
    )
}

fn addons(root: &Path) -> Addons {
    let fetcher = Fetcher::builder().build().unwrap();
    Addons::new(
        Runtime::new(fetcher.clone(), RuntimePaths::default()),
        fetcher,
        AddonPaths::new(root.join("addons")),
    )
}

fn manifest_with(rows: &[serde_json::Value]) -> VerifiedManifest {
    let json = serde_json::json!({ "version": 1, "programs": rows });
    let manifest = ComponentManifest::from_json_bytes(json.to_string().as_bytes()).unwrap();
    assert!(
        manifest.refused_programs.is_empty(),
        "{:?}",
        manifest.refused_programs
    );
    VerifiedManifest::minted_for_tests(manifest)
}

fn act(server: &ChaosServer, pin: &str) -> serde_json::Value {
    let mut row = act_row(server.url("act.zip").as_str(), pin);
    // The fixture's settings file is the archive's own, placed by the seeded step.
    row["steps"][1]["verify"] =
        serde_json::json!(["{appdata}/Advanced Combat Tracker/Config/act.json"]);
    row
}

fn collect(rx: &mut tokio::sync::mpsc::UnboundedReceiver<SetupEvent>) -> Vec<SetupEvent> {
    let mut out = Vec::new();
    while let Ok(event) = rx.try_recv() {
        out.push(event);
    }
    out
}

async fn install(addons: &Addons, manifest: &VerifiedManifest, prefix: &Prefix) {
    let report = addons
        .apply_setup_for(
            manifest,
            prefix,
            &["act"],
            &CancellationToken::new(),
            &SetupEvents::none(),
        )
        .await
        .expect("apply");
    assert!(!report.any_failed(), "{report:?}");
}

fn gates(addons: &Addons, manifest: &VerifiedManifest, prefix: &Prefix) -> crate::ProgramPlan {
    addons.program_gates(
        manifest,
        prefix,
        &["act"],
        GAME,
        &runner(),
        &SetupEvents::none(),
    )
}

fn only_skip(plan: &crate::ProgramPlan) -> &SkipReason {
    assert!(plan.planned().is_empty(), "{plan:?}");
    match plan.skipped() {
        [one] => &one.reason,
        other => panic!("expected one skipped program, got {other:?}"),
    }
}

/// Installed once and started from the place its steps put it: the steps run in order, the settings
/// land in the Proton user's application data, the prefix records the program at its row's version,
/// a second pass fetches nothing, and the companion runs inside the game's prefix with the row's
/// environment and the curated mark.
#[cfg_attr(not(target_os = "linux"), ignore = "placing files is Linux-only")]
#[tokio::test]
async fn an_enabled_program_installs_once_and_starts_from_its_own_files() {
    let (server, pin) = served("False").await;
    let dir = tempfile::tempdir().unwrap();
    let prefix = scratch(dir.path());
    let addons = addons(dir.path());
    let manifest = manifest_with(&[act(&server, &pin)]);

    install(&addons, &manifest, &prefix).await;
    let drive_c = prefix.drive_c();
    assert!(drive_c.join(EXE).is_file());
    assert!(
        drive_c
            .join("users/steamuser/AppData/Roaming/Advanced Combat Tracker/Config/act.json")
            .is_file()
    );
    let recorded: Vec<(String, Option<String>)> = prefix
        .components()
        .unwrap()
        .iter()
        .map(|c| (c.name().to_owned(), c.version().map(str::to_owned)))
        .collect();
    let version = Some("3.8.5.288+plugin-3.0.3.5".to_owned());
    assert_eq!(
        recorded,
        [
            ("act-files".to_owned(), version.clone()),
            ("act-config".to_owned(), version.clone()),
            ("act".to_owned(), version),
        ]
    );

    let requests = server.stats().requests();
    install(&addons, &manifest, &prefix).await;
    assert_eq!(
        server.stats().requests(),
        requests,
        "a second pass fetches nothing"
    );

    let plan = gates(&addons, &manifest, &prefix);
    assert!(plan.skipped().is_empty(), "{:?}", plan.skipped());
    let game = GameContext::in_prefix(4321, &prefix).unwrap();
    let companions = plan.companions(&game).expect("companions");
    let [companion] = companions.as_slice() else {
        panic!("one companion, got {companions:?}");
    };
    assert_eq!(companion.program(), drive_c.join(EXE));
    assert_eq!(companion.run_in(), RunIn::Prefix);
    assert!(!companion.keeps_running());
    assert_eq!(companion.curated_program(), Some("act"));
    assert_eq!(
        companion.env().get("WINEDLLOVERRIDES").map(String::as_str),
        Some("mscoree=b")
    );
    assert_eq!(plan.load_evidence(std::time::SystemTime::now()).len(), 1);

    // Another prefix's game is not where this plan's checks were made.
    let other_dir = tempfile::tempdir().unwrap();
    let other = scratch(other_dir.path());
    assert!(matches!(
        plan.companions(&GameContext::in_prefix(4321, &other).unwrap()),
        Err(AddonError::ProgramPrefixMismatch { .. })
    ));
}

/// A program nobody enabled is never fetched, installed or planned, even with its row in the catalog.
#[cfg_attr(not(target_os = "linux"), ignore = "placing files is Linux-only")]
#[tokio::test]
async fn a_program_not_enabled_contacts_nothing_and_is_not_planned() {
    let (server, pin) = served("False").await;
    let dir = tempfile::tempdir().unwrap();
    let prefix = scratch(dir.path());
    let addons = addons(dir.path());
    let manifest = manifest_with(&[act(&server, &pin)]);

    let report = addons
        .apply_setup_for(
            &manifest,
            &prefix,
            &[],
            &CancellationToken::new(),
            &SetupEvents::none(),
        )
        .await
        .expect("apply");
    assert!(report.outcomes.is_empty());
    assert!(
        addons
            .missing_setup_for(&manifest, &prefix, &[])
            .unwrap()
            .is_empty()
    );
    assert_eq!(server.stats().requests(), 0);
    assert!(!prefix.drive_c().join("Apogee").exists());
    let plan = addons.program_gates(
        &manifest,
        &prefix,
        &[],
        GAME,
        &runner(),
        &SetupEvents::none(),
    );
    assert!(plan.is_empty() && plan.skipped().is_empty());
}

/// Each gate, on an otherwise good install: a game version or runner the row was never validated on,
/// a placed byte flipped, the updater switched back on, and an install recorded at another version
/// of the row. Each leaves the program out of the plan with its own reason and a caveat said aloud.
#[cfg_attr(not(target_os = "linux"), ignore = "placing files is Linux-only")]
#[tokio::test]
async fn every_gate_keeps_a_program_out_of_the_plan_for_its_own_reason() {
    let (server, pin) = served("False").await;
    let dir = tempfile::tempdir().unwrap();
    let prefix = scratch(dir.path());
    let addons = addons(dir.path());
    let manifest = manifest_with(&[act(&server, &pin)]);
    install(&addons, &manifest, &prefix).await;
    let drive_c = prefix.drive_c();

    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    let plan = addons.program_gates(
        &manifest,
        &prefix,
        &["act"],
        "2026.11.17.0000.0000",
        &runner(),
        &SetupEvents::new(tx),
    );
    assert!(matches!(only_skip(&plan), SkipReason::GameVersion { .. }));
    assert!(
        collect(&mut rx)
            .iter()
            .any(|e| matches!(e, SetupEvent::Caveat { what, note } if what == "act" && note.contains("2026.11.17"))),
        "the skip is said aloud"
    );
    assert!(
        plan.companions(&GameContext::in_prefix(1, &prefix).unwrap())
            .unwrap()
            .is_empty()
    );

    let stock = RunnerRef {
        name: "GE-Proton".to_owned(),
        version: "11-12".to_owned(),
    };
    let plan = addons.program_gates(
        &manifest,
        &prefix,
        &["act"],
        GAME,
        &stock,
        &SetupEvents::none(),
    );
    assert!(
        matches!(only_skip(&plan), SkipReason::Runner { validated, .. } if validated.len() == 1)
    );

    // The updater turned back on inside the program.
    let settings =
        drive_c.join("users/steamuser/AppData/Roaming/Advanced Combat Tracker/Config/act.json");
    std::fs::write(&settings, br#"{"cbAutoCheck": "True"}"#).unwrap();
    assert!(matches!(
        only_skip(&gates(&addons, &manifest, &prefix)),
        SkipReason::UpdaterOn { value: Some(v), .. } if v == "True"
    ));
    // A settings file swapped for a link is not read through, and so is not off.
    std::fs::remove_file(&settings).unwrap();
    std::fs::write(dir.path().join("off.json"), br#"{"cbAutoCheck": "False"}"#).unwrap();
    std::os::unix::fs::symlink(dir.path().join("off.json"), &settings).unwrap();
    assert!(matches!(
        only_skip(&gates(&addons, &manifest, &prefix)),
        SkipReason::UpdaterOn { value: None, .. }
    ));
    std::fs::remove_file(&settings).unwrap();
    std::fs::write(&settings, br#"{"cbAutoCheck": "False"}"#).unwrap();
    assert!(gates(&addons, &manifest, &prefix).skipped().is_empty());

    // A byte the program's own updater, or anything else, changed.
    std::fs::write(drive_c.join(EXE), b"MZ acu").unwrap();
    assert!(matches!(
        only_skip(&gates(&addons, &manifest, &prefix)),
        SkipReason::Changed { path } if path == EXE
    ));
    std::fs::write(drive_c.join(EXE), b"MZ act").unwrap();

    // A row moved to a new version is not installed until the next setup pass.
    let mut bumped = act(&server, &pin);
    bumped["version"] = "3.8.5.289".into();
    let bumped = manifest_with(&[bumped]);
    assert!(matches!(
        only_skip(&gates(&addons, &bumped, &prefix)),
        SkipReason::NotInstalled { recorded: Some(v) } if v == "3.8.5.288+plugin-3.0.3.5"
    ));
}

/// A version moved in the catalog reinstalls the pinned step and leaves the seeded settings alone,
/// so the user's own changes to them survive the upgrade.
#[cfg_attr(not(target_os = "linux"), ignore = "placing files is Linux-only")]
#[tokio::test]
async fn a_version_bump_reinstalls_the_program_and_keeps_its_settings() {
    let (server, pin) = served("False").await;
    let dir = tempfile::tempdir().unwrap();
    let prefix = scratch(dir.path());
    let addons = addons(dir.path());
    install(&addons, &manifest_with(&[act(&server, &pin)]), &prefix).await;
    let settings = prefix
        .drive_c()
        .join("users/steamuser/AppData/Roaming/Advanced Combat Tracker/Config/act.json");
    std::fs::write(&settings, br#"{"cbAutoCheck": "False", "theirs": 1}"#).unwrap();

    let mut bumped = act(&server, &pin);
    bumped["version"] = "3.8.5.289".into();
    let bumped = manifest_with(&[bumped]);
    let report = addons
        .apply_setup_for(
            &bumped,
            &prefix,
            &["act"],
            &CancellationToken::new(),
            &SetupEvents::none(),
        )
        .await
        .unwrap();
    let states: Vec<(&str, &SetupState)> = report
        .outcomes
        .iter()
        .map(|o| (o.name.as_str(), &o.state))
        .collect();
    assert!(
        matches!(states[0], ("act-files", SetupState::Reapplied { .. })),
        "{states:?}"
    );
    assert!(
        matches!(states[1], ("act-config", SetupState::AlreadyPresent)),
        "{states:?}"
    );
    assert!(
        std::fs::read_to_string(&settings)
            .unwrap()
            .contains("theirs")
    );
    assert!(gates(&addons, &bumped, &prefix).skipped().is_empty());
}

/// Two programs claiming one fixed name cannot share a session: the first in row order starts, and
/// the second is refused with a failure that names both.
#[cfg_attr(not(target_os = "linux"), ignore = "placing files is Linux-only")]
#[tokio::test]
async fn two_programs_claiming_one_name_do_not_both_start() {
    let (server, pin) = served("False").await;
    let dir = tempfile::tempdir().unwrap();
    let prefix = scratch(dir.path());
    let addons = addons(dir.path());
    let first = act(&server, &pin);
    let mut second = act(&server, &pin);
    second["name"] = "parser".into();
    second["steps"][0]["name"] = "parser-files".into();
    second["steps"][0]["ops"][0]["files"]["into"] = "Apogee/Parser".into();
    second["steps"][1]["name"] = "parser-config".into();
    second["start"]["program"] = "Apogee/Parser/Advanced Combat Tracker.exe".into();
    let manifest = manifest_with(&[first, second]);
    addons
        .apply_setup_for(
            &manifest,
            &prefix,
            &["parser", "act"],
            &CancellationToken::new(),
            &SetupEvents::none(),
        )
        .await
        .unwrap();

    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    let plan = addons.program_gates(
        &manifest,
        &prefix,
        &["parser", "act"],
        GAME,
        &runner(),
        &SetupEvents::new(tx),
    );
    let planned: Vec<&str> = plan.planned().iter().map(|p| p.name.as_str()).collect();
    assert_eq!(planned, ["act"], "row order decides, not the order enabled");
    assert!(matches!(
        &plan.skipped()[0].reason,
        SkipReason::Conflict { with, claim } if with == "act" && claim == "pipe:deucalion"
    ));
    assert!(collect(&mut rx).iter().any(|e| matches!(
        e,
        SetupEvent::Failed { what, reason } if what == "parser" && reason.contains("act")
    )));
}

/// A step that fails stops the rest of its program and nothing else, the program is not recorded as
/// installed, and an enabled name with no row is a failure under that name.
#[cfg_attr(not(target_os = "linux"), ignore = "placing files is Linux-only")]
#[tokio::test]
async fn a_failed_step_stops_its_program_and_nothing_else() {
    let (server, pin) = served("False").await;
    let dir = tempfile::tempdir().unwrap();
    let prefix = scratch(dir.path());
    let addons = addons(dir.path());
    let mut row = act(&server, &pin);
    row["steps"][0]["ops"][0]["files"]["sha256"] = "f".repeat(64).into();
    let manifest = manifest_with(&[row]);

    let report = addons
        .apply_setup_for(
            &manifest,
            &prefix,
            &["act", "absent"],
            &CancellationToken::new(),
            &SetupEvents::none(),
        )
        .await
        .unwrap();
    assert_eq!(report.failed(), ["absent", "act-files", "act-config"]);
    assert!(
        prefix.components().unwrap().is_empty(),
        "nothing is recorded"
    );
    assert!(matches!(
        only_skip(&gates(&addons, &manifest, &prefix)),
        SkipReason::NotInstalled { recorded: None }
    ));
}

/// A link planted in the application-data path is refused, and the settings are not written to where
/// it points.
#[cfg_attr(not(target_os = "linux"), ignore = "placing files is Linux-only")]
#[tokio::test]
async fn a_link_on_the_way_into_the_prefix_is_not_written_through() {
    let (server, pin) = served("False").await;
    let dir = tempfile::tempdir().unwrap();
    let prefix = scratch(dir.path());
    let addons = addons(dir.path());
    let outside = dir.path().join("outside");
    std::fs::create_dir_all(&outside).unwrap();
    let appdata = prefix.drive_c().join("users/steamuser/AppData");
    std::fs::create_dir_all(&appdata).unwrap();
    std::os::unix::fs::symlink(&outside, appdata.join("Roaming")).unwrap();

    let report = addons
        .apply_setup_for(
            &manifest_with(&[act(&server, &pin)]),
            &prefix,
            &["act"],
            &CancellationToken::new(),
            &SetupEvents::none(),
        )
        .await
        .unwrap();
    assert_eq!(report.failed(), ["act-config"]);
    assert_eq!(std::fs::read_dir(&outside).unwrap().count(), 0);
}

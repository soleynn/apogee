//! Dalamud against a scratch prefix and a hand-written install record.
//!
//! No wine and no network. What is checked here is the half that decides whether a launch is touched at
//! all and, when it is, that the game stays the process the launcher waits on: the injector's own
//! command line is pinned in `injector.rs`, and the download pipeline in `tests/dalamud_fetch.rs`.

use std::collections::BTreeMap;
use std::path::Path;

use apogee_fetch::Fetcher;
use apogee_runtime::{LaunchPlan, Prefix, RunnerKind};

use super::*;
use crate::manifest::ComponentManifest;

const GAME_VERSION: &str = "2026.06.18.0000.0000";

fn entry() -> InjectableEntry {
    let json = r#"{ "version": 1, "injectables": [
        { "name": "Dalamud", "kind": "dalamud",
          "distribution": "https://kamori.goats.dev/Dalamud/Release/VersionInfo",
          "tier": "best_effort", "note": "Best with the wine-xiv runner.",
          "caveats": ["Third-party code is loaded into the game client."] } ] }"#;
    ComponentManifest::from_json_bytes(json.as_bytes())
        .expect("fixture parses")
        .injectables
        .remove(0)
}

fn dalamud(root: &Path, runner: &str) -> (Dalamud, Prefix) {
    apogee_test_support::sandbox::write_prefix_skeleton(root).expect("prefix skeleton");
    let prefix = Prefix::for_testing(
        root,
        root.join("runner"),
        RunnerKind::Wine,
        runner,
        "custom",
    );
    let config = DalamudConfig {
        game_version: GAME_VERSION.to_owned(),
        ..DalamudConfig::default()
    };
    let dalamud = Dalamud::new(
        DalamudPaths::under(root.join("dalamud")),
        Fetcher::builder().build().expect("fetcher"),
        &entry(),
        config,
    );
    (dalamud, prefix)
}

/// Write the record and the injector a completed install would have left, for `supported`.
fn pretend_installed(dalamud: &Dalamud, supported: &str) {
    let version_dir = dalamud.paths.version_dir("15.0.2.3");
    std::fs::create_dir_all(&version_dir).expect("mkdir");
    std::fs::write(version_dir.join("Dalamud.Injector.exe"), b"MZ").expect("write");
    dalamud
        .write_record(&Installed {
            assembly_version: "15.0.2.3".to_owned(),
            supported_game_ver: supported.to_owned(),
            runtime_version: "10.0.0".to_owned(),
            track: "release".to_owned(),
            asset_version: 432,
        })
        .expect("record");
}

fn plan(prefix: &Prefix) -> LaunchPlan {
    LaunchPlan::new(
        "/games/ffxiv/game/ffxiv_dx11.exe",
        "//**sqex0003**//",
        BTreeMap::new(),
    )
    .prefix(prefix)
}

fn drain(rx: &mut tokio::sync::mpsc::UnboundedReceiver<SetupEvent>) -> Vec<SetupEvent> {
    let mut out = Vec::new();
    while let Ok(event) = rx.try_recv() {
        out.push(event);
    }
    out
}

fn notes(events: &[SetupEvent]) -> Vec<&str> {
    events
        .iter()
        .filter_map(|event| match event {
            SetupEvent::Caveat { note, .. } => Some(note.as_str()),
            _ => None,
        })
        .collect()
}

/// A launch that Dalamud takes over still waits on the game. The injector starts the game and exits, so
/// a launcher tracking the injector would report the session as over seconds after it began.
#[test]
fn wrapping_a_launch_keeps_the_game_as_the_supervised_process() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let (dalamud, prefix) = dalamud(tmp.path(), "wine-xiv-staging");
    pretend_installed(&dalamud, GAME_VERSION);
    let mut plan = plan(&prefix);

    dalamud
        .prepare_launch(&mut plan, &SetupEvents::none())
        .expect("prepare");

    assert!(
        plan.program().ends_with("Dalamud.Injector.exe"),
        "the injector becomes the launched program, got {}",
        plan.program()
    );
    // In Windows form, because the runner is what executes it. A host path is accepted by plain wine
    // and not by Proton, which routes a foreign-looking path through a launch helper the injector's
    // handoff to the game does not survive: the game starts and nothing is ever loaded into it.
    assert!(
        plan.program().contains(":\\"),
        "the injector is named the way every runner reads, got {}",
        plan.program()
    );
    assert!(
        !plan.program().starts_with('/'),
        "a host path here works on one runner and silently breaks another, got {}",
        plan.program()
    );
    assert_eq!(
        plan.supervised(),
        Some("ffxiv_dx11.exe"),
        "the game is what the launcher waits on"
    );
    assert_eq!(
        plan.args(),
        "//**sqex0003**//",
        "the game's own argument string is passed through untouched"
    );
    let inserted = plan.inserted_args();
    assert_eq!(inserted.first().map(String::as_str), Some("launch"));
    assert_eq!(inserted.last().map(String::as_str), Some("--"));
}

/// The injector reads one variable and the runtime it starts reads the other, and both are read by
/// Windows code, so a Unix path in either is a runtime that does not resolve.
#[test]
fn the_runtime_reaches_the_child_as_a_windows_path_in_both_variables() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let (dalamud, prefix) = dalamud(tmp.path(), "wine-xiv-staging");
    pretend_installed(&dalamud, GAME_VERSION);
    let mut plan = plan(&prefix);

    dalamud
        .prepare_launch(&mut plan, &SetupEvents::none())
        .expect("prepare");

    let runtime = plan.env().get("DALAMUD_RUNTIME").expect("DALAMUD_RUNTIME");
    assert_eq!(
        plan.env().get("DOTNET_ROOT"),
        Some(runtime),
        "both name the same tree"
    );
    assert!(
        runtime.contains(':') && runtime.contains('\\'),
        "{runtime} is not a windows path"
    );
    assert_eq!(
        plan.env().get("DALAMUD_BRANCH").map(String::as_str),
        Some("release")
    );
}

/// Dalamud reads the client's memory at offsets it was built for, so a release for another game version
/// is not a degraded launch, it is a crash. Declining is narrated rather than silent, because "my
/// plugins are gone" with no explanation is the worst version of this.
#[test]
fn a_release_built_for_another_game_version_leaves_the_launch_alone() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let (dalamud, prefix) = dalamud(tmp.path(), "wine-xiv-staging");
    pretend_installed(&dalamud, "2020.01.01.0000.0000");
    let mut plan = plan(&prefix);
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();

    dalamud
        .prepare_launch(&mut plan, &SetupEvents::new(tx))
        .expect("declining is not a failure");

    assert_eq!(plan.program(), "/games/ffxiv/game/ffxiv_dx11.exe");
    assert!(plan.inserted_args().is_empty());
    assert!(plan.supervised().is_none());
    assert!(
        notes(&drain(&mut rx))
            .iter()
            .any(|note| note.contains("2020.01.01.0000.0000")),
        "the version it declined over has to be in the note"
    );
}

/// Nothing installed is the ordinary state before the first launch with the setting on, and a launch
/// through an injector that is not there would fail outright.
#[test]
fn nothing_installed_leaves_the_launch_alone() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let (dalamud, prefix) = dalamud(tmp.path(), "wine-xiv-staging");
    let mut plan = plan(&prefix);

    dalamud
        .prepare_launch(&mut plan, &SetupEvents::none())
        .expect("declining is not a failure");
    assert_eq!(plan.program(), "/games/ffxiv/game/ffxiv_dx11.exe");
    assert!(plan.inserted_args().is_empty());
}

/// The row's caveats are stated every time, and the runner in front of it is named when it is not the
/// one the injector was written against. Steering, not gating: it is still the user's prefix.
///
/// The tier note is not among them and must not be: it is said for every injectable by the loop that
/// installs them, and said twice it reads as two different warnings.
#[test]
fn the_caveats_and_the_runner_are_both_stated_before_anything_is_fetched() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let (dalamud, prefix) = dalamud(tmp.path(), "system-wine");
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();

    dalamud.announce(&prefix, &SetupEvents::new(tx));

    let events = drain(&mut rx);
    let notes = notes(&events);
    assert!(
        notes.iter().any(|note| note.contains("system-wine")),
        "the runner it is about to run under has to be named: {notes:?}"
    );
    assert!(
        notes.iter().any(|note| note.contains("Third-party code")),
        "the row's own caveats have to be said: {notes:?}"
    );
    let tier = dalamud.support_tier();
    let tier_note = tier.note().expect("the shipped row is best effort");
    assert!(
        !notes.contains(&tier_note),
        "the tier note belongs to the loop that installs injectables, not to one of them: {notes:?}"
    );
}

/// A prefix already on the steered runner has nothing to be warned about, so it is not.
#[test]
fn the_steered_runner_draws_no_runner_warning() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let (dalamud, prefix) = dalamud(tmp.path(), "wine-xiv-staging-10.8");
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();

    dalamud.announce(&prefix, &SetupEvents::new(tx));

    assert!(
        !notes(&drain(&mut rx))
            .iter()
            .any(|note| note.contains("best supported on")),
        "a prefix already on the steered runner needs no steering"
    );
}

/// Every endpoint is a sibling of the pointer the manifest carries, so one row describes the service.
#[test]
fn the_endpoints_are_derived_from_the_one_pointer_the_row_carries() {
    let endpoints = Endpoints::derive(&entry().distribution).expect("derive");
    assert_eq!(
        endpoints.asset_meta.as_str(),
        "https://kamori.goats.dev/Dalamud/Asset/Meta"
    );
    let (dotnet, desktop) = endpoints.runtime_archives("10.0.0").expect("runtime urls");
    assert_eq!(
        dotnet.as_str(),
        "https://kamori.goats.dev/Dalamud/Release/Runtime/DotNet/10.0.0"
    );
    assert_eq!(
        desktop.as_str(),
        "https://kamori.goats.dev/Dalamud/Release/Runtime/WindowsDesktop/10.0.0"
    );
    assert_eq!(
        endpoints
            .runtime_hashes("10.0.0")
            .expect("hashes url")
            .as_str(),
        "https://kamori.goats.dev/Dalamud/Release/Runtime/Hashes/10.0.0"
    );
}

/// The rollout bucket is stated rather than sampled, so two machines on the same track are asking for
/// the same release.
#[test]
fn the_release_request_names_the_track_and_a_fixed_bucket() {
    let endpoints = Endpoints::derive(&entry().distribution).expect("derive");
    let query = endpoints.release_query();
    let pairs: Vec<(String, String)> = query
        .query_pairs()
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect();
    assert_eq!(
        pairs,
        [
            ("track".to_owned(), "release".to_owned()),
            ("bucket".to_owned(), "Control".to_owned())
        ]
    );
}

/// A version directory without the digest map it ships with is an incomplete extraction, not a tree the
/// distribution declined to describe. Accepting it would put an unchecked injector on the launch path.
#[test]
fn a_version_directory_without_its_hash_map_is_not_intact() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let (dalamud, _prefix) = dalamud(tmp.path(), "wine-xiv-staging");
    let dir = dalamud.paths.version_dir("15.0.2.3");
    std::fs::create_dir_all(&dir).expect("mkdir");
    for name in integrity::REQUIRED {
        std::fs::write(dir.join(name), b"MZ").expect("write");
    }
    assert!(!dalamud.tree_is_intact(&dir));

    let hashes: BTreeMap<String, String> = integrity::REQUIRED
        .iter()
        .map(|name| {
            (
                (*name).to_owned(),
                integrity::hash_file(&dir.join(name), Digest::Md5).expect("hash"),
            )
        })
        .collect();
    std::fs::write(
        dir.join("hashes.json"),
        serde_json::to_vec(&hashes).expect("serialize"),
    )
    .expect("write");
    assert!(dalamud.tree_is_intact(&dir));
}

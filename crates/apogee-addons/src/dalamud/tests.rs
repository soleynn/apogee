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

/// Prepare a launch and apply what came back, which is the pass the loop makes over one companion.
///
/// A decline leaves the plan as it was built, so a test that expects an edit catches one through the
/// assertions it was going to make anyway.
fn applied(dalamud: &Dalamud, prefix: &Prefix, events: &SetupEvents) -> LaunchPlan {
    let mut plan = plan(prefix);
    if let Contribution::Edit(edit) = dalamud.prepare_launch(&plan, events).expect("prepare") {
        edit.apply(&mut plan);
    }
    plan
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

    let plan = applied(&dalamud, &prefix, &SetupEvents::none());

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

    let plan = applied(&dalamud, &prefix, &SetupEvents::none());

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
    let plan = plan(&prefix);
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();

    let contribution = dalamud
        .prepare_launch(&plan, &SetupEvents::new(tx))
        .expect("declining is not a failure");

    assert!(
        matches!(contribution, Contribution::Declined),
        "a release for another game version contributes nothing to the launch"
    );
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
    let plan = plan(&prefix);

    let contribution = dalamud
        .prepare_launch(&plan, &SetupEvents::none())
        .expect("declining is not a failure");

    assert!(
        matches!(contribution, Contribution::Declined),
        "nothing installed contributes nothing to the launch"
    );
}

/// The row's caveats are stated every time, before anything is fetched.
///
/// Nothing is said about the runner. A compiled-in caveat used to name one runner as the supported
/// bet; measured against the real client it loads behind the host's own wine, wine-xiv and Proton
/// alike, so the claim was false and what a runner costs is the published row's to say.
///
/// The tier note is not among them and must not be: it is said for every injectable by the loop that
/// installs them, and said twice it reads as two different warnings.
#[test]
fn the_caveats_are_stated_before_anything_is_fetched() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let (dalamud, _prefix) = dalamud(tmp.path(), "system-wine");
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();

    dalamud.announce(&SetupEvents::new(tx));

    let events = drain(&mut rx);
    let notes = notes(&events);
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

/// No runner draws a warning any more, whichever one it is, because the launcher no longer holds an
/// opinion about which runner this works behind. The row does.
#[test]
fn no_runner_draws_a_warning_of_its_own() {
    for runner in ["system-wine", "wine-xiv-staging-10.8", "GE-Proton"] {
        let tmp = tempfile::tempdir().expect("tempdir");
        let (dalamud, _prefix) = dalamud(tmp.path(), runner);
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();

        dalamud.announce(&SetupEvents::new(tx));

        let events = drain(&mut rx);
        let notes = notes(&events);
        assert!(
            !notes.iter().any(|note| note.contains(runner)),
            "{runner} was singled out: {notes:?}"
        );
    }
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
    assert!(dalamud.version_fault(&dir).is_some());

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
    assert!(dalamud.version_fault(&dir).is_none());
}

/// A tree whose bytes moved is an integrity failure that names the file and both digests, not a
/// sentence about the tree.
///
/// This is the reading somebody does when an install keeps failing: "it does not match its own hashes"
/// is true of a distribution that served a bad build and of a disk that corrupted one file, and the
/// file plus the two digests is what tells them apart. The check that produces this used to answer with
/// a bool, so there was nothing to say either way.
#[test]
fn a_file_whose_bytes_moved_is_named_with_both_digests() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let (dalamud, _prefix) = dalamud(tmp.path(), "wine-xiv-staging");
    let dir = dalamud.paths.version_dir("15.0.2.3");
    std::fs::create_dir_all(&dir).expect("mkdir");
    for name in integrity::REQUIRED {
        std::fs::write(dir.join(name), b"MZ").expect("write");
    }
    // A map that describes the tree correctly except for one file, which is what a partly-corrupted
    // download looks like from here.
    let mut hashes: BTreeMap<String, String> = integrity::REQUIRED
        .iter()
        .map(|name| {
            (
                (*name).to_owned(),
                integrity::hash_file(&dir.join(name), Digest::Md5).expect("hash"),
            )
        })
        .collect();
    let moved = integrity::REQUIRED[0];
    let stated = "0".repeat(32);
    hashes.insert(moved.to_owned(), stated.clone());
    std::fs::write(
        dir.join("hashes.json"),
        serde_json::to_vec(&hashes).expect("serialize"),
    )
    .expect("write");

    let fault = dalamud.version_fault(&dir).expect("the tree is not intact");

    let AddonError::IntegrityMismatch {
        file,
        expected,
        got,
        ..
    } = &fault
    else {
        panic!("bytes that arrived and do not match are an integrity failure, not: {fault:?}");
    };
    assert!(file.ends_with(moved), "{file:?}");
    assert_eq!(*expected, stated);
    assert_eq!(
        *got,
        integrity::hash_file(&dir.join(moved), Digest::Md5).expect("hash"),
        "the digest the file actually has"
    );
}

/// And a file the map names that is not there at all is a filesystem failure carrying the path and what
/// the open said, rather than the same integrity sentence: one of them is the distribution's fault and
/// the other is this machine's.
#[test]
fn a_file_the_map_names_and_the_tree_lacks_is_a_filesystem_failure() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let (dalamud, _prefix) = dalamud(tmp.path(), "wine-xiv-staging");
    let dir = dalamud.paths.version_dir("15.0.2.3");
    std::fs::create_dir_all(&dir).expect("mkdir");
    for name in integrity::REQUIRED {
        std::fs::write(dir.join(name), b"MZ").expect("write");
    }
    let mut hashes: BTreeMap<String, String> = BTreeMap::new();
    hashes.insert("absent.dll".to_owned(), "0".repeat(32));
    std::fs::write(
        dir.join("hashes.json"),
        serde_json::to_vec(&hashes).expect("serialize"),
    )
    .expect("write");

    let fault = dalamud.version_fault(&dir).expect("the tree is not intact");

    let AddonError::Io { path, source, .. } = &fault else {
        panic!("a file that cannot be read is a filesystem failure, not: {fault:?}");
    };
    assert!(path.ends_with("absent.dll"), "{path:?}");
    assert!(
        source.to_string().to_lowercase().contains("no such file"),
        "the error the filesystem raised is the one carried: {source}"
    );
}
